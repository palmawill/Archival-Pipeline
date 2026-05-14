from pathlib import Path
import hashlib
from datetime import datetime
from lxml import etree as LET
import uuid
import logging
import csv
from collections import Counter
import shutil
import os
import mimetypes
import tarfile
import urllib.request
import gzip
import io
import time

# ==========================
# OPTIONAL DEPENDENCIES
# ==========================

try:
    import bagit
    BAGIT_AVAILABLE = True
except ImportError:
    BAGIT_AVAILABLE = False

# APTrust constants — exported so the GUI can import them
APTRUST_PROFILE_IDENTIFIER = (
    "https://raw.githubusercontent.com/APTrust/preservation-services"
    "/master/profiles/aptrust-v2.2.json"
)
APTRUST_ACCESS_VALUES   = ["Institution", "Restricted", "Consortia"]
APTRUST_STORAGE_OPTIONS = [
    "Standard",
    "Glacier-OH", "Glacier-OR", "Glacier-VA",
    "Glacier-Deep-OH", "Glacier-Deep-OR", "Glacier-Deep-VA",
]


# ==========================
# MALWAREBAZAAR HASH DATABASE
# ==========================

# The database file lives beside this script so it persists between runs.
MALWARE_DB_PATH = Path(__file__).parent / "malware_hashes.txt"

# AV is available as long as the database file exists on disk.
AV_AVAILABLE = MALWARE_DB_PATH.exists()

# Recent list — free, no auth required, ~48 hrs of hashes (~4 MB plain text)
MALWARE_RECENT_URL = "https://bazaar.abuse.ch/export/txt/md5/recent/"

# Full database — requires a free Auth-Key from bazaar.abuse.ch/api/
# URL pattern: https://mb-api.abuse.ch/v2/files/exports/<AUTH-KEY>/full.csv
MALWARE_FULL_URL_TEMPLATE = "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/full.csv"


def update_malware_db(progress_callback=None, auth_key=""):
    """
    Download the MalwareBazaar MD5 hash list and cache it locally.

    Two modes depending on whether an Auth-Key is provided:

    No auth_key → downloads the recent list (last 48 hours, ~500k hashes).
                  Free, no account needed.
                  URL: https://bazaar.abuse.ch/export/txt/md5/recent/

    auth_key    → downloads the full database (all hashes, ~3M+ entries).
                  Requires a free Auth-Key from bazaar.abuse.ch/api/
                  URL: https://mb-api.abuse.ch/v2/files/exports/<key>/full.csv

    The recent list is plain text (one MD5 per line, comment lines start with #).
    The full database is a CSV where the first column is the MD5 hash.

    progress_callback(message: str) — optional; called with status updates.
    Returns (success: bool, message: str).
    """
    import zipfile

    def _report(msg):
        logging.info(msg)
        if progress_callback:
            progress_callback(msg)

    auth_key = auth_key.strip()

    try:
        if auth_key:
            # Full database download (CSV, may be zipped)
            url = MALWARE_FULL_URL_TEMPLATE.format(auth_key=auth_key)
            _report("Connecting to MalwareBazaar (full database)...")
            req = urllib.request.Request(
                url, headers={"User-Agent": "ArchivalPipeline/1.0"}
            )
            with urllib.request.urlopen(req, timeout=180) as response:
                _report("Downloading full hash database (~50 MB, please wait)...")
                data = response.read()

            # Response may be a zip or plain CSV depending on endpoint version
            content_type = ""
            if hasattr(response, "headers"):
                content_type = response.headers.get("Content-Type", "")

            if data[:2] == b"PK":  # ZIP magic bytes
                _report("Extracting database archive...")
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    csv_name = next(n for n in zf.namelist() if n.endswith(".csv"))
                    with zf.open(csv_name) as csv_file:
                        raw_text = csv_file.read().decode("utf-8", errors="replace")
            else:
                raw_text = data.decode("utf-8", errors="replace")

            # Extract MD5 column (first field of each non-comment line)
            _report("Processing database...")
            hashes = []
            for line in raw_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                md5 = line.split(",")[0].strip().strip('"').lower()
                if len(md5) == 32:
                    hashes.append(md5)

            MALWARE_DB_PATH.write_text("\n".join(hashes), encoding="utf-8")
            count = len(hashes)
            mode = "full database"

        else:
            # Recent list — plain text, one MD5 per line
            _report("Connecting to MalwareBazaar (recent list, last 48 hrs)...")
            req = urllib.request.Request(
                MALWARE_RECENT_URL,
                headers={"User-Agent": "ArchivalPipeline/1.0"}
            )
            with urllib.request.urlopen(req, timeout=120) as response:
                _report("Downloading recent hash list...")
                raw_text = response.read().decode("utf-8", errors="replace")

            hashes = [
                line.strip().lower()
                for line in raw_text.splitlines()
                if line.strip() and not line.startswith("#") and len(line.strip()) == 32
            ]
            MALWARE_DB_PATH.write_text("\n".join(hashes), encoding="utf-8")
            count = len(hashes)
            mode = "recent list (48 hrs)"

        global AV_AVAILABLE
        AV_AVAILABLE = True

        msg = f"Database updated: {count:,} hashes ({mode})."
        _report(msg)
        return True, msg

    except Exception as exc:
        msg = f"Failed to update malware database: {exc}"
        logging.error(msg)
        return False, msg


def load_malware_db():
    """
    Load the cached MalwareBazaar hash list into a frozenset of lowercase MD5 strings.

    The file is plain text — one MD5 hex string per line, comment lines start with #.
    Returns a frozenset, or an empty frozenset if the file cannot be read.
    """
    if not MALWARE_DB_PATH.exists():
        return frozenset()

    hashes = set()
    try:
        with open(MALWARE_DB_PATH, encoding="utf-8", errors="replace") as f:
            for line in f:
                md5 = line.strip().lower()
                if md5 and not md5.startswith("#") and len(md5) == 32:
                    hashes.add(md5)
    except Exception as exc:
        logging.error(f"Failed to load malware database: {exc}")

    return frozenset(hashes)


# ==========================
# CHUNKED MD5
# ==========================

def compute_md5(file_path, chunk_size=1024 * 1024):
    """Compute MD5 checksum using chunked reading (1 MB default chunk)."""
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
    return md5.hexdigest()


# ==========================
# ANTIVIRUS SCANNER
# ==========================

def run_antivirus_scan(data_directory, output_folder, accession_number):
    """
    Scan all files in data_directory by comparing their MD5 checksums against
    the locally cached MalwareBazaar hash database.

    No external executable is required — the check is pure Python.
    The database must have been downloaded at least once via update_malware_db().

    Returns:
        (clean_files, infected_files, av_skipped)
        clean_files    — set of Path objects whose MD5 was not in the database
        infected_files — dict of {Path: "MD5 match in MalwareBazaar"}
        av_skipped     — True if the database file was missing
    """
    data_directory = Path(data_directory)
    output_folder  = Path(output_folder)
    all_files      = {p for p in data_directory.rglob("*") if p.is_file()}

    if not AV_AVAILABLE:
        logging.warning(
            "Malware hash database not found. Antivirus scan skipped. "
            "Use 'Update Malware Database' in the GUI to download it."
        )
        return set(all_files), {}, True

    logging.info(f"Loading malware hash database from: {MALWARE_DB_PATH}")
    malware_hashes = load_malware_db()

    if not malware_hashes:
        logging.warning("Malware database loaded but contained no hashes. Scan skipped.")
        return set(all_files), {}, True

    logging.info(f"Loaded {len(malware_hashes):,} malware hashes. Scanning {len(all_files)} files...")

    av_log_file    = output_folder / f"antivirus_{accession_number}.log"
    av_csv_file    = output_folder / f"antivirus_{accession_number}.csv"
    infected_files = {}
    av_results     = []

    for file_path in sorted(all_files):
        try:
            md5 = compute_md5(file_path)
            if md5.lower() in malware_hashes:
                status = "INFECTED"
                threat = f"MD5 match in MalwareBazaar ({md5})"
                infected_files[file_path] = threat
                logging.warning(f"[INFECTED] {file_path} — {threat}")
            else:
                status = "CLEAN"
                threat = ""
        except Exception as exc:
            status = "SCAN_ERROR"
            threat = str(exc)
            logging.error(f"[SCAN_ERROR] {file_path} — {exc}")

        av_results.append({
            "file_path": str(file_path),
            "status":    status,
            "threat":    threat,
        })
        logging.info(f"[AV:{status}] {file_path}")

    with open(av_csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file_path", "status", "threat"])
        writer.writeheader()
        writer.writerows(av_results)

    with open(av_log_file, "w", encoding="utf-8") as f:
        f.write(f"--- MalwareBazaar Hash Scan: {datetime.now().isoformat()} ---\n")
        f.write(f"Database: {MALWARE_DB_PATH}\n")
        f.write(f"Hashes loaded: {len(malware_hashes):,}\n")
        f.write(f"Files scanned: {len(all_files)}\n")
        f.write(f"Infected:      {len(infected_files)}\n\n")
        for r in av_results:
            f.write(f"[{r['status']}] {r['file_path']}")
            if r["threat"]:
                f.write(f"\n        {r['threat']}")
            f.write("\n")

    clean_files = all_files - set(infected_files.keys())
    return clean_files, infected_files, False


# ==========================
# DATA ACCESSIONER
# ==========================

def generate_data_accessioner_xml(data_directory, output_folder, accession_number,
                                  move_files=False, clean_files_only=None):
    """
    Copy (or move) files into the accession folder and produce a
    Data Accessioner-compatible XML manifest with PREMIS object identifiers.

    clean_files_only — if provided, only files in this set are transferred;
                       others are logged as skipped (infected).
    """
    data_directory  = Path(data_directory)
    output_folder   = Path(output_folder)
    accession_folder = output_folder / accession_number
    accession_folder.mkdir(parents=True, exist_ok=True)

    dir_times = {}

    NSMAP = {
        None:     "http://dataaccessioner.org/schema/dda-1-1",
        "premis": "info:lc/xmlns/premis-v2",
    }

    collection_el = LET.Element("collection", nsmap=NSMAP)
    accession_el  = LET.SubElement(collection_el, "accession", number=accession_number)
    LET.SubElement(accession_el, "ingest_note").text = (
        f"Transferred on {datetime.now().isoformat()}"
    )

    for file_path in data_directory.rglob("*"):

        # Record directory timestamps so we can restore them after copying
        if file_path.is_dir():
            stat = file_path.stat()
            rel  = file_path.relative_to(data_directory)
            dir_times[rel] = (stat.st_atime, stat.st_mtime)

        if not file_path.is_file():
            continue

        # Skip infected files when a filter is active
        if clean_files_only is not None and file_path not in clean_files_only:
            logging.warning(f"[SKIPPED — INFECTED] {file_path}")
            continue

        stat_src = file_path.stat()
        atime    = stat_src.st_atime
        mtime    = stat_src.st_mtime

        rel_path  = file_path.relative_to(data_directory)
        dest_path = accession_folder / rel_path
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        if move_files:
            shutil.move(str(file_path), str(dest_path))
        else:
            shutil.copy2(str(file_path), str(dest_path))

        # Restore original timestamps explicitly after copy
        os.utime(dest_path, (atime, mtime))

        checksum = compute_md5(dest_path)

        file_el = LET.SubElement(
            accession_el, "file",
            name=str(rel_path.as_posix()),
            size=str(dest_path.stat().st_size),
            MD5=checksum,
        )

        premis_obj = LET.SubElement(
            file_el, "{info:lc/xmlns/premis-v2}object", nsmap=NSMAP
        )
        premis_id = LET.SubElement(
            premis_obj, "{info:lc/xmlns/premis-v2}objectIdentifier"
        )
        LET.SubElement(
            premis_id, "{info:lc/xmlns/premis-v2}objectIdentifierType"
        ).text = "uuid"
        LET.SubElement(
            premis_id, "{info:lc/xmlns/premis-v2}objectIdentifierValue"
        ).text = str(uuid.uuid4())

    xml_output_file = output_folder / f"{accession_number}.xml"
    LET.ElementTree(collection_el).write(
        str(xml_output_file),
        encoding="UTF-8",
        xml_declaration=True,
        pretty_print=True,
    )

    # Restore directory timestamps (fix: loop must be indented correctly so
    # ALL directories are restored, not just the last one)
    for rel_path, (atime, mtime) in dir_times.items():
        dest_dir = accession_folder / rel_path
        if dest_dir.exists():
            try:
                os.utime(dest_dir, (atime, mtime))
            except Exception:
                pass

    return xml_output_file


# ==========================
# XSLT PROCESSOR
# ==========================

def run_xslt_processor(xml_input, xslt_file, output_file):
    """Transform xml_input with xslt_file and write result to output_file."""
    xml_tree  = LET.parse(str(xml_input))
    xslt_tree = LET.parse(str(xslt_file))
    transform = LET.XSLT(xslt_tree)
    result    = transform(xml_tree)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(str(result))

    return output_file


# ==========================
# BAGIT PACKAGER
# ==========================

def _write_aptrust_info(bag_dir, title, access, storage_option, description=""):
    """
    Write aptrust-info.txt into the bag root and regenerate tagmanifest-md5.txt
    so the new file is properly checksummed.

    APTrust requires this custom tag file in addition to the standard bag-info.txt.
    """
    if access not in APTRUST_ACCESS_VALUES:
        raise ValueError(
            f"APTrust Access must be one of {APTRUST_ACCESS_VALUES}, got '{access}'"
        )
    if storage_option not in APTRUST_STORAGE_OPTIONS:
        raise ValueError(
            f"APTrust Storage-Option must be one of {APTRUST_STORAGE_OPTIONS}, "
            f"got '{storage_option}'"
        )

    aptrust_info_path = Path(bag_dir) / "aptrust-info.txt"
    lines = [
        f"Title: {title}",
        f"Access: {access}",
        f"Storage-Option: {storage_option}",
    ]
    if description:
        lines.append(f"Description: {description}")

    with open(aptrust_info_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    # Regenerate tag manifest to include aptrust-info.txt
    tag_manifest_path = Path(bag_dir) / "tagmanifest-md5.txt"
    tag_files = ["bagit.txt", "bag-info.txt", "aptrust-info.txt", "manifest-md5.txt"]
    tag_manifest_lines = []
    for tag_file in tag_files:
        tf_path = Path(bag_dir) / tag_file
        if tf_path.exists():
            tag_manifest_lines.append(f"{compute_md5(tf_path)}  {tag_file}")

    with open(tag_manifest_path, "w", encoding="utf-8") as f:
        f.write("\n".join(tag_manifest_lines) + "\n")

    logging.info(f"aptrust-info.txt written and tag manifest updated at: {bag_dir}")


def create_bag(accession_folder, accession_number, contact_name="", contact_email="",
               source_organization="", profile="generic", title="",
               access="Institution", storage_option="Standard",
               description="", serialize_tar=False, validate=False,
               xml_manifest=None):
    """
    Convert the accession folder into a valid BagIt bag in-place.

    profile:
        "generic"  — standard BagIt bag (bag-info.txt only)
        "aptrust"  — APTrust profile (adds aptrust-info.txt; optionally tars)

    For APTrust bags, title and source_organization are required.
    access must be one of: Institution, Restricted, Consortia
    storage_option sets the APTrust storage tier (Standard, Glacier-*, etc.)

    If serialize_tar is True and profile is "aptrust", the bag directory is
    archived into <accession_number>.tar beside the accession folder, matching
    APTrust's required serialization format.

    validate     — if True, verifies all file checksums against the manifest
                   after bagging. Skipped by default since it rehashes every
                   file (all files were already hashed during Data Accessioner).
    xml_manifest — path to the Data Accessioner XML report. When supplied,
                   MD5s are read from it rather than recomputed, making
                   bagging significantly faster for large collections.

    Returns (bag_path, tar_path, bag_valid, bag_error).
    Requires: pip install bagit-python
    """
    if not BAGIT_AVAILABLE:
        logging.warning(
            "bagit-python is not installed. BagIt packaging skipped. "
            "Run: pip install bagit-python"
        )
        return None, None, False, "bagit-python is not installed."

    accession_folder = Path(accession_folder).resolve()

    # Build bag-info.txt metadata
    bag_metadata = {
        "Bag-Software-Agent": "bagit-python",
        "Bagging-Date":       datetime.now().strftime("%Y-%m-%d"),
        "External-Identifier": accession_number,
    }
    if contact_name:
        bag_metadata["Contact-Name"]  = contact_name
    if contact_email:
        bag_metadata["Contact-Email"] = contact_email
    if source_organization:
        bag_metadata["Source-Organization"] = source_organization
    if profile == "aptrust":
        bag_metadata["BagIt-Profile-Identifier"] = APTRUST_PROFILE_IDENTIFIER

    import time

    # bagit.make_bag() moves files through a temp directory using os.rename,
    # which Windows denies if anything has an open handle on the folder tree
    # (Explorer, antivirus, or a previous pipeline step). We build the bag
    # structure manually instead: move files into data/, write tag files, then
    # let bagit.Bag() read the result without touching os.rename at all.

    data_dir = accession_folder / "data"
    data_dir.mkdir(exist_ok=True)

    # Move all existing files and subdirectories into data/
    # Retry up to 5 times with a short delay for transient Windows locks
    for item in list(accession_folder.iterdir()):
        if item.name == "data":
            continue
        dest = data_dir / item.name
        for attempt in range(5):
            try:
                shutil.move(str(item), str(dest))
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.5)

    # Write bagit.txt
    (accession_folder / "bagit.txt").write_text(
        "BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n",
        encoding="utf-8"
    )

    # Write bag-info.txt
    bag_info_lines = []
    for key, value in bag_metadata.items():
        bag_info_lines.append(f"{key}: {value}")
    (accession_folder / "bag-info.txt").write_text(
        "\n".join(bag_info_lines) + "\n", encoding="utf-8"
    )

    # Generate manifest-md5.txt by reading checksums already computed during
    # the Data Accessioner step — no need to rehash every file again.
    # xml_manifest is optional; if not provided we fall back to hashing.
    manifest_lines = []
    if xml_manifest is not None:
        try:
            tree    = LET.parse(str(xml_manifest))
            root_el = tree.getroot()
            ns      = {"d": "http://dataaccessioner.org/schema/dda-1-1"}
            md5_map = {
                file_el.get("name"): file_el.get("MD5")
                for file_el in root_el.xpath("//d:file", namespaces=ns)
            }
            for file_path in sorted(data_dir.rglob("*")):
                if file_path.is_file():
                    rel       = file_path.relative_to(accession_folder).as_posix()
                    # XML stores paths without the leading "data/" prefix
                    xml_key   = file_path.relative_to(data_dir).as_posix()
                    checksum  = md5_map.get(xml_key) or compute_md5(file_path)
                    manifest_lines.append(f"{checksum}  {rel}")
            logging.info("BagIt manifest built from existing XML checksums (no rehashing).")
        except Exception as exc:
            logging.warning(f"Could not read XML manifest for BagIt ({exc}); falling back to hashing.")
            manifest_lines = []

    if not manifest_lines:
        for file_path in sorted(data_dir.rglob("*")):
            if file_path.is_file():
                rel = file_path.relative_to(accession_folder).as_posix()
                manifest_lines.append(f"{compute_md5(file_path)}  {rel}")
    (accession_folder / "manifest-md5.txt").write_text(
        "\n".join(manifest_lines) + "\n", encoding="utf-8"
    )

    # Generate tagmanifest-md5.txt (hash the tag files themselves)
    tag_files = ["bagit.txt", "bag-info.txt", "manifest-md5.txt"]
    tag_manifest_lines = []
    for tag_file in tag_files:
        tf_path = accession_folder / tag_file
        if tf_path.exists():
            tag_manifest_lines.append(f"{compute_md5(tf_path)}  {tag_file}")
    (accession_folder / "tagmanifest-md5.txt").write_text(
        "\n".join(tag_manifest_lines) + "\n", encoding="utf-8"
    )

    bag_root = accession_folder.resolve()
    logging.info(f"BagIt bag created at: {bag_root}")

    # Write APTrust-specific tag file
    if profile == "aptrust":
        if not title:
            raise ValueError("APTrust profile requires a Title.")
        if not source_organization:
            raise ValueError("APTrust profile requires a Source-Organization.")
        _write_aptrust_info(bag_root, title, access, storage_option, description)

    # Optionally validate — rehashes every file so skipped by default
    bag_valid = None
    bag_error = ""
    if validate:
        try:
            bagit.Bag(str(bag_root)).validate()
            bag_valid = True
            logging.info("BagIt bag validated successfully.")
        except bagit.BagValidationError as exc:
            bag_valid = False
            bag_error = str(exc)
            logging.warning(f"BagIt validation warning: {bag_error}")
        except Exception as exc:
            bag_valid = False
            bag_error = str(exc)
            logging.warning(f"BagIt validation error: {bag_error}")

    # Optionally serialise to .tar (required for APTrust ingest uploads)
    # The source bag directory is kept alongside the .tar for local reference.
    tar_path = None
    if serialize_tar and profile == "aptrust":
        tar_path = bag_root.parent / (bag_root.name + ".tar")
        with tarfile.open(tar_path, "w") as tf:
            tf.add(bag_root, arcname=bag_root.name)
        logging.info(f"Bag serialized to tar: {tar_path}")

    return bag_root, tar_path, bag_valid, bag_error


def validate_bag(bag_path):
    """
    Validate an existing BagIt bag directory.
    Returns (is_valid: bool, error_message: str).
    """
    if not BAGIT_AVAILABLE:
        return False, "bagit-python is not installed."
    try:
        bag = bagit.Bag(str(bag_path))
        bag.validate()
        return True, ""
    except bagit.BagValidationError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)


# ==========================
# FIXITY CHECKER
# ==========================

def run_fixity(xml_input, output_folder, accession_number):
    """
    Verify MD5 checksums recorded in the XML manifest against files on disk.
    Always runs before BagIt packaging, so files are always directly inside
    the accession folder (never in a data/ subdirectory at this point).
    Writes a CSV report and log file to output_folder.
    """
    output_folder    = Path(output_folder)
    accession_folder = output_folder / accession_number

    log_file = output_folder / f"fixity_{accession_number}.log"
    csv_file = output_folder / f"fixity_{accession_number}.csv"

    # Use an isolated named logger so the pipeline's root logger is not disturbed
    fixity_log = logging.getLogger(f"fixity.{accession_number}")
    fixity_log.setLevel(logging.INFO)
    fixity_log.handlers.clear()
    fh = logging.FileHandler(log_file, "w", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    fixity_log.addHandler(fh)
    fixity_log.propagate = False  # do not bubble up to root logger

    tree    = LET.parse(str(xml_input))
    root_el = tree.getroot()
    results = []

    for file_el in root_el.xpath(
        "//default:file",
        namespaces={"default": "http://dataaccessioner.org/schema/dda-1-1"}
    ):
        rel        = Path(file_el.get("name"))
        file_path  = accession_folder / rel
        md5_stored = file_el.get("MD5")

        status       = "OK"
        computed_md5 = ""
        error        = ""

        try:
            if not file_path.exists():
                status = "MISSING"
                error  = "File not found"
            else:
                computed_md5 = compute_md5(file_path)
                if computed_md5 != md5_stored:
                    status = "MISMATCH"
        except Exception as exc:
            status = "ERROR"
            error  = str(exc)

        results.append({
            "file_path":    str(file_path),
            "stored_md5":   md5_stored or "",
            "computed_md5": computed_md5 or "",
            "status":       status,
            "error":        error,
        })
        fixity_log.info(f"[{status}] {file_path}")

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["file_path", "stored_md5", "computed_md5", "status", "error"]
        )
        writer.writeheader()
        writer.writerows(results)

    fh.close()
    fixity_log.removeHandler(fh)

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["file_path", "stored_md5", "computed_md5", "status", "error"]
        )
        writer.writeheader()
        writer.writerows(results)

    return csv_file, log_file


# ==========================
# SUMMARY REPORT
# ==========================

def generate_summary_report(csv_file, output_folder, accession_number):
    """
    Read the XSLT-transformed CSV and produce a plain-text summary of
    file extension counts, total size, and guessed MIME types.
    """
    ext_counter  = Counter()
    mime_counter = Counter()
    total_size   = 0

    with open(csv_file, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ext = row.get("file extension", "").lower()
            if ext:
                ext_counter[ext] += 1

            try:
                total_size += int(row.get("size (bytes)", 0))
            except Exception:
                pass

            mime = mimetypes.guess_type(row.get("file name", ""))[0]
            if mime:
                mime_counter[mime] += 1

    output_txt = Path(output_folder) / f"{accession_number}.txt"

    with open(output_txt, "w", encoding="utf-8") as f:
        f.write(f"Accession: {accession_number}\n\n")

        f.write("File Extension Counts:\n")
        for k, v in ext_counter.items():
            f.write(f"  {k}: {v}\n")

        f.write(f"\nTotal Size: {total_size / 1024:.2f} KB\n")

        f.write("\nMIME Type Counts (guessed):\n")
        for k, v in mime_counter.items():
            f.write(f"  {k}: {v}\n")

    return output_txt
