import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import threading
import logging
import traceback
from datetime import datetime

from pipeline import (
    generate_data_accessioner_xml,
    run_xslt_processor,
    run_fixity,
    generate_summary_report,
    run_antivirus_scan,
    update_malware_db,
    create_bag,
    BAGIT_AVAILABLE,
    AV_AVAILABLE,
    MALWARE_DB_PATH,
    APTRUST_ACCESS_VALUES,
    APTRUST_STORAGE_OPTIONS,
)


# ==========================
# INPUT LOCKING
# ==========================

def set_inputs_locked(locked: bool):
    """
    Disable every user-editable widget while the pipeline runs so settings
    cannot be changed mid-run. Re-enables them when done.
    """
    for widget in lockable_inputs:
        try:
            if isinstance(widget, ttk.Combobox):
                widget.config(state="disabled" if locked else "readonly")
            else:
                widget.config(state="disabled" if locked else "normal")
        except tk.TclError:
            pass


# ==========================
# DATABASE UPDATE
# ==========================

def do_update_db():
    """Download the MalwareBazaar hash database in a background thread."""
    update_db_button.config(state="disabled")
    auth_key = auth_key_var.get().strip()
    mode = "full database" if auth_key else "recent list (48 hrs, no key required)"
    av_status_var.set(f"Downloading {mode}...")

    def _run():
        def _progress(msg):
            av_status_var.set(msg)

        success, message = update_malware_db(
            progress_callback=_progress,
            auth_key=auth_key,
        )

        if success:
            import pipeline as test_module
            test_module.AV_AVAILABLE = True
            chk_av.config(state="normal")
            av_var.set(True)
            av_status_var.set(f"Database ready — {_db_info_string()}")
            messagebox.showinfo("Database Updated", message)
        else:
            av_status_var.set("Database update failed.")
            messagebox.showerror(
                "Update Failed",
                f"{message}\n\n"
                "If downloading the full database, check that your Auth-Key is correct.\n"
                "For the recent list (no key), check your internet connection."
            )

        update_db_button.config(state="normal")

    threading.Thread(target=_run, daemon=True).start()


def _db_info_string():
    """Return a short string describing the current database file."""
    if MALWARE_DB_PATH.exists():
        size_mb = MALWARE_DB_PATH.stat().st_size / (1024 * 1024)
        mtime   = datetime.fromtimestamp(MALWARE_DB_PATH.stat().st_mtime)
        return f"updated {mtime.strftime('%Y-%m-%d')}"
    return "not downloaded"


# ==========================
# PIPELINE
# ==========================

def run_pipeline():
    data_dir         = input_dir_var.get()
    out_dir          = output_dir_var.get()
    accession_number = accession_var.get().strip()
    move_files       = move_var.get()
    do_av            = av_var.get()
    do_bag           = bag_var.get()

    if not data_dir or not out_dir or not accession_number:
        messagebox.showerror("Missing Information", "Please fill in all fields before running.")
        run_button.config(state="normal")
        set_inputs_locked(False)
        progress_bar.stop()
        return

    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path  = Path(out_dir) / f"pipeline_log_{accession_number}_{timestamp}.log"

    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        filemode="w",
    )

    infected_files = {}
    bag_valid      = None
    tar_path       = None

    try:
        logging.info("Pipeline started.")

        # ---- STEP 1: ANTIVIRUS SCAN ----
        clean_files = None

        if do_av:
            import pipeline as test_module
            if not test_module.AV_AVAILABLE:
                status_var.set("Step 1/6 — Malware database not found, skipping scan...")
                logging.warning("Malware hash database missing. Skipping antivirus scan.")
            else:
                status_var.set("Step 1/6 — Scanning files against malware database...")
                logging.info("Starting antivirus scan.")

                clean_files, infected_files, av_skipped = run_antivirus_scan(
                    data_dir, out_dir, accession_number
                )

                if av_skipped:
                    status_var.set("Step 1/6 — Antivirus scan skipped.")
                    messagebox.showwarning(
                        "Antivirus Scan Skipped",
                        "The malware database could not be loaded.\n\n"
                        "Pipeline will continue without antivirus."
                    )
                    clean_files = None

                elif infected_files:
                    infected_list = "\n".join(
                        f"  {p.name}: {t}" for p, t in infected_files.items()
                    )
                    proceed = messagebox.askyesno(
                        "Infected Files Detected",
                        f"{len(infected_files)} infected file(s) found and will be EXCLUDED:\n\n"
                        f"{infected_list}\n\n"
                        "Continue pipeline without these files?"
                    )
                    if not proceed:
                        status_var.set("Pipeline cancelled by user.")
                        return
                else:
                    clean_files = None

        logging.info("Antivirus step complete.")

        # ---- STEP 2: DATA ACCESSIONER ----
        status_var.set("Step 2/6 — Copying files and building XML manifest...")
        logging.info("Starting Data Accessioner.")

        xml_report = generate_data_accessioner_xml(
            data_dir, out_dir, accession_number, move_files,
            clean_files_only=clean_files if infected_files else None,
        )
        logging.info("Data Accessioner complete.")

        # ---- STEP 3: XSLT PROCESSOR ----
        status_var.set("Step 3/6 — Generating CSV and HTML reports...")
        logging.info("Starting XSLT processing.")

        script_dir       = Path(__file__).parent
        csv_transformed  = Path(out_dir) / f"{accession_number}_files.csv"
        html_transformed = Path(out_dir) / f"{accession_number}_files.html"

        run_xslt_processor(xml_report, script_dir / "files.csv.xslt",  csv_transformed)
        run_xslt_processor(xml_report, script_dir / "files.html.xslt", html_transformed)
        logging.info("XSLT processing complete.")

        # ---- STEP 4: SUMMARY REPORT ----
        status_var.set("Step 4/6 — Generating summary report...")
        logging.info("Starting summary report generation.")
        generate_summary_report(csv_transformed, out_dir, accession_number)
        logging.info("Summary report complete.")

        # ---- STEP 5: FIXITY CHECK ----
        status_var.set("Step 5/6 — Running fixity check...")
        logging.info("Starting fixity check.")
        run_fixity(xml_report, out_dir, accession_number)
        logging.info("Fixity check complete.")

        # ---- STEP 6: BAGIT PACKAGING ----
        # Explicitly flush and close all logging handlers before bagging.
        # On Windows, open log file handles cause PermissionError when
        # bagit.make_bag() tries to move files within the accession folder.
        for handler in logging.root.handlers[:]:
            handler.flush()
            handler.close()
            logging.root.removeHandler(handler)

        if do_bag:
            if not BAGIT_AVAILABLE:
                status_var.set("Step 6/6 — bagit-python not installed, skipping BagIt...")
                logging.warning("bagit-python not installed. Run: pip install bagit-python")
                messagebox.showwarning(
                    "BagIt Unavailable",
                    "bagit-python is not installed.\n\nRun: pip install bagit-python\n\n"
                    "Pipeline will continue without BagIt packaging."
                )
            else:
                profile       = bag_profile_var.get()
                profile_label = "APTrust" if profile == "aptrust" else "Generic BagIt"
                status_var.set(f"Step 6/6 — Creating {profile_label} bag...")
                logging.info(f"Starting BagIt packaging — profile: {profile}.")

                if profile == "aptrust":
                    if not bag_title_var.get().strip() or not source_org_var.get().strip():
                        messagebox.showerror(
                            "Missing APTrust Fields",
                            "APTrust profile requires both Title and Source-Organization.\n\n"
                            "Please fill in the required (*) fields and try again."
                        )
                        status_var.set("Pipeline stopped — missing required APTrust fields.")
                        return

                accession_folder = Path(out_dir) / accession_number
                bag_path, tar_path, bag_valid, bag_error = create_bag(
                    accession_folder, accession_number,
                    contact_name=contact_name_var.get().strip(),
                    contact_email=contact_email_var.get().strip(),
                    source_organization=source_org_var.get().strip(),
                    profile=profile,
                    title=bag_title_var.get().strip(),
                    access=bag_access_var.get(),
                    storage_option=bag_storage_var.get(),
                    description=bag_desc_var.get().strip(),
                    serialize_tar=serialize_tar_var.get(),
                    validate=validate_bag_var.get(),
                    xml_manifest=xml_report,
                )

                if bag_valid:
                    status_var.set("Step 6/6 — BagIt bag validated.")
                    if tar_path:
                        logging.info(f"Bag serialized to: {tar_path}")
                else:
                    status_var.set("Step 6/6 — BagIt bag created with warnings.")
                    logging.warning(f"BagIt validation warning: {bag_error}")

        # Re-attach the pipeline log handler now that bagging is done
        file_handler = logging.FileHandler(log_path, "a", encoding="utf-8")
        file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logging.root.addHandler(file_handler)
        logging.root.setLevel(logging.INFO)

        # ---- DONE ----
        status_var.set("Pipeline complete.")
        logging.info("Pipeline finished successfully.")

        summary_lines = ["Pipeline completed successfully."]
        if infected_files:
            summary_lines.append(
                f"\n⚠  {len(infected_files)} infected file(s) excluded from ingest."
            )
        if do_bag and BAGIT_AVAILABLE:
            if bag_valid is True:
                summary_lines.append("\n✓  BagIt bag validated.")
                if tar_path:
                    summary_lines.append(f"    Tar archive: {tar_path.name}")
            elif bag_valid is False:
                summary_lines.append(
                    "\n⚠  BagIt bag created but validation had warnings — check log."
                )
        summary_lines.append(f"\nLog file:\n{log_path}")
        messagebox.showinfo("Pipeline Complete", "\n".join(summary_lines))

    except Exception:
        logging.error("Pipeline failed.\n" + traceback.format_exc())
        status_var.set("Pipeline failed — see log for details.")
        messagebox.showerror("Pipeline Error", f"An error occurred.\n\nSee log file:\n{log_path}")

    finally:
        progress_bar.stop()
        run_button.config(state="normal")
        set_inputs_locked(False)


def start_pipeline():
    status_var.set("Starting pipeline...")
    run_button.config(state="disabled")
    set_inputs_locked(True)
    progress_bar.start(10)
    threading.Thread(target=run_pipeline, daemon=True).start()


# ==========================
# BAG FRAME VISIBILITY
# ==========================

def on_profile_change(*_):
    toggle_bag_fields()


def toggle_bag_fields():
    if not bag_var.get() or not BAGIT_AVAILABLE:
        bag_frame.grid_remove()
        return
    bag_frame.grid()
    is_aptrust = (bag_profile_var.get() == "aptrust")
    for widget in aptrust_only_widgets:
        if is_aptrust:
            widget.grid()
        else:
            widget.grid_remove()
    root.update_idletasks()


# ==========================
# GUI SETUP
# ==========================

root = tk.Tk()
root.title("Archival Pipeline")
root.geometry("700x700")
root.resizable(False, False)

input_dir_var    = tk.StringVar()
output_dir_var   = tk.StringVar()
accession_var    = tk.StringVar()
move_var         = tk.BooleanVar()
av_var           = tk.BooleanVar(value=AV_AVAILABLE)
bag_var          = tk.BooleanVar(value=True)
status_var       = tk.StringVar(value="Idle")
av_status_var    = tk.StringVar()
auth_key_var     = tk.StringVar()

bag_profile_var   = tk.StringVar(value="aptrust")
source_org_var    = tk.StringVar()
contact_name_var  = tk.StringVar()
contact_email_var = tk.StringVar()
bag_title_var     = tk.StringVar()
bag_access_var    = tk.StringVar(value="Institution")
bag_storage_var   = tk.StringVar(value="Standard")
bag_desc_var      = tk.StringVar()
serialize_tar_var = tk.BooleanVar(value=True)
validate_bag_var  = tk.BooleanVar(value=False)

# Uniform padding used throughout
pad    = {"padx": 10, "pady": 3}   # outer form rows
ipad   = {"padx": 6,  "pady": 3}   # inner frame rows (labels)
epad   = {"padx": 0,  "pady": 3}   # inner frame rows (entries/widgets)

# Input Directory
tk.Label(root, text="Input Directory:").grid(row=0, column=0, sticky="e", **pad)
ent_input = tk.Entry(root, textvariable=input_dir_var, width=42)
ent_input.grid(row=0, column=1, **pad)
btn_input = tk.Button(root, text="Browse",
                      command=lambda: input_dir_var.set(filedialog.askdirectory()))
btn_input.grid(row=0, column=2, padx=5)

# Output Directory
tk.Label(root, text="Output Directory:").grid(row=1, column=0, sticky="e", **pad)
ent_output = tk.Entry(root, textvariable=output_dir_var, width=42)
ent_output.grid(row=1, column=1, **pad)
btn_output = tk.Button(root, text="Browse",
                       command=lambda: output_dir_var.set(filedialog.askdirectory()))
btn_output.grid(row=1, column=2, padx=5)

# Accession Number
tk.Label(root, text="Accession Number:").grid(row=2, column=0, sticky="e", **pad)
ent_accession = tk.Entry(root, textvariable=accession_var, width=28)
ent_accession.grid(row=2, column=1, sticky="w", **pad)

# Move Files
chk_move = tk.Checkbutton(root, text="Move files instead of copy", variable=move_var)
chk_move.grid(row=3, column=1, sticky="w", padx=10, pady=2)

# ---- Antivirus section ----
av_frame = tk.LabelFrame(root, text="Antivirus — MalwareBazaar Hash Check", padx=8, pady=4)
av_frame.grid(row=4, column=0, columnspan=3, sticky="ew", padx=10, pady=3)

chk_av = tk.Checkbutton(av_frame, text="Scan files against malware database",
                        variable=av_var,
                        state="normal" if AV_AVAILABLE else "disabled")
chk_av.grid(row=0, column=0, sticky="w")

update_db_button = tk.Button(av_frame, text="Update Malware Database",
                             command=do_update_db)
update_db_button.grid(row=0, column=1, padx=10)

db_info = _db_info_string() if AV_AVAILABLE else "not downloaded"
av_status_var.set(f"Database: {db_info}" if AV_AVAILABLE else "Database not downloaded yet")
tk.Label(av_frame, textvariable=av_status_var, fg="gray",
         font=("TkDefaultFont", 8)).grid(row=1, column=0, columnspan=2, sticky="w", padx=4)

tk.Label(av_frame, text="Auth-Key (optional):").grid(row=2, column=0, sticky="e", padx=6, pady=3)
ent_auth_key = tk.Entry(av_frame, textvariable=auth_key_var, width=36)
ent_auth_key.grid(row=2, column=1, sticky="w", pady=3)
tk.Label(av_frame, text="Leave blank for recent list (free). Full database requires a key from bazaar.abuse.ch/api/",
         fg="gray", font=("TkDefaultFont", 8)
         ).grid(row=3, column=0, columnspan=3, sticky="w", padx=6, pady=(0, 2))

# BagIt checkbox
bag_label = ("Create BagIt package" if BAGIT_AVAILABLE
             else "Create BagIt package (install bagit-python to enable)")
chk_bag = tk.Checkbutton(root, text=bag_label, variable=bag_var,
                         command=toggle_bag_fields,
                         state="normal" if BAGIT_AVAILABLE else "disabled")
chk_bag.grid(row=5, column=1, sticky="w", padx=10, pady=2)

# ---- BagIt metadata frame ----
bag_frame = tk.LabelFrame(root, text="BagIt Metadata", padx=8, pady=4)
bag_frame.grid(row=6, column=0, columnspan=3, sticky="ew", padx=10, pady=3)
aptrust_only_widgets = []
r = 0

tk.Label(bag_frame, text="BagIt Profile:").grid(row=r, column=0, sticky="e", **ipad)
pf = tk.Frame(bag_frame)
pf.grid(row=r, column=1, columnspan=2, sticky="w", **epad)
rb_aptrust = tk.Radiobutton(pf, text="APTrust", variable=bag_profile_var,
                             value="aptrust", command=on_profile_change)
rb_aptrust.pack(side="left")
rb_generic = tk.Radiobutton(pf, text="Generic BagIt", variable=bag_profile_var,
                              value="generic", command=on_profile_change)
rb_generic.pack(side="left", padx=10)
r += 1

tk.Label(bag_frame, text="Source-Organization: *").grid(row=r, column=0, sticky="e", **ipad)
ent_source_org = tk.Entry(bag_frame, textvariable=source_org_var, width=36)
ent_source_org.grid(row=r, column=1, sticky="w", **epad); r += 1

tk.Label(bag_frame, text="Contact Name:").grid(row=r, column=0, sticky="e", **ipad)
ent_contact_name = tk.Entry(bag_frame, textvariable=contact_name_var, width=36)
ent_contact_name.grid(row=r, column=1, sticky="w", **epad); r += 1

tk.Label(bag_frame, text="Contact Email:").grid(row=r, column=0, sticky="e", **ipad)
ent_contact_email = tk.Entry(bag_frame, textvariable=contact_email_var, width=36)
ent_contact_email.grid(row=r, column=1, sticky="w", **epad); r += 1

lbl_title = tk.Label(bag_frame, text="Title: *")
lbl_title.grid(row=r, column=0, sticky="e", **ipad)
ent_title = tk.Entry(bag_frame, textvariable=bag_title_var, width=36)
ent_title.grid(row=r, column=1, sticky="w", **epad)
aptrust_only_widgets += [lbl_title, ent_title]; r += 1

lbl_access = tk.Label(bag_frame, text="Access: *")
lbl_access.grid(row=r, column=0, sticky="e", **ipad)
access_frame = tk.Frame(bag_frame)
access_frame.grid(row=r, column=1, sticky="w", **epad)
cmb_access = ttk.Combobox(access_frame, textvariable=bag_access_var,
                           values=APTRUST_ACCESS_VALUES, state="readonly", width=16)
cmb_access.pack(side="left")
tk.Label(access_frame, text="Institution = visible to all staff at your org",
         fg="gray", font=("TkDefaultFont", 8)).pack(side="left", padx=6)
aptrust_only_widgets += [lbl_access, access_frame]; r += 1

lbl_storage = tk.Label(bag_frame, text="Storage-Option: *")
lbl_storage.grid(row=r, column=0, sticky="e", **ipad)
cmb_storage = ttk.Combobox(bag_frame, textvariable=bag_storage_var,
                            values=APTRUST_STORAGE_OPTIONS, state="readonly", width=18)
cmb_storage.grid(row=r, column=1, sticky="w", **epad)
aptrust_only_widgets += [lbl_storage, cmb_storage]; r += 1

lbl_desc = tk.Label(bag_frame, text="Description:")
lbl_desc.grid(row=r, column=0, sticky="e", **ipad)
ent_desc = tk.Entry(bag_frame, textvariable=bag_desc_var, width=36)
ent_desc.grid(row=r, column=1, sticky="w", **epad)
aptrust_only_widgets += [lbl_desc, ent_desc]; r += 1

chk_tar = tk.Checkbutton(bag_frame,
                          text="Serialize to .tar (required for APTrust upload)",
                          variable=serialize_tar_var)
chk_tar.grid(row=r, column=1, sticky="w", padx=0, pady=2)
aptrust_only_widgets.append(chk_tar); r += 1

chk_validate = tk.Checkbutton(bag_frame,
                               text="Validate bag after creation (slower — rehashes all files)",
                               variable=validate_bag_var)
chk_validate.grid(row=r, column=1, sticky="w", padx=0, pady=2)
r += 1

lbl_req = tk.Label(bag_frame, text="* Required for APTrust",
                    fg="gray", font=("TkDefaultFont", 8))
lbl_req.grid(row=r, column=1, sticky="w", padx=2, pady=(0, 2))
aptrust_only_widgets.append(lbl_req)

# ---- Lockable inputs (disabled during pipeline run) ----
lockable_inputs = [
    ent_input, btn_input,
    ent_output, btn_output,
    ent_accession,
    chk_move, chk_av, ent_auth_key, update_db_button, chk_bag,
    rb_aptrust, rb_generic,
    ent_source_org, ent_contact_name, ent_contact_email,
    ent_title, cmb_access, cmb_storage, ent_desc, chk_tar, chk_validate,
]

if not BAGIT_AVAILABLE:
    bag_frame.grid_remove()
else:
    toggle_bag_fields()

# Status
tk.Label(root, textvariable=status_var, anchor="w", fg="blue").grid(
    row=7, column=0, columnspan=3, sticky="w", padx=10, pady=3)

# Run button
run_button = tk.Button(root, text="Run Pipeline", command=start_pipeline,
                       bg="#4CAF50", fg="white", width=15)
run_button.grid(row=8, column=1, pady=6)

# Progress bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=420, mode="indeterminate")
progress_bar.grid(row=9, column=0, columnspan=4, padx=10, pady=(0, 8))

root.mainloop()
