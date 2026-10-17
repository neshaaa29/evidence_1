import os
import shutil
import hashlib
from pathlib import Path
from datetime import datetime

import pandas as pd
import ipywidgets as widgets
from IPython.display import display, clear_output, HTML

# Confirm that the backend was run in this notebook kernel.
_required_backend_names = [
    "OUT", "FILES", "REGISTRY", "LOG", "FMT", "REG_FIELDS", "LOG_FIELDS",
    "read_registry", "save_registry", "read_log", "rebuild_log",
    "sha256_file", "screen_evidence", "detect_anomalies"
]
_missing = [name for name in _required_backend_names if name not in globals()]
if _missing:
    raise RuntimeError(
        "Run the existing EvidenceGuard_Complete.py backend cells in this SAME "
        "Jupyter kernel before running this frontend. Missing: " + ", ".join(_missing)
    )

# Use existing backend storage and functions; do not initialize demo data.
FILES.mkdir(parents=True, exist_ok=True)

# ---------- UI theme ----------
display(HTML("""
<style>
.eg-root { font-family: Inter, system-ui, -apple-system, Segoe UI, sans-serif; color:#172033; }
.eg-hero { background:linear-gradient(120deg,#101b32,#24466c); padding:24px 28px;
           border-radius:16px; color:white; margin:8px 0 18px 0; }
.eg-hero h1 { color:white; margin:0; font-size:28px; }
.eg-hero p { color:#d5e4f5; margin:8px 0 0 0; }
.eg-note { background:#f4f7fb; border:1px solid #dce5f0; padding:12px 14px;
           border-radius:10px; margin:8px 0 14px 0; }
.eg-kpi { background:white; border:1px solid #e0e7f0; border-radius:12px;
          padding:14px 16px; min-width:130px; }
.eg-kpi-label { color:#63738a; font-size:12px; }
.eg-kpi-value { color:#14213d; font-size:26px; font-weight:750; }
</style>
<div class="eg-root eg-hero">
  <h1>🛡️ EvidenceGuard</h1>
  <p>Forensic evidence intake · SHA-256 integrity · screening · chain-of-custody audit</p>
</div>
<div class="eg-note"><b>Connected mode:</b> This interface uses the backend functions and CSV/file storage
already loaded in this notebook. It does not seed sample records automatically.</div>
"""))

# ---------- Shared helpers ----------
def _records_df():
    records = read_registry()
    if not records:
        return pd.DataFrame(columns=REG_FIELDS)
    return pd.DataFrame(list(records.values()))

def _audit_df():
    rows = read_log()
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=LOG_FIELDS)

def _status_counts():
    reg = read_registry()
    total = len(reg)
    flagged = 0
    screening_field = "screening_score"
    for record in reg.values():
        try:
            if float(record.get(screening_field, 0) or 0) >= 10:
                flagged += 1
        except (TypeError, ValueError):
            pass
    return total, flagged, len(read_log())

def _refresh_notice(out, message, kind="info"):
    with out:
        clear_output()
        if kind == "error":
            display(HTML(f'<div style="padding:10px;border-radius:8px;background:#fff0f0;color:#9b1c1c">{message}</div>'))
        elif kind == "success":
            display(HTML(f'<div style="padding:10px;border-radius:8px;background:#eaf8ef;color:#176534">{message}</div>'))
        else:
            display(HTML(f'<div style="padding:10px;border-radius:8px;background:#eef5ff;color:#24466c">{message}</div>'))

def _make_event(eid, case_id, action, user, role, timestamp, digest, is_anomaly=0, anomaly_type=""):
    return {
        "evidence_id": eid, "case_id": case_id, "action": action, "user": user,
        "role": role, "timestamp": timestamp, "file_sha256": digest,
        "is_anomaly": is_anomaly, "anomaly_type": anomaly_type
    }

def _append_audit_event(event):
    events = []
    for row in read_log():
        events.append({
            "evidence_id": row.get("evidence_id", ""),
            "case_id": row.get("case_id", ""),
            "action": row.get("action", ""),
            "user": row.get("user", ""),
            "role": row.get("role", ""),
            "timestamp": row.get("timestamp", ""),
            "file_sha256": row.get("file_sha256", ""),
            "is_anomaly": row.get("is_anomaly", 0),
            "anomaly_type": row.get("anomaly_type", "")
        })
    events.append(event)
    rebuild_log(events)

# ---------- Navigation ----------
nav = widgets.ToggleButtons(
    options=[
        ("Overview", "overview"),
        ("Register evidence", "register"),
        ("Evidence registry", "registry"),
        ("Integrity check", "integrity"),
        ("Audit & anomalies", "audit"),
    ],
    value="overview",
    button_style="",
    layout=widgets.Layout(width="100%", flex_flow="row wrap")
)
page = widgets.Output()
display(nav, page)

# ---------- Overview ----------
def _render_overview():
    with page:
        clear_output()
        total, flagged, events = _status_counts()
        reg = _records_df()
        display(HTML(f"""
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin:8px 0 18px">
          <div class="eg-kpi"><div class="eg-kpi-label">Registered evidence</div><div class="eg-kpi-value">{total}</div></div>
          <div class="eg-kpi"><div class="eg-kpi-label">Flagged by screening score ≥ 10</div><div class="eg-kpi-value">{flagged}</div></div>
          <div class="eg-kpi"><div class="eg-kpi-label">Audit entries</div><div class="eg-kpi-value">{events}</div></div>
        </div>
        <h3 style="color:#172033">Recent evidence</h3>
        """))
        if reg.empty:
            display(HTML("<p>No evidence records found in the existing registry. Register a real file to begin; no sample records were added.</p>"))
        else:
            cols = [c for c in ["evidence_id","case_id","filename","submitted_by","submitted_at","screening_status","screening_score"] if c in reg.columns]
            display(reg[cols].tail(10).iloc[::-1].reset_index(drop=True))
        display(HTML("<p style='color:#63738a'>Use the tabs above to register a file, review stored evidence, check integrity, or inspect the audit log.</p>"))

# ---------- Registration ----------
case_id = widgets.Text(description="Case ID:", placeholder="e.g. CASE-2026-019", layout=widgets.Layout(width="98%"))
submitter = widgets.Text(description="Submitted by:", placeholder="Name or user ID", layout=widgets.Layout(width="98%"))
file_path = widgets.Text(description="File path:", placeholder="/path/to/evidence-file", layout=widgets.Layout(width="98%"))
reference_path = widgets.Text(description="Trusted ref:", placeholder="Optional path to trusted original", layout=widgets.Layout(width="98%"))
register_btn = widgets.Button(description="Register & screen evidence", button_style="primary", icon="shield")
register_out = widgets.Output()

def _register_evidence(_):
    with register_out:
        clear_output()
        try:
            source = Path(file_path.value.strip().strip('"')).expanduser()
            cid = case_id.value.strip()
            user = submitter.value.strip()
            ref_text = reference_path.value.strip().strip('"')
            if not source.is_file():
                raise ValueError("Evidence file path does not point to an existing file.")
            if not cid or not user:
                raise ValueError("Case ID and submitter are required.")

            registry = read_registry()
            reference_hash = ""
            reference_status = "NO_REFERENCE_PROVIDED"
            reference_mismatch = False
            if ref_text:
                reference = Path(ref_text).expanduser()
                if not reference.is_file():
                    raise ValueError("Trusted reference file was not found.")
                if reference.resolve() == source.resolve():
                    raise ValueError("Evidence and trusted reference paths are the same file.")
                reference_hash = sha256_file(reference)
                if sha256_file(source) == reference_hash:
                    reference_status = "MATCHES_TRUSTED_REFERENCE"
                else:
                    reference_status = "HASH_MISMATCH_POSSIBLY_MODIFIED"
                    reference_mismatch = True

            print("Running existing backend screening function…")
            screening = screen_evidence(source)
            if reference_mismatch:
                screening["score"] = 100
                screening["status"] = "REFERENCE HASH MISMATCH - FLAGGED FOR MANUAL REVIEW"
                screening["findings"].insert(0, "Uploaded file SHA-256 does not match the trusted reference file")
            elif reference_status == "MATCHES_TRUSTED_REFERENCE":
                screening["findings"].insert(0, "SHA-256 matches the supplied trusted reference file")

            FILES.mkdir(parents=True, exist_ok=True)
            numbers = [int(eid[3:]) for eid in registry if eid.startswith("EV-") and eid[3:].isdigit()]
            eid = f"EV-{max(numbers, default=0) + 1:03d}"
            filename = source.name
            destination = FILES / filename
            if destination.exists():
                stem, suffix = source.stem, source.suffix
                counter = 2
                while (FILES / f"{stem}_{counter}{suffix}").exists():
                    counter += 1
                filename = f"{stem}_{counter}{suffix}"
                destination = FILES / filename

            before = sha256_file(source)
            shutil.copy2(source, destination)
            after = sha256_file(source)
            stored = sha256_file(destination)
            if before != after or stored != before:
                try:
                    destination.unlink()
                except OSError:
                    pass
                raise RuntimeError("Upload blocked: source changed during copy or stored hash differs. Retry with a stable file.")

            timestamp = datetime.now().replace(microsecond=0).strftime(FMT)
            record = {
                "evidence_id": eid,
                "case_id": cid,
                "filename": filename,
                "original_sha256": stored,
                "submitted_by": user,
                "submitted_at": timestamp,
                "reference_sha256": reference_hash,
                "reference_status": reference_status,
                "screening_score": screening["score"],
                "screening_status": screening["status"],
                "screening_findings": "; ".join(screening["findings"])
            }
            registry[eid] = record
            save_registry(registry)

            anomaly = int(screening["score"] >= 10 or reference_mismatch)
            event_kind = "reference_hash_mismatch" if reference_mismatch else (
                "potential_manipulation" if screening["score"] >= 25 else
                ("suspicious_indicators" if anomaly else "")
            )
            _append_audit_event(_make_event(
                eid, cid, "SUBMITTED", user, "user_submitted", timestamp,
                stored, anomaly, event_kind
            ))

            display(HTML(f"<h3 style='color:#176534'>Evidence registered: {eid}</h3>"))
            display(pd.DataFrame([{
                "Evidence ID": eid, "Case ID": cid, "File": filename,
                "SHA-256": stored, "Screening score": f'{screening["score"]}/100',
                "Screening status": screening["status"],
                "Reference comparison": reference_status
            }]))
            print("\nScreening findings:")
            for finding in screening["findings"]:
                print(" •", finding)
            print("\nStored file:", destination.resolve())
            print("Note: screening indicators are not proof of manipulation or authenticity.")
        except Exception as exc:
            display(HTML(f'<div style="padding:10px;background:#fff0f0;color:#9b1c1c;border-radius:8px"><b>Registration failed:</b> {type(exc).__name__}: {exc}</div>'))

register_btn.on_click(_register_evidence)

# ---------- Registry ----------
search_box = widgets.Text(placeholder="Search evidence ID, case, filename, submitter…", description="Search:", layout=widgets.Layout(width="98%"))
refresh_registry_btn = widgets.Button(description="Refresh registry", icon="refresh")
registry_out = widgets.Output()

def _render_registry(_=None):
    with registry_out:
        clear_output()
        df = _records_df()
        if df.empty:
            print("No evidence records found in the existing backend registry.")
            return
        term = search_box.value.strip().lower()
        if term:
            mask = df.astype(str).apply(lambda col: col.str.lower().str.contains(term, regex=False)).any(axis=1)
            df = df[mask]
        display(df.reset_index(drop=True))

refresh_registry_btn.on_click(_render_registry)

# ---------- Integrity ----------
integrity_selector = widgets.Dropdown(options=[], description="Evidence:", layout=widgets.Layout(width="98%"))
integrity_btn = widgets.Button(description="Verify selected evidence", button_style="primary", icon="check")
integrity_refresh = widgets.Button(description="Refresh IDs", icon="refresh")
integrity_out = widgets.Output()

def _refresh_integrity_ids(_=None):
    records = read_registry()
    opts = [(f"{eid} — {r.get('filename','')}", eid) for eid, r in records.items()]
    integrity_selector.options = opts
    if opts and integrity_selector.value not in [v for _, v in opts]:
        integrity_selector.value = opts[0][1]
    if not opts:
        integrity_selector.value = None

def _verify_selected(_):
    with integrity_out:
        clear_output()
        eid = integrity_selector.value
        registry = read_registry()
        if not eid or eid not in registry:
            print("No evidence selected. Refresh IDs after registering evidence.")
            return
        rec = registry[eid]
        path = FILES / rec["filename"]
        timestamp = datetime.now().replace(microsecond=0).strftime(FMT)
        if not path.is_file():
            status = "MISSING"
            print(f"{eid} — {rec['filename']} — FILE MISSING")
        else:
            actual = sha256_file(path)
            expected = rec.get("original_sha256", "")
            if actual == expected:
                status = "OK"
                display(HTML(f'<div style="padding:12px;background:#eaf8ef;color:#176534;border-radius:8px"><b>INTEGRITY OK</b> — current file matches its intake SHA-256.</div>'))
            else:
                status = "CHANGED/TAMPERED SINCE INTAKE"
                display(HTML(f'<div style="padding:12px;background:#fff0f0;color:#9b1c1c;border-radius:8px"><b>HASH MISMATCH</b> — current file differs from its intake SHA-256.</div>'))
            print("Evidence:", eid, "|", rec["filename"])
            print("Recorded SHA-256:", expected)
            print("Current SHA-256: ", actual)
        # Log the integrity check using existing audit chain.
        _append_audit_event(_make_event(
            eid, rec.get("case_id", ""), "INTEGRITY_CHECK_" + status,
            "jupyter_user", "frontend", timestamp,
            rec.get("original_sha256", ""), int(status != "OK"),
            "integrity_check_" + status.lower().replace("/", "_").replace(" ", "_") if status != "OK" else ""
        ))

integrity_refresh.on_click(_refresh_integrity_ids)
integrity_btn.on_click(_verify_selected)
_refresh_integrity_ids()

# ---------- Audit and anomalies ----------
audit_refresh_btn = widgets.Button(description="Refresh audit log", icon="refresh")
anomaly_btn = widgets.Button(description="Run anomaly detection", button_style="warning", icon="search")
audit_out = widgets.Output()
anomaly_out = widgets.Output()

def _render_audit(_=None):
    with audit_out:
        clear_output()
        df = _audit_df()
        if df.empty:
            print("No audit entries found in the existing backend log.")
        else:
            display(df.iloc[::-1].reset_index(drop=True))

def _run_anomalies(_):
    with anomaly_out:
        clear_output()
        print("Running existing backend detect_anomalies() function…\n")
        detect_anomalies()

audit_refresh_btn.on_click(_render_audit)
anomaly_btn.on_click(_run_anomalies)

# ---------- Render page ----------
def _show_page(change=None):
    with page:
        clear_output()
        if nav.value == "overview":
            _render_overview()
        elif nav.value == "register":
            display(HTML("<h3 style='color:#172033'>Register evidence</h3><p>Enter a local file path accessible to this Jupyter kernel. A trusted reference is optional.</p>"))
            display(case_id, submitter, file_path, reference_path, register_btn, register_out)
        elif nav.value == "registry":
            display(HTML("<h3 style='color:#172033'>Evidence registry</h3>"))
            display(search_box, refresh_registry_btn, registry_out)
            _render_registry()
        elif nav.value == "integrity":
            display(HTML("<h3 style='color:#172033'>Integrity verification</h3><p>Checks the stored evidence file against the SHA-256 recorded at intake and appends the result to the audit log.</p>"))
            display(integrity_refresh, integrity_selector, integrity_btn, integrity_out)
            _refresh_integrity_ids()
        elif nav.value == "audit":
            display(HTML("<h3 style='color:#172033'>Audit log & anomaly detection</h3>"))
            display(audit_refresh_btn, audit_out, anomaly_btn, anomaly_out)
            _render_audit()

nav.observe(_show_page, names="value")
_show_page()

print("EvidenceGuard Jupyter frontend loaded. Backend data has not been reset or seeded.")
