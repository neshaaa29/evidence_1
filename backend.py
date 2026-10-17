#!/usr/bin/env python3
"""EvidenceGuard demo with automatic preliminary forensic screening at intake.

Run this whole file as a script, or paste it into one Jupyter cell.
Notebook steps:
    setup_demo()
    intake_evidence()
    show_evidence()
    verify_evidence()
    detect_anomalies()
"""
import csv
import hashlib
import json
import os
import random
import shutil
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path("evidence_demo")
FILES = OUT / "files"
REGISTRY = OUT / "evidence_registry.csv"
LOG = OUT / "audit_log.csv"
FMT = "%Y-%m-%d %H:%M:%S"
ZERO = "0" * 64
REG_FIELDS = ["evidence_id", "case_id", "filename", "original_sha256", "submitted_by", "submitted_at", "reference_sha256", "reference_status", "screening_score", "screening_status", "screening_findings"]
LOG_FIELDS = ["seq", "evidence_id", "case_id", "action", "user", "role", "timestamp",
              "file_sha256", "prev_hash", "entry_hash", "is_anomaly", "anomaly_type"]

SAMPLES = [
    ("EV-001", "CASE-2026-014", "whatsapp_chat.txt", "Ravi: transfer done\\nAmit: call me\\nSuresh: meet at 8\\n"),
    ("EV-002", "CASE-2026-014", "bank_statement.csv", "date,description,amount_inr\\n2026-08-01,UPI,-1200\\n2026-08-02,NEFT,5000\\n"),
    ("EV-003", "CASE-2026-015", "cctv_clip.mp4", None),
    ("EV-004", "CASE-2026-015", "photo_scene.jpg", None),
    ("EV-005", "CASE-2026-016", "email_export.json", None),
]


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def entry_hash(seq, eid, action, user, ts, sha, prev):
    return sha256_bytes("|".join(map(str, [seq, eid, action, user, ts, sha, prev])).encode())


def read_registry():
    if not REGISTRY.exists():
        return {}
    with REGISTRY.open(newline="", encoding="utf-8") as f:
        return {r["evidence_id"]: r for r in csv.DictReader(f)}


def read_log():
    if not LOG.exists():
        return []
    with LOG.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_registry(registry):
    OUT.mkdir(exist_ok=True)
    with REGISTRY.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=REG_FIELDS)
        w.writeheader()
        for r in registry.values():
            w.writerow(r)


def rebuild_log(events):
    events.sort(key=lambda x: x["timestamp"])
    rows, previous = [], ZERO
    for seq, e in enumerate(events, 1):
        ts = e["timestamp"]
        h = entry_hash(seq, e["evidence_id"], e["action"], e["user"], ts, e["file_sha256"], previous)
        rows.append({
            "seq": seq, "evidence_id": e["evidence_id"], "case_id": e["case_id"],
            "action": e["action"], "user": e["user"], "role": e["role"], "timestamp": ts,
            "file_sha256": e["file_sha256"], "prev_hash": previous, "entry_hash": h,
            "is_anomaly": e.get("is_anomaly", 0), "anomaly_type": e.get("anomaly_type", "")
        })
        previous = h
    with LOG.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        w.writeheader()
        w.writerows(rows)


def setup_demo():
    """Create five sample evidence records without overwriting existing files."""
    OUT.mkdir(exist_ok=True)
    FILES.mkdir(parents=True, exist_ok=True)
    registry = read_registry()
    events = []
    for row in read_log():
        events.append({
            "evidence_id": row["evidence_id"], "case_id": row["case_id"],
            "action": row["action"], "user": row["user"], "role": row["role"],
            "timestamp": row["timestamp"], "file_sha256": row["file_sha256"],
            "is_anomaly": row.get("is_anomaly", 0), "anomaly_type": row.get("anomaly_type", "")
        })

    sample_data = {
        "whatsapp_chat.txt": b"Ravi: transfer done\\nAmit: call me\\nSuresh: meet at 8\\n",
        "bank_statement.csv": b"date,description,amount_inr\\n2026-08-01,UPI,-1200\\n2026-08-02,NEFT,5000\\n",
        "cctv_clip.mp4": b"DEMO ONLY - placeholder CCTV sample file",
        "photo_scene.jpg": b"DEMO ONLY - placeholder image file",
        "email_export.json": json.dumps([{"from":"demo@example.com","subject":"Sample email"}]).encode()
    }
    for eid, case_id, filename, _ in SAMPLES:
        target = FILES / filename
        if eid in registry and target.exists():
            continue
        data = sample_data[filename]
        if target.exists() and eid not in registry:
            # Do not overwrite a file that may have been uploaded by the user.
            continue
        target.write_bytes(data)
        now = datetime.now().replace(microsecond=0).strftime(FMT)
        digest = sha256_bytes(data)
        registry[eid] = {"evidence_id": eid, "case_id": case_id, "filename": filename,
                         "original_sha256": digest, "submitted_by": "demo_system", "submitted_at": now}
        events.append({"evidence_id": eid, "case_id": case_id, "action": "SUBMITTED",
                       "user": "demo_system", "role": "system", "timestamp": now,
                       "file_sha256": digest, "is_anomaly": 0, "anomaly_type": ""})
    save_registry(registry)
    rebuild_log(events)
    print(f"Demo ready. Registered sample records: {len(registry)}")
    print(f"Evidence folder: {FILES.resolve()}")
    print("Note: sample files are placeholders for demonstration, not real CCTV/images.")



def screen_evidence(path):
    """Automatic first-pass forensic screening. Heuristics are not proof of editing."""
    suffix = path.suffix.lower()
    findings = []
    score = 0
    kind = "file"

    # Image screening: metadata inspection plus Error Level Analysis (ELA).
    if suffix in {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".bmp"}:
        kind = "image"
        try:
            from PIL import Image, ImageChops, ImageEnhance
            import io
            with Image.open(path) as image:
                image.verify()
            with Image.open(path) as image:
                metadata = dict(image.getexif()) if hasattr(image, "getexif") else {}
                image_format = image.format
                image_size = image.size
                image.load()
                if image_format not in {"JPEG", "PNG", "WEBP", "TIFF", "BMP"}:
                    findings.append("Unusual or unsupported image format")
                    score += 10
                if image.width < 100 or image.height < 100:
                    findings.append("Very small image; forensic analysis may be limited")
                    score += 5

                # ELA is meaningful mainly for JPEGs; for other formats report metadata only.
                if image_format == "JPEG":
                    buffer = io.BytesIO()
                    image.convert("RGB").save(buffer, format="JPEG", quality=90)
                    buffer.seek(0)
                    recompressed = Image.open(buffer).convert("RGB")
                    original = image.convert("RGB")
                    diff = ImageChops.difference(original, recompressed)
                    extrema = diff.getextrema()
                    max_diff = max(channel[1] for channel in extrema)
                    amplified = ImageEnhance.Brightness(diff).enhance(4)
                    # Average pixel difference as a rough indicator, not a calibrated classifier.
                    import statistics
                    sample = list(amplified.convert("L").resize((min(100, image.width), min(100, image.height))).getdata())
                    mean_diff = sum(sample) / max(len(sample), 1)
                    if mean_diff > 18:
                        findings.append("High JPEG recompression difference (ELA indicator)")
                        score += 25
                    elif mean_diff > 10:
                        findings.append("Moderate JPEG recompression difference (ELA indicator)")
                        score += 12
                    if max_diff > 200:
                        findings.append("Some regions differ strongly after recompression")
                        score += 5
                else:
                    findings.append("ELA not applied: this image format is not JPEG")

                # Metadata absence is common and is not proof of manipulation.
                if not metadata:
                    findings.append("No EXIF metadata found (common for messaging-app images too)")
                    score += 5
                else:
                    software_tag = metadata.get(305)  # EXIF Software
                    if software_tag:
                        findings.append(f"Software metadata present: {str(software_tag)[:80]}")
                        score += 8
        except ImportError:
            findings.append("Pillow is not installed; image analysis unavailable")
        except Exception as exc:
            findings.append(f"Image could not be fully analyzed: {type(exc).__name__}")
            score += 20

    # Video screening: sample a few frames if OpenCV is installed, then apply image checks.
    elif suffix in {".mp4", ".mov", ".avi", ".mkv", ".webm"}:
        kind = "video"
        try:
            import cv2
            capture = cv2.VideoCapture(str(path))
            if not capture.isOpened():
                findings.append("Video could not be decoded; format or codec may be unsupported")
                score += 15
            else:
                frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
                fps = float(capture.get(cv2.CAP_PROP_FPS) or 0)
                findings.append(f"Video metadata: {frame_count} frames, {fps:.2f} FPS")
                if frame_count <= 0 or fps <= 0:
                    findings.append("Missing or unusual video stream metadata")
                    score += 10
                # Inspect up to 5 evenly spaced frames for decode errors/near-duplicates.
                sample_count = min(5, max(frame_count, 0))
                means = []
                for i in range(sample_count):
                    frame_no = int(i * max(frame_count - 1, 0) / max(sample_count - 1, 1))
                    capture.set(cv2.CAP_PROP_POS_FRAMES, frame_no)
                    ok, frame = capture.read()
                    if not ok or frame is None:
                        findings.append(f"Frame {frame_no} failed to decode")
                        score += 5
                    else:
                        means.append(float(frame.mean()))
                if len(means) >= 3 and max(means) - min(means) < 1.0:
                    findings.append("Sampled frames have unusually similar average brightness; manual review suggested")
                    score += 5
                capture.release()
        except ImportError:
            findings.append("OpenCV is not installed; video frame screening unavailable")
        except Exception as exc:
            findings.append(f"Video screening error: {type(exc).__name__}")
            score += 15

    # PDF / Office documents: structural checks and metadata hints, not content authenticity.
    elif suffix == ".pdf":
        kind = "PDF/document"
        try:
            data = path.read_bytes()[:2_000_000]
            if not data.startswith(b"%PDF-"):
                findings.append("Missing expected PDF header")
                score += 25
            if b"/ModDate" in data:
                findings.append("PDF contains a modification-date field")
                score += 5
            if b"/JavaScript" in data or b"/JS " in data:
                findings.append("PDF contains a JavaScript-related marker; inspect manually")
                score += 10
            if b"/Prev" in data or b"%%EOF" in data:
                findings.append("PDF structural markers found; these alone do not indicate tampering")
        except Exception as exc:
            findings.append(f"PDF screening error: {type(exc).__name__}")
            score += 15
    elif suffix in {".docx", ".xlsx", ".pptx"}:
        kind = "Office document"
        try:
            with zipfile.ZipFile(path) as archive:
                names = set(archive.namelist())
                if "docProps/core.xml" in names:
                    core = archive.read("docProps/core.xml")[:200_000].lower()
                    if b"<dcterms:modified" in core:
                        findings.append("Document metadata includes a modified timestamp")
                        score += 5
                if not names:
                    findings.append("Office document archive is empty")
                    score += 20
        except Exception:
            findings.append("Office document could not be read as a valid ZIP-based document")
            score += 20
    else:
        kind = "generic file"
        findings.append("No specialized image/video/document detector for this file type")

    score = min(score, 100)
    if score >= 25:
        status = "POTENTIAL MANIPULATION - MANUAL REVIEW"
    elif score >= 10:
        status = "SUSPICIOUS INDICATORS - REVIEW"
    else:
        status = "NO OBVIOUS INDICATORS - NOT PROOF OF AUTHENTICITY"

    return {"kind": kind, "score": score, "status": status, "findings": findings}

def intake_evidence():
    """Upload evidence, run automatic screening, hash it, and log the result."""
    if not REGISTRY.exists():
        setup_demo()
    registry = read_registry()
    source_text = input("Full path of the evidence file to upload: ").strip().strip('"')
    source = Path(source_text).expanduser()
    if not source.is_file():
        print("File not found. Check the path and try again.")
        return

    case_id = input("Case ID (e.g. CASE-2026-019): ").strip()
    submitter = input("Submitted by (name or user ID): ").strip()
    if not case_id or not submitter:
        print("Case ID and submitter are required.")
        return

    # A file cannot be proven authentic from its own contents alone. If a trusted
    # original/reference is available, compare hashes to detect pre-upload changes.
    reference_text = input(
        "Path to trusted ORIGINAL/reference file for comparison (press Enter if unavailable): "
    ).strip().strip('"')
    reference_hash = ""
    reference_status = "NO_REFERENCE_PROVIDED"
    reference_mismatch = False
    if reference_text:
        reference = Path(reference_text).expanduser()
        if not reference.is_file():
            print("Reference file not found. Upload cancelled so you can correct the path.")
            return
        if reference.resolve() == source.resolve():
            print("The reference and upload paths point to the same file. Choose the unmodified original.")
            return
        reference_hash = sha256_file(reference)
        upload_hash_for_compare = sha256_file(source)
        if upload_hash_for_compare == reference_hash:
            reference_status = "MATCHES_TRUSTED_REFERENCE"
        else:
            reference_status = "HASH_MISMATCH_POSSIBLY_MODIFIED"
            reference_mismatch = True

    print("\nRunning automatic evidence screening...")
    screening = screen_evidence(source)
    if reference_mismatch:
        screening["score"] = 100
        screening["status"] = "REFERENCE HASH MISMATCH - FLAGGED FOR MANUAL REVIEW"
        screening["findings"].insert(0, "Uploaded file SHA-256 does not match the trusted reference file")
    elif reference_status == "MATCHES_TRUSTED_REFERENCE":
        screening["findings"].insert(0, "SHA-256 matches the supplied trusted reference file")
    print("File type:", screening["kind"])
    print("Risk indicator score:", f'{screening["score"]}/100')
    print("Screening result:", screening["status"])
    if reference_status != "NO_REFERENCE_PROVIDED":
        print("Reference comparison:", reference_status)
    else:
        print("Reference comparison: unavailable (no trusted original supplied)")
    for finding in screening["findings"]:
        print(" -", finding)
    print("Important: forensic heuristics can miss edits. A trusted reference hash detects byte-level differences from that reference; without one, the tool can only flag suspicious indicators, not prove authenticity.")

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

    # Hash before and after copying to detect changes during the upload operation.
    source_hash_before = sha256_file(source)
    shutil.copy2(source, destination)
    source_hash_after = sha256_file(source)
    stored_hash = sha256_file(destination)
    if source_hash_before != source_hash_after or stored_hash != source_hash_before:
        try:
            destination.unlink()
        except OSError:
            pass
        print("UPLOAD BLOCKED: file changed during copying. Please retry with a stable file.")
        return

    timestamp = datetime.now().replace(microsecond=0).strftime(FMT)
    registry[eid] = {"evidence_id": eid, "case_id": case_id, "filename": filename,
                     "original_sha256": stored_hash, "submitted_by": submitter, "submitted_at": timestamp,
                     "reference_sha256": reference_hash, "reference_status": reference_status,
                     "screening_score": screening["score"], "screening_status": screening["status"],
                     "screening_findings": "; ".join(screening["findings"])}
    save_registry(registry)

    events = []
    for row in read_log():
        events.append({"evidence_id": row["evidence_id"], "case_id": row["case_id"],
                       "action": row["action"], "user": row["user"], "role": row["role"],
                       "timestamp": row["timestamp"], "file_sha256": row["file_sha256"],
                       "is_anomaly": row.get("is_anomaly", 0), "anomaly_type": row.get("anomaly_type", "")})

    anomaly = int(screening["score"] >= 10 or reference_mismatch)
    event_kind = "reference_hash_mismatch" if reference_mismatch else (
        "potential_manipulation" if screening["score"] >= 25 else ("suspicious_indicators" if anomaly else ""))
    events.append({"evidence_id": eid, "case_id": case_id, "action": "SUBMITTED",
                   "user": submitter, "role": "user_submitted", "timestamp": timestamp,
                   "file_sha256": stored_hash, "is_anomaly": anomaly, "anomaly_type": event_kind})
    rebuild_log(events)

    print("\n===== UPLOAD RESULT =====")
    print(f"Accepted as {eid}: {filename}")
    print("Screening status:", screening["status"])
    print("Stored copy:", destination.resolve())
    print("SHA-256 recorded at intake:", stored_hash)
    if reference_mismatch:
        print("ALERT: uploaded file differs from the trusted reference. Quarantine/review before treating it as authentic.")
    elif anomaly:
        print("ALERT: evidence is flagged for manual review; it is not automatically declared fake.")
    elif reference_status == "MATCHES_TRUSTED_REFERENCE":
        print("The upload matches the supplied trusted reference byte-for-byte.")
    else:
        print("No strong screening indicators were found, but no trusted original was supplied. Authenticity is NOT guaranteed.")

def show_evidence():
    registry = read_registry()
    if not registry:
        print("No evidence registered. Run setup_demo() first.")
        return
    print("Evidence registry:")
    for eid, r in registry.items():
        print(f"{eid} | {r['case_id']} | {r['filename']} | by {r['submitted_by']}")
        if r.get("screening_status"):
            print(f"   Screening: {r['screening_status']} | score {r.get('screening_score', 'N/A')}/100 | reference: {r.get('reference_status', 'unknown')}")


def verify_evidence():
    registry = read_registry()
    if not registry:
        print("No evidence registered. Run setup_demo() first.")
        return
    print("== Evidence integrity ==")
    for eid, r in registry.items():
        path = FILES / r["filename"]
        if not path.is_file():
            print(f"{eid} | {r['filename']} | MISSING")
        elif sha256_file(path) == r["original_sha256"]:
            print(f"{eid} | {r['filename']} | OK (matches intake hash)")
        else:
            print(f"{eid} | {r['filename']} | CHANGED/TAMPERED SINCE INTAKE")


def detect_anomalies():
    registry = read_registry()
    rows = read_log()
    if not registry or not rows:
        print("No data. Run setup_demo() first.")
        return
    flags = []
    by_evidence = defaultdict(list)
    by_user = defaultdict(list)
    for row in rows:
        eid, user = row["evidence_id"], row["user"]
        ts = datetime.strptime(row["timestamp"], FMT)
        by_evidence[eid].append(ts)
        by_user[(eid, user)].append(ts)
        if ts.hour < 6 or ts.hour >= 22:
            flags.append((eid, row["timestamp"], "odd_hours", f"access by {user}"))
        if user in ("unknown", "unknown_acct"):
            flags.append((eid, row["timestamp"], "unknown_user", user))
        if str(row.get("is_anomaly", "0")).lower() in ("1", "true"):
            flags.append((eid, row["timestamp"], row.get("anomaly_type", "intake_screening"), "flagged during upload screening"))
        if eid in registry and row["file_sha256"] != registry[eid]["original_sha256"]:
            flags.append((eid, row["timestamp"], "hash_mismatch", row["action"]))
    for eid, times in by_evidence.items():
        times.sort()
        for a, b in zip(times, times[1:]):
            if b-a > timedelta(days=5):
                flags.append((eid, b.strftime(FMT), "time_gap", f"{(b-a).total_seconds()/86400:.1f} days"))
    for (eid, user), times in by_user.items():
        times.sort()
        for i in range(len(times)):
            j = i
            while j < len(times) and (times[j]-times[i]).total_seconds() <= 60:
                j += 1
            if j-i > 10:
                flags.append((eid, times[i].strftime(FMT), "burst_access", f"{j-i} actions in 60 seconds by {user}"))
                break
    if flags:
        for eid, ts, kind, note in sorted(flags):
            print(f"{eid} | {ts} | {kind} | {note}")
        print(f"{len(flags)} flags raised.")
    else:
        print("No rule-based anomaly flags detected.")
    print("These are rule-based demo alerts, not AI conclusions or proof of wrongdoing.")


def tamper_demo(filename="photo_scene.jpg"):
    """Optional demo: append bytes to a sample file to test hash verification."""
    path = FILES / filename
    if not path.is_file():
        print(f"No file found: {path}")
        return
    with path.open("ab") as f:
        f.write(b"\\nDEMO_TAMPER")
    print(f"Modified {filename}; run verify_evidence() again.")
