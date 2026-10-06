"""
Module 4 -- Digital Evidence Management + Case Management + Chain of Custody.

Implements a defensible workflow:
  * Case creation with unique case numbers
  * Evidence acquisition with immediate hashing (MD5/SHA-1/SHA-256)
  * Write-once storage layout (evidence/<case>/<id>_<name>)
  * Full chain-of-custody audit trail (who / what / when / integrity)
  * On-demand integrity re-verification against the acquisition hash
  * Tagging, searching, timeline building, IOC registry
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from config import Config
from core.database import (add_custody, add_ioc, add_timeline, execute, query,
                           query_one, scalar)
from core.utils import (ensure_dir, extract_iocs, file_type_guess, hash_file,
                        human_size, safe_name, utcnow)

EVIDENCE_TYPES = ["image", "document", "video", "audio", "log", "browser",
                  "memory", "disk", "network", "email", "mobile", "other"]

INCIDENT_TYPES = ["Phishing", "Malware/Ransomware", "Data Breach", "Financial Fraud",
                  "Account Takeover", "Insider Threat", "Website Defacement",
                  "Social Media Abuse", "Cyberbullying", "Identity Theft", "Other"]


# ---------------------------------------------------------------- cases
def next_case_number() -> str:
    year = utcnow()[:4]
    n = scalar("SELECT COUNT(*) FROM cases WHERE case_number LIKE ?", (f"CASE-{year}-%",))
    return f"CASE-{year}-{n + 1:04d}"


def create_case(title, description="", investigator=None, priority="medium",
                incident_type="Other") -> dict:
    cn = next_case_number()
    now = utcnow()
    cid = execute(
        """INSERT INTO cases(case_number,title,description,investigator,status,priority,
                             incident_type,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (cn, title.strip()[:200], description, investigator or Config.DEFAULT_INVESTIGATOR,
         "open", priority, incident_type, now, now))
    ensure_dir(Path(Config.EVIDENCE_DIR) / cn)
    add_timeline(cid, now, "case", f"Case {cn} opened: {title}", "info")
    return get_case(cid)


def get_case(case_id) -> dict | None:
    c = query_one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not c:
        return None
    c["evidence_count"] = scalar("SELECT COUNT(*) FROM evidence WHERE case_id=?", (case_id,))
    c["total_size"] = human_size(scalar("SELECT COALESCE(SUM(size),0) FROM evidence WHERE case_id=?", (case_id,)))
    c["scan_count"] = scalar("SELECT COUNT(*) FROM scans WHERE case_id=?", (case_id,))
    c["ioc_count"] = scalar("SELECT COUNT(*) FROM iocs WHERE case_id=?", (case_id,))
    c["custody_count"] = scalar(
        """SELECT COUNT(*) FROM custody WHERE evidence_id IN
           (SELECT id FROM evidence WHERE case_id=?)""", (case_id,))
    c["integrity_issues"] = scalar(
        "SELECT COUNT(*) FROM evidence WHERE case_id=? AND verified=0", (case_id,))
    return c


def list_cases(status=None, q=None) -> list[dict]:
    sql = """SELECT c.*,
                (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) AS evidence_count,
                (SELECT COALESCE(SUM(e.size),0) FROM evidence e WHERE e.case_id=c.id) AS total_bytes
             FROM cases c WHERE 1=1"""
    params = []
    if status and status != "all":
        sql += " AND c.status=?"; params.append(status)
    if q:
        sql += " AND (c.title LIKE ? OR c.case_number LIKE ? OR c.description LIKE ?)"
        params += [f"%{q}%"] * 3
    sql += " ORDER BY c.created_at DESC"
    rows = query(sql, tuple(params))
    for r in rows:
        r["total_size"] = human_size(r.get("total_bytes", 0))
    return rows


def update_case(case_id, **fields):
    allowed = {"title", "description", "status", "priority", "investigator", "incident_type"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed and v is not None:
            sets.append(f"{k}=?"); params.append(v)
    if not sets:
        return
    sets.append("updated_at=?"); params.append(utcnow())
    if fields.get("status") == "closed":
        sets.append("closed_at=?"); params.append(utcnow())
    params.append(case_id)
    execute(f"UPDATE cases SET {','.join(sets)} WHERE id=?", tuple(params))
    add_timeline(case_id, utcnow(), "case", f"Case updated: {', '.join(fields.keys())}", "info")


def delete_case(case_id):
    c = query_one("SELECT case_number FROM cases WHERE id=?", (case_id,))
    execute("DELETE FROM cases WHERE id=?", (case_id,))
    if c:
        folder = Path(Config.EVIDENCE_DIR) / c["case_number"]
        if folder.exists():
            shutil.rmtree(folder, ignore_errors=True)


# ---------------------------------------------------------------- evidence
def add_evidence(case_id, file_storage=None, name=None, evidence_type="other",
                 description="", source="", collected_by=None, tags="",
                 existing_path=None) -> dict:
    """Acquire evidence: copy into the vault, hash it, open the custody chain."""
    case = query_one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not case:
        raise ValueError("case not found")
    folder = ensure_dir(Path(Config.EVIDENCE_DIR) / case["case_number"])
    collected_by = collected_by or Config.DEFAULT_INVESTIGATOR

    if file_storage is not None:
        original = file_storage.filename or "evidence.bin"
        stored_name = f"{int(__import__('time').time())}_{safe_name(original)}"
        dest = folder / stored_name
        file_storage.save(str(dest))
    elif existing_path:
        original = os.path.basename(existing_path)
        stored_name = f"{int(__import__('time').time())}_{safe_name(original)}"
        dest = folder / stored_name
        shutil.copy2(existing_path, dest)
    else:
        raise ValueError("no file provided")

    h = hash_file(dest)
    with open(dest, "rb") as fh:
        head = fh.read(8192)
    meta = {"true_type": file_type_guess(head, original),
            "acquired_from": source or "manual upload"}

    now = utcnow()
    eid = execute(
        """INSERT INTO evidence(case_id,name,original_filename,stored_path,evidence_type,
             description,source,collected_by,collected_at,size,md5,sha1,sha256,verified,
             last_verified_at,tags,meta,created_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)""",
        (case_id, name or original, original, str(dest), evidence_type, description,
         source, collected_by, now, h["size"], h["md5"], h["sha1"], h["sha256"],
         now, tags, json.dumps(meta), now))

    add_custody(eid, "acquired", collected_by,
                f"Evidence acquired from '{source or 'upload'}'. "
                f"SHA-256 computed at acquisition: {h['sha256']}", "intact")
    add_timeline(case_id, now, "evidence",
                 f"Evidence #{eid} '{name or original}' acquired ({human_size(h['size'])})", "info")
    execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
    return get_evidence(eid)


def get_evidence(eid) -> dict | None:
    e = query_one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not e:
        return None
    e["size_human"] = human_size(e["size"])
    e["custody"] = query("SELECT * FROM custody WHERE evidence_id=? ORDER BY id DESC", (eid,))
    e["tag_list"] = [t.strip() for t in (e.get("tags") or "").split(",") if t.strip()]
    try:
        e["meta_obj"] = json.loads(e.get("meta") or "{}")
    except json.JSONDecodeError:
        e["meta_obj"] = {}
    e["exists_on_disk"] = os.path.exists(e["stored_path"] or "")
    case = query_one("SELECT case_number,title FROM cases WHERE id=?", (e["case_id"],))
    e["case_number"] = (case or {}).get("case_number")
    e["case_title"] = (case or {}).get("title")
    return e


def list_evidence(case_id=None, etype=None, q=None, tag=None) -> list[dict]:
    sql = """SELECT e.*, c.case_number FROM evidence e
             LEFT JOIN cases c ON c.id=e.case_id WHERE 1=1"""
    params = []
    if case_id:
        sql += " AND e.case_id=?"; params.append(case_id)
    if etype and etype != "all":
        sql += " AND e.evidence_type=?"; params.append(etype)
    if tag:
        sql += " AND e.tags LIKE ?"; params.append(f"%{tag}%")
    if q:
        sql += " AND (e.name LIKE ? OR e.description LIKE ? OR e.sha256 LIKE ? OR e.md5 LIKE ?)"
        params += [f"%{q}%"] * 4
    sql += " ORDER BY e.created_at DESC"
    rows = query(sql, tuple(params))
    for r in rows:
        r["size_human"] = human_size(r["size"])
        r["tag_list"] = [t.strip() for t in (r.get("tags") or "").split(",") if t.strip()]
    return rows


def verify_evidence(eid, actor=None) -> dict:
    """Recompute hashes and compare against the acquisition baseline."""
    e = query_one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not e:
        return {"error": "not found"}
    actor = actor or Config.DEFAULT_INVESTIGATOR
    path = e["stored_path"]
    if not path or not os.path.exists(path):
        execute("UPDATE evidence SET verified=0,last_verified_at=? WHERE id=?", (utcnow(), eid))
        add_custody(eid, "verified", actor, "FILE MISSING from evidence vault.", "mismatch")
        return {"ok": False, "status": "missing",
                "message": "Evidence file is missing from the vault."}
    h = hash_file(path)
    ok = (h["sha256"] == e["sha256"] and h["md5"] == e["md5"])
    execute("UPDATE evidence SET verified=?,last_verified_at=? WHERE id=?",
            (1 if ok else 0, utcnow(), eid))
    add_custody(eid, "verified", actor,
                ("Integrity verified - SHA-256 matches acquisition baseline."
                 if ok else
                 f"INTEGRITY FAILURE. Expected {e['sha256'][:16]}… got {h['sha256'][:16]}…"),
                "intact" if ok else "mismatch")
    if not ok:
        add_timeline(e["case_id"], utcnow(), "integrity",
                     f"Evidence #{eid} FAILED integrity verification", "critical")
    return {"ok": ok, "status": "intact" if ok else "mismatch",
            "expected": {"md5": e["md5"], "sha256": e["sha256"]},
            "actual": {"md5": h["md5"], "sha256": h["sha256"]},
            "message": ("Hash matches the acquisition baseline. Evidence is unaltered."
                        if ok else
                        "HASH MISMATCH - the file has been modified since acquisition. "
                        "This evidence may be inadmissible.")}


def verify_all(case_id, actor=None) -> dict:
    rows = query("SELECT id FROM evidence WHERE case_id=?", (case_id,))
    results = [{"id": r["id"], **verify_evidence(r["id"], actor)} for r in rows]
    intact = sum(1 for r in results if r.get("ok"))
    return {"total": len(results), "intact": intact,
            "failed": len(results) - intact, "results": results}


def record_access(eid, actor, action="accessed", notes=""):
    add_custody(eid, action, actor or Config.DEFAULT_INVESTIGATOR, notes, "intact")


def update_evidence(eid, **fields):
    allowed = {"name", "description", "evidence_type", "tags", "source"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed and v is not None:
            sets.append(f"{k}=?"); params.append(v)
    if not sets:
        return
    params.append(eid)
    execute(f"UPDATE evidence SET {','.join(sets)} WHERE id=?", tuple(params))
    add_custody(eid, "accessed", Config.DEFAULT_INVESTIGATOR,
                f"Metadata updated: {', '.join(fields.keys())}", "intact")


def delete_evidence(eid, actor=None, reason=""):
    e = query_one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not e:
        return
    add_timeline(e["case_id"], utcnow(), "evidence",
                 f"Evidence #{eid} '{e['name']}' DELETED. Reason: {reason or 'not stated'}", "warning")
    p = e["stored_path"]
    if p and os.path.exists(p):
        try:
            os.remove(p)
        except OSError:
            pass
    execute("DELETE FROM evidence WHERE id=?", (eid,))


def custody_chain(case_id) -> list[dict]:
    return query(
        """SELECT cu.*, e.name AS evidence_name, e.id AS eid
           FROM custody cu JOIN evidence e ON e.id=cu.evidence_id
           WHERE e.case_id=? ORDER BY cu.id DESC""", (case_id,))


def case_timeline(case_id) -> list[dict]:
    return query("SELECT * FROM timeline WHERE case_id=? ORDER BY ts DESC, id DESC LIMIT 400",
                 (case_id,))


def case_iocs(case_id) -> list[dict]:
    return query("SELECT * FROM iocs WHERE case_id=? ORDER BY ioc_type, value", (case_id,))


def harvest_iocs_from_evidence(eid) -> dict:
    """Scan a text-ish evidence item and register any IOCs found on the case."""
    e = query_one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not e or not os.path.exists(e["stored_path"] or ""):
        return {"error": "evidence unavailable"}
    with open(e["stored_path"], "rb") as fh:
        data = fh.read(4 * 1024 * 1024)
    text = data.decode("utf-8", "ignore")
    iocs = extract_iocs(text)
    n = 0
    for t in ("urls", "domains", "ips", "emails", "bitcoin", "upi_ids", "md5", "sha256"):
        for v in iocs.get(t, []):
            add_ioc(e["case_id"], t.rstrip("s"), v, f"evidence#{eid}", 60)
            n += 1
    add_custody(eid, "analyzed", Config.DEFAULT_INVESTIGATOR,
                f"IOC extraction run: {n} indicator(s) registered to the case.", "intact")
    return {"registered": n, "iocs": iocs}


def stats() -> dict:
    return {
        "cases_total": scalar("SELECT COUNT(*) FROM cases"),
        "cases_open": scalar("SELECT COUNT(*) FROM cases WHERE status='open'"),
        "cases_progress": scalar("SELECT COUNT(*) FROM cases WHERE status='in_progress'"),
        "cases_closed": scalar("SELECT COUNT(*) FROM cases WHERE status='closed'"),
        "evidence_total": scalar("SELECT COUNT(*) FROM evidence"),
        "evidence_bytes": scalar("SELECT COALESCE(SUM(size),0) FROM evidence"),
        "custody_events": scalar("SELECT COUNT(*) FROM custody"),
        "integrity_failures": scalar("SELECT COUNT(*) FROM evidence WHERE verified=0"),
        "iocs": scalar("SELECT COUNT(*) FROM iocs"),
    }
