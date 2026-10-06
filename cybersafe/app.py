#!/usr/bin/env python3
"""
AI Cyber Safety & Digital Forensics Platform
"Protect. Detect. Investigate."

100% local. 100% free. No API keys anywhere. AI powered by local Ollama.

Run:  python app.py    ->  http://127.0.0.1:5000
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from pathlib import Path

from flask import (Flask, Response, jsonify, redirect, render_template, request,
                   send_file, session, url_for, abort, stream_with_context)
from werkzeug.utils import secure_filename

from config import Config
from core import ollama_client
from core.database import (add_ioc, execute, get_setting, init_db, log_scan, query,
                           query_one, scalar, set_setting)
from core.utils import human_size, safe_name, utcnow
from modules import (assistant, breach, browser_forensics, evidence as ev, learning,
                     log_analysis, malware, memory_forensics, password, phishing,
                     reports, toolkit)

app = Flask(__name__)
app.config.from_object(Config)

with app.app_context():
    init_db()


# ------------------------------------------------------------------ helpers
def _tmp_save(fs) -> tuple[str, str]:
    """Save an upload to a temp file. Returns (path, original_name)."""
    name = secure_filename(fs.filename or "upload.bin") or "upload.bin"
    fd, path = tempfile.mkstemp(prefix="cs_", suffix="_" + name[:60])
    os.close(fd)
    fs.save(path)
    return path, (fs.filename or name)


def _cleanup(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _ai_on() -> bool:
    """
    True only when the user actually ticked the AI checkbox.

    Forms submit a hidden use_ai=0 plus (when ticked) a checkbox use_ai=1, so we
    look for an explicit "1" anywhere in the submitted values. If the field is
    absent entirely (e.g. API callers), default to enabled.
    """
    vals = request.form.getlist("use_ai")
    if not vals:
        return True
    return "1" in vals or "true" in [v.lower() for v in vals] or "on" in vals


def _case_id():
    v = request.form.get("case_id") or request.args.get("case_id")
    try:
        return int(v) if v else None
    except (TypeError, ValueError):
        return None


def _sid() -> str:
    if "sid" not in session:
        session["sid"] = str(uuid.uuid4())[:12]
    return session["sid"]


@app.context_processor
def inject_globals():
    st = ollama_client.status()
    return {
        "APP_NAME": Config.APP_NAME,
        "APP_TAGLINE": Config.APP_TAGLINE,
        "APP_VERSION": Config.APP_VERSION,
        "ollama_online": st["online"],
        "ollama_model": st.get("model"),
        "ollama_models": st.get("models", []),
        "ollama_host": Config.OLLAMA_HOST,
        "open_cases": query("SELECT id,case_number,title FROM cases WHERE status!='closed' "
                            "ORDER BY created_at DESC LIMIT 30"),
        "now": utcnow(),
    }


@app.template_filter("hsize")
def _hsize(v):
    return human_size(v)


@app.template_filter("band")
def _band(score):
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "low"
    return "critical" if s >= 80 else "high" if s >= 55 else "medium" if s >= 25 else "low"


@app.template_filter("fromjson")
def _fromjson(v):
    try:
        return json.loads(v or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}


# ================================================================== dashboard
@app.route("/")
def dashboard():
    s = ev.stats()
    recent_scans = query("SELECT * FROM scans ORDER BY id DESC LIMIT 12")
    threats = query("SELECT * FROM scans WHERE risk_score>=55 ORDER BY id DESC LIMIT 8")
    by_module = query("""SELECT module, COUNT(*) AS n, COALESCE(AVG(risk_score),0) AS avg_risk,
                                MAX(risk_score) AS max_risk
                         FROM scans GROUP BY module ORDER BY n DESC""")
    recent_cases = ev.list_cases()[:6]
    prog = learning.progress()
    trend = query("""SELECT substr(created_at,1,10) AS day, COUNT(*) AS n,
                            COALESCE(AVG(risk_score),0) AS avg_risk
                     FROM scans GROUP BY day ORDER BY day DESC LIMIT 14""")
    trend = list(reversed(trend))
    risk_dist = {
        "critical": scalar("SELECT COUNT(*) FROM scans WHERE risk_score>=80"),
        "high": scalar("SELECT COUNT(*) FROM scans WHERE risk_score>=55 AND risk_score<80"),
        "medium": scalar("SELECT COUNT(*) FROM scans WHERE risk_score>=25 AND risk_score<55"),
        "low": scalar("SELECT COUNT(*) FROM scans WHERE risk_score<25"),
    }
    total_scans = sum(risk_dist.values())
    overall = 0
    if total_scans:
        overall = round((risk_dist["critical"] * 100 + risk_dist["high"] * 70 +
                         risk_dist["medium"] * 40 + risk_dist["low"] * 10) / total_scans)
    recs = build_recommendations(s, risk_dist, prog)
    return render_template("dashboard.html", stats=s, recent_scans=recent_scans,
                           threats=threats, by_module=by_module, recent_cases=recent_cases,
                           progress=prog, trend=trend, risk_dist=risk_dist,
                           total_scans=total_scans, overall_risk=overall,
                           recommendations=recs,
                           evidence_size=human_size(s["evidence_bytes"]),
                           reports_count=scalar("SELECT COUNT(*) FROM reports"))


def build_recommendations(s, risk_dist, prog):
    r = []
    if not ollama_client.is_online():
        r.append({"icon": "🤖", "severity": "medium", "title": "Local AI model is offline",
                  "text": "Start Ollama to unlock AI analysis across every module: run "
                          "`ollama serve` then `ollama pull llama3.2`. All rule engines keep "
                          "working without it."})
    if s["integrity_failures"]:
        r.append({"icon": "⚠️", "severity": "critical",
                  "title": f"{s['integrity_failures']} evidence item(s) failed integrity checks",
                  "text": "Investigate immediately - these items may be inadmissible. "
                          "Check the chain of custody for when the mismatch appeared."})
    if risk_dist["critical"]:
        r.append({"icon": "🚨", "severity": "critical",
                  "title": f"{risk_dist['critical']} critical-risk detection(s) recorded",
                  "text": "Review these in the scan history and make sure each one was actioned."})
    if s["cases_open"] > 3:
        r.append({"icon": "📁", "severity": "medium",
                  "title": f"{s['cases_open']} cases are still open",
                  "text": "Close or progress stale cases to keep the workload manageable."})
    if prog["overall_percent"] < 40:
        r.append({"icon": "📚", "severity": "low", "title": "Training progress is low",
                  "text": "Complete the Cyber Safety Essentials path in the Learning Center - "
                          "awareness prevents most incidents."})
    if s["evidence_total"] == 0:
        r.append({"icon": "🗂️", "severity": "low", "title": "No evidence stored yet",
                  "text": "Create a case and upload artefacts to try the chain-of-custody workflow."})
    if not scalar("SELECT COUNT(*) FROM breach_watchlist"):
        r.append({"icon": "💧", "severity": "medium", "title": "Check your email breach exposure",
                  "text": "The Breach Checker cross-references your address against 99 documented "
                          "breaches and tells you exactly what data is already circulating."})
    else:
        stale = scalar("SELECT COUNT(*) FROM breach_watchlist WHERE last_score>=55")
        if stale:
            r.append({"icon": "💧", "severity": "high",
                      "title": f"{stale} monitored address(es) have high breach exposure",
                      "text": "Open the Breach Checker watchlist and work through the recovery "
                              "plan for each one."})
    r.append({"icon": "🔐", "severity": "low", "title": "Run your monthly security checkup",
              "text": "Daily Toolkit → Security Checkup scores your personal hygiene in 2 minutes."})
    return r[:6]


# ================================================================== phishing
VALID_KINDS = ("url", "email", "sms")


def _phishing_input() -> tuple[str, str, str | None]:
    """
    Read the submitted artefact from the correct tab.

    Each tab has its OWN field name (content_url / content_email / content_sms).
    They used to share name="content", which meant the browser submitted all
    three (hidden panes are only display:none, so they still post) and Flask's
    .get() returned the first, always-empty one. That silently blanked the page.
    """
    kind = (request.form.get("kind") or "url").strip().lower()
    if kind not in VALID_KINDS:
        kind = "url"

    content = (request.form.get(f"content_{kind}") or "").strip()

    # If the active tab is empty but another one has text, use that instead
    # and switch the view to match, rather than silently doing nothing.
    if not content:
        for k in VALID_KINDS:
            v = (request.form.get(f"content_{k}") or "").strip()
            if v:
                return v, k, None

    # Backwards compatibility with the old shared field name.
    if not content:
        vals = [v.strip() for v in request.form.getlist("content") if v.strip()]
        if vals:
            return vals[0], kind, None

    if not content:
        return "", kind, ("Nothing to analyse — please paste a URL, email or SMS "
                          "into the box before pressing Analyse.")
    return content, kind, None


@app.route("/phishing", methods=["GET", "POST"])
def phishing_page():
    result = None
    error = None
    kind = "url"
    if request.method == "POST":
        content, kind, error = _phishing_input()
        if content:
            t0 = time.time()
            result = phishing.analyze(content, kind, use_ai=_ai_on())
            cid = _case_id()
            sid = log_scan("phishing", content[:300], result["verdict"], result["risk_score"],
                           result["explanation"][:900], result, cid,
                           result.get("ai", {}).get("available"),
                           int((time.time() - t0) * 1000))
            result["scan_id"] = sid
            if cid:
                for t in ("urls", "domains", "ips", "emails", "bitcoin", "upi_ids"):
                    for v in (result.get("iocs", {}) or {}).get(t, [])[:20]:
                        add_ioc(cid, t.rstrip("s"), v, "phishing", result["risk_score"])
                if kind == "url":
                    add_ioc(cid, "url", content[:300], "phishing", result["risk_score"])
    samples = {
        "url": "http://amazon.in.delivery-update.secure-login.xyz/track?id=99213",
        "email": ("From: \"HDFC Bank Security\" <alerts@hdfcbank.com>\n"
                  "Reply-To: recovery.desk909@gmail.com\n"
                  "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
                  "Subject: URGENT: Your account will be suspended in 24 hours\n\n"
                  "Dear Customer,\n\nWe detected an unauthorized transaction on your account. "
                  "Your account will be SUSPENDED within 24 hours unless you verify your "
                  "identity immediately.\n\nVerify now: http://hdfc-secure-verify.tk/login\n\n"
                  "You will need your account number, debit card number, CVV and OTP.\n\n"
                  "Failure to comply will result in permanent account closure and legal action.\n\n"
                  "HDFC Bank Security Team"),
        "sms": ("URGENT: Your SBI account is BLOCKED due to incomplete KYC. "
                "Update immediately to avoid freezing: http://bit.ly/sbi-kyc-verify "
                "Share OTP with our executive to complete. -SBI"),
    }
    return render_template("phishing.html", result=result, samples=samples,
                           error=error, kind=kind)


# ================================================================== password
@app.route("/password", methods=["GET", "POST"])
def password_page():
    result = compare = None
    if request.method == "POST":
        action = request.form.get("action", "analyze")
        if action == "analyze":
            pw = request.form.get("password", "")
            ctx = request.form.get("context", "")
            if pw:
                result = password.analyze(pw, use_ai=_ai_on(), context=ctx)
                log_scan("password", result["masked"], result["rating"],
                         100 - result["score"],
                         f"{result['rating']} ({result['score']}/100, "
                         f"{result['entropy_bits']} bits, cracks in "
                         f"{result['headline_crack_time']})",
                         {k: v for k, v in result.items() if k != "masked"},
                         _case_id(), result.get("ai_advice", {}).get("available"))
        elif action == "compare":
            pws = [request.form.get(f"pw{i}", "") for i in range(1, 6)]
            compare = password.compare_passwords([p for p in pws if p])
    return render_template("password.html", result=result, compare=compare)


@app.post("/api/password/generate")
def api_pw_generate():
    d = request.get_json(silent=True) or {}
    mode = d.get("mode", "random")
    if mode == "passphrase":
        pw = password.generate_passphrase(int(d.get("words", 5)),
                                          d.get("separator", "-"),
                                          bool(d.get("capitalize", True)),
                                          bool(d.get("add_number", True)))
    else:
        pw = password.generate_password(int(d.get("length", 20)),
                                        bool(d.get("symbols", True)),
                                        bool(d.get("digits", True)),
                                        bool(d.get("exclude_ambiguous", True)))
    a = password.analyze(pw, use_ai=False)
    return jsonify({"password": pw, "score": a["score"], "rating": a["rating"],
                    "bits": a["entropy_bits"], "crack": a["headline_crack_time"]})


@app.post("/api/password/check")
def api_pw_check():
    d = request.get_json(silent=True) or {}
    a = password.analyze(d.get("password", ""), use_ai=False)
    if "error" in a:
        return jsonify(a)
    return jsonify({"score": a["score"], "rating": a["rating"], "color": a["color"],
                    "bits": a["entropy_bits"], "crack": a["headline_crack_time"],
                    "top_issues": [f["title"] for f in a["findings"] if f["points"] > 0][:4],
                    "breached": a["breach"]["found"]})


# ================================================================== malware
@app.route("/malware", methods=["GET", "POST"])
def malware_page():
    result = hash_result = None
    if request.method == "POST":
        action = request.form.get("action", "file")
        if action == "hash":
            hash_result = malware.analyze_hash_only(request.form.get("hash", ""))
        else:
            f = request.files.get("file")
            if f and f.filename:
                path, orig = _tmp_save(f)
                try:
                    t0 = time.time()
                    result = malware.analyze_file(path, orig, use_ai=_ai_on())
                    cid = _case_id()
                    log_scan("malware", orig, result["verdict"], result["risk_score"],
                             f"{result['true_type']} | {result['size_human']} | "
                             f"entropy {result['entropy']} | "
                             f"{len(result['findings'])} findings",
                             {k: v for k, v in result.items()
                              if k not in ("interesting_strings",)},
                             cid, result.get("ai", {}).get("available"),
                             int((time.time() - t0) * 1000))
                    if cid:
                        for a in ("md5", "sha256"):
                            add_ioc(cid, a, result["hashes"][a], "malware", result["risk_score"])
                        for u in result.get("iocs", {}).get("urls", [])[:15]:
                            add_ioc(cid, "url", u, "malware", 60)
                finally:
                    _cleanup(path)
    return render_template("malware.html", result=result, hash_result=hash_result)


# ================================================================== evidence & cases
@app.route("/cases")
def cases_page():
    status = request.args.get("status", "all")
    q = request.args.get("q", "")
    return render_template("cases.html", cases=ev.list_cases(status, q),
                           status=status, q=q, stats=ev.stats(),
                           incident_types=ev.INCIDENT_TYPES)


@app.post("/cases/new")
def case_new():
    c = ev.create_case(request.form.get("title", "Untitled case"),
                       request.form.get("description", ""),
                       request.form.get("investigator") or Config.DEFAULT_INVESTIGATOR,
                       request.form.get("priority", "medium"),
                       request.form.get("incident_type", "Other"))
    return redirect(url_for("case_detail", case_id=c["id"]))


@app.route("/cases/<int:case_id>")
def case_detail(case_id):
    case = ev.get_case(case_id)
    if not case:
        abort(404)
    return render_template("case_detail.html", case=case,
                           evidence=ev.list_evidence(case_id),
                           custody=ev.custody_chain(case_id),
                           timeline=ev.case_timeline(case_id),
                           iocs=ev.case_iocs(case_id),
                           scans=query("SELECT * FROM scans WHERE case_id=? ORDER BY id DESC",
                                       (case_id,)),
                           evidence_types=ev.EVIDENCE_TYPES,
                           incident_types=ev.INCIDENT_TYPES)


@app.post("/cases/<int:case_id>/update")
def case_update(case_id):
    ev.update_case(case_id, **{k: request.form.get(k) for k in
                               ("title", "description", "status", "priority",
                                "investigator", "incident_type")})
    return redirect(url_for("case_detail", case_id=case_id))


@app.post("/cases/<int:case_id>/delete")
def case_delete(case_id):
    ev.delete_case(case_id)
    return redirect(url_for("cases_page"))


@app.post("/cases/<int:case_id>/evidence")
def evidence_add(case_id):
    f = request.files.get("file")
    if f and f.filename:
        ev.add_evidence(case_id, file_storage=f,
                        name=request.form.get("name") or None,
                        evidence_type=request.form.get("evidence_type", "other"),
                        description=request.form.get("description", ""),
                        source=request.form.get("source", ""),
                        collected_by=request.form.get("collected_by") or None,
                        tags=request.form.get("tags", ""))
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/evidence")
def evidence_page():
    return render_template("evidence.html",
                           evidence=ev.list_evidence(etype=request.args.get("type", "all"),
                                                     q=request.args.get("q", ""),
                                                     tag=request.args.get("tag")),
                           etype=request.args.get("type", "all"),
                           q=request.args.get("q", ""),
                           evidence_types=ev.EVIDENCE_TYPES, stats=ev.stats())


@app.route("/evidence/<int:eid>")
def evidence_detail(eid):
    e = ev.get_evidence(eid)
    if not e:
        abort(404)
    ev.record_access(eid, Config.DEFAULT_INVESTIGATOR, "accessed", "Viewed in evidence browser")
    return render_template("evidence_detail.html", e=e, evidence_types=ev.EVIDENCE_TYPES)


@app.post("/evidence/<int:eid>/verify")
def evidence_verify(eid):
    return jsonify(ev.verify_evidence(eid, Config.DEFAULT_INVESTIGATOR))


@app.post("/evidence/<int:eid>/update")
def evidence_update(eid):
    ev.update_evidence(eid, **{k: request.form.get(k) for k in
                               ("name", "description", "evidence_type", "tags", "source")})
    return redirect(url_for("evidence_detail", eid=eid))


@app.post("/evidence/<int:eid>/harvest")
def evidence_harvest(eid):
    return jsonify(ev.harvest_iocs_from_evidence(eid))


@app.post("/evidence/<int:eid>/delete")
def evidence_delete(eid):
    e = ev.get_evidence(eid)
    cid = e["case_id"] if e else None
    ev.delete_evidence(eid, Config.DEFAULT_INVESTIGATOR, request.form.get("reason", ""))
    return redirect(url_for("case_detail", case_id=cid) if cid else url_for("evidence_page"))


@app.get("/evidence/<int:eid>/download")
def evidence_download(eid):
    e = ev.get_evidence(eid)
    if not e or not e["exists_on_disk"]:
        abort(404)
    ev.record_access(eid, Config.DEFAULT_INVESTIGATOR, "exported", "Downloaded original artefact")
    return send_file(e["stored_path"], as_attachment=True,
                     download_name=e["original_filename"] or e["name"])


@app.post("/cases/<int:case_id>/verify-all")
def case_verify_all(case_id):
    return jsonify(ev.verify_all(case_id, Config.DEFAULT_INVESTIGATOR))


# ================================================================== browser forensics
@app.route("/browser", methods=["GET", "POST"])
def browser_page():
    result = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            path, orig = _tmp_save(f)
            try:
                t0 = time.time()
                result = browser_forensics.analyze_file(path, use_ai=_ai_on())
                if "error" not in result:
                    log_scan("browser", orig,
                             f"{result['risk_score']}/100",
                             result["risk_score"],
                             f"{result['browser']}: {result['counts']['history']} history, "
                             f"{result['counts']['downloads']} downloads, "
                             f"{len(result['flagged_urls'])} flagged URLs",
                             {k: v for k, v in result.items()
                              if k not in ("recent_history", "searches")},
                             _case_id(), result.get("ai", {}).get("available"),
                             int((time.time() - t0) * 1000))
            finally:
                _cleanup(path)
    return render_template("browser.html", result=result)


# ================================================================== memory forensics
@app.route("/memory", methods=["GET", "POST"])
def memory_page():
    result = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            path, orig = _tmp_save(f)
            try:
                t0 = time.time()
                result = memory_forensics.analyze_dump(path, use_ai=_ai_on())
                log_scan("memory", orig, result["band"], result["risk_score"],
                         f"{result['file_size_human']} dump: "
                         f"{len(result['suspicious_processes'])} suspicious processes, "
                         f"{len(result['connections'])} network artefacts, "
                         f"{len(result['signatures'])} signature hits",
                         {k: v for k, v in result.items()
                          if k not in ("processes", "command_lines", "powershell_commands")},
                         _case_id(), result.get("ai", {}).get("available"),
                         int((time.time() - t0) * 1000))
            finally:
                _cleanup(path)
    return render_template("memory.html", result=result)


# ================================================================== logs
@app.route("/logs", methods=["GET", "POST"])
def logs_page():
    result = event_info = None
    if request.method == "POST":
        action = request.form.get("action", "file")
        if action == "event":
            event_info = log_analysis.explain_event_id(request.form.get("event_id", ""),
                                                       use_ai=_ai_on())
        else:
            f = request.files.get("file")
            text = (request.form.get("logtext") or "").strip()
            path = None
            orig = "pasted.log"
            if f and f.filename:
                path, orig = _tmp_save(f)
            elif text:
                fd, path = tempfile.mkstemp(suffix=".log")
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(text)
            if path:
                try:
                    t0 = time.time()
                    result = log_analysis.analyze_log(path, orig, use_ai=_ai_on())
                    cid = _case_id()
                    log_scan("logs", orig, result["band"], result["risk_score"],
                             f"{result['log_type_label']}: {result['total_lines']} lines, "
                             f"{len(result['findings'])} detections",
                             {k: v for k, v in result.items() if k != "sample_lines"},
                             cid, result.get("ai", {}).get("available"),
                             int((time.time() - t0) * 1000))
                    if cid:
                        from core.database import add_timeline
                        for t in result["timeline"][:80]:
                            add_timeline(cid, t.get("ts") or utcnow(),
                                         f"log:{t.get('source')}", t.get("event"),
                                         t.get("severity", "info"))
                        for ip in result.get("stats", {}).get("external_ips", [])[:20]:
                            add_ioc(cid, "ip", ip["ip"], "logs", 60)
                finally:
                    _cleanup(path)
    return render_template("logs.html", result=result, event_info=event_info,
                           common_events=sorted(log_analysis.WINDOWS_EVENTS.items(),
                                                key=lambda kv: kv[0])[:40])


# ================================================================== assistant
@app.route("/assistant")
def assistant_page():
    sid = _sid()
    return render_template("assistant.html", history=assistant.get_history(sid),
                           quick=assistant.QUICK_PROMPTS, sid=sid,
                           sessions=assistant.list_sessions(),
                           kb=[{"id": d["id"], "title": d["title"]} for d in assistant.KB])


@app.post("/api/assistant/ask")
def api_assistant_ask():
    d = request.get_json(silent=True) or {}
    q = (d.get("question") or "").strip()
    if not q:
        return jsonify({"error": "empty question"}), 400
    sid = d.get("session_id") or _sid()
    hist = [{"role": m["role"], "content": m["content"]}
            for m in assistant.get_history(sid)][-10:]
    res = assistant.ask(q, sid, hist)
    log_scan("assistant", q[:200], res["source"], 0, res["answer"][:400], {},
             None, res["ai_online"])
    return jsonify(res)


@app.post("/api/assistant/stream")
def api_assistant_stream():
    d = request.get_json(silent=True) or {}
    q = (d.get("question") or "").strip()
    sid = d.get("session_id") or _sid()
    if not q:
        return jsonify({"error": "empty"}), 400
    docs = assistant.retrieve(q, 3)
    prompt = assistant.build_prompt(q, docs)
    hist = [{"role": m["role"], "content": m["content"]}
            for m in assistant.get_history(sid)][-8:]
    hist.append({"role": "user", "content": prompt})

    def gen():
        buf = []
        if not ollama_client.is_online():
            txt = assistant.fallback_answer(q, docs)
            execute("INSERT INTO chat(session_id,role,content,created_at) VALUES(?,?,?,?)",
                    (sid, "user", q, utcnow()))
            execute("INSERT INTO chat(session_id,role,content,created_at) VALUES(?,?,?,?)",
                    (sid, "assistant", txt, utcnow()))
            yield f"data: {json.dumps({'chunk': txt})}\n\n"
            yield f"data: {json.dumps({'done': True, 'source': 'knowledge_base'})}\n\n"
            return
        for chunk in ollama_client.stream_chat(hist, system=assistant.SYSTEM):
            buf.append(chunk)
            yield f"data: {json.dumps({'chunk': chunk})}\n\n"
        full = "".join(buf)
        execute("INSERT INTO chat(session_id,role,content,created_at) VALUES(?,?,?,?)",
                (sid, "user", q, utcnow()))
        execute("INSERT INTO chat(session_id,role,content,created_at) VALUES(?,?,?,?)",
                (sid, "assistant", full[:8000], utcnow()))
        yield f"data: {json.dumps({'done': True, 'source': 'ollama', 'sources': [{'id': x['id'], 'title': x['title']} for x in docs]})}\n\n"

    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/assistant/clear")
def api_assistant_clear():
    assistant.clear_session(_sid())
    session["sid"] = str(uuid.uuid4())[:12]
    return jsonify({"ok": True, "session_id": session["sid"]})


# ================================================================== learning
@app.route("/learn")
def learn_page():
    return render_template("learn.html", labs=learning.LABS,
                           topics=learning.TOPIC_LABELS,
                           paths=learning.LEARNING_PATHS,
                           progress=learning.progress(),
                           sims=len(learning.SIM_EMAILS))


@app.route("/learn/quiz/<topic>", methods=["GET", "POST"])
def quiz_page(topic):
    if request.method == "POST":
        picks = json.loads(request.form.get("picks", "[]"))
        answers = []
        for i in range(len(picks)):
            v = request.form.get(f"a{i}")
            answers.append(int(v) if v is not None and v.isdigit() else -1)
        result = learning.grade_quiz(topic, picks, answers)
        return render_template("quiz.html", topic=topic, result=result,
                               label=learning.TOPIC_LABELS.get(topic, topic))
    questions, picks = learning.get_quiz(topic, 6)
    return render_template("quiz.html", topic=topic, questions=questions,
                           picks=json.dumps(picks),
                           label=learning.TOPIC_LABELS.get(topic, topic), result=None)


@app.route("/learn/lab/<lab_id>")
def lab_page(lab_id):
    lab = learning.get_lab(lab_id)
    if not lab:
        abort(404)
    return render_template("lab.html", lab=lab,
                           done=lab_id in learning.progress()["labs_completed"])


@app.post("/learn/lab/<lab_id>/complete")
def lab_complete(lab_id):
    learning.mark_lab("student", lab_id)
    return redirect(url_for("lab_page", lab_id=lab_id))


@app.route("/learn/simulator", methods=["GET", "POST"])
def simulator_page():
    result = None
    if request.method == "POST":
        answers = {e["id"]: request.form.get(e["id"]) for e in learning.SIM_EMAILS
                   if request.form.get(e["id"])}
        result = learning.grade_sim(answers)
    return render_template("simulator.html", emails=learning.SIM_EMAILS, result=result)


@app.post("/api/learn/generate-quiz")
def api_gen_quiz():
    d = request.get_json(silent=True) or {}
    return jsonify(learning.ai_generate_quiz(d.get("topic", "phishing"),
                                             int(d.get("n", 5)),
                                             d.get("difficulty", "beginner")))


@app.post("/api/learn/explain")
def api_explain():
    d = request.get_json(silent=True) or {}
    return jsonify(learning.ai_explain(d.get("topic", ""), d.get("level", "beginner")))


# ================================================================== toolkit
@app.route("/toolkit")
def toolkit_page():
    return render_template("toolkit.html", ops=toolkit.ENCODE_OPS,
                           checkup=toolkit.CHECKUP_ITEMS)


@app.post("/api/tool/pii")
def api_pii():
    d = request.get_json(silent=True) or {}
    r = toolkit.scan_pii(d.get("text", ""))
    log_scan("toolkit-pii", f"{len(d.get('text',''))} chars",
             "safe" if r["safe"] else "pii found", r["risk_score"],
             f"{r['count']} PII item(s) detected", {"counts": r["counts"]})
    return jsonify(r)


@app.post("/api/tool/encode")
def api_encode():
    d = request.get_json(silent=True) or {}
    return jsonify(toolkit.encode_decode(d.get("text", ""), d.get("operation", "base64_encode")))


@app.post("/api/tool/hash-text")
def api_hash_text():
    d = request.get_json(silent=True) or {}
    return jsonify(toolkit.hash_text(d.get("text", "")))


@app.post("/api/tool/qr")
def api_qr():
    d = request.get_json(silent=True) or {}
    return jsonify(toolkit.check_qr_payload(d.get("payload", "")))


@app.post("/api/tool/scam")
def api_scam():
    d = request.get_json(silent=True) or {}
    r = toolkit.detect_scam(d.get("text", ""), use_ai=d.get("use_ai", True))
    log_scan("toolkit-scam", (d.get("text") or "")[:150], r["band"], r["risk_score"],
             f"{len(r['findings'])} scam indicators", r, None,
             r.get("ai", {}).get("available"))
    return jsonify(r)


@app.post("/api/tool/checkup")
def api_checkup():
    d = request.get_json(silent=True) or {}
    r = toolkit.score_checkup(d.get("answers", {}))
    log_scan("toolkit-checkup", "security checkup", r["grade"], 100 - r["percent"],
             f"Score {r['percent']}% (grade {r['grade']})", r)
    return jsonify(r)


@app.post("/tool/exif")
def tool_exif():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "no file"}), 400
    path, orig = _tmp_save(f)
    try:
        r = toolkit.read_exif(path)
        r["filename"] = orig
        if request.form.get("strip") == "1" and r.get("has_exif"):
            out = Path(Config.UPLOAD_DIR) / f"clean_{safe_name(orig)}"
            r["strip_result"] = toolkit.strip_exif(path, str(out))
            r["clean_file"] = out.name
        return jsonify(r)
    finally:
        _cleanup(path)


@app.get("/tool/exif/download/<name>")
def tool_exif_download(name):
    p = Path(Config.UPLOAD_DIR) / secure_filename(name)
    if not p.exists():
        abort(404)
    return send_file(str(p), as_attachment=True, download_name=p.name)


@app.post("/tool/compare")
def tool_compare():
    a, b = request.files.get("file_a"), request.files.get("file_b")
    if not (a and b and a.filename and b.filename):
        return jsonify({"error": "two files required"}), 400
    pa, _ = _tmp_save(a)
    pb, _ = _tmp_save(b)
    try:
        r = toolkit.compare_files(pa, pb)
        r["name_a"], r["name_b"] = a.filename, b.filename
        return jsonify(r)
    finally:
        _cleanup(pa); _cleanup(pb)


# ================================================================== breach check
@app.route("/breach", methods=["GET", "POST"])
def breach_page():
    result = None
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        services = request.form.getlist("services")
        online = "1" in request.form.getlist("online")
        if email:
            t0 = time.time()
            result = breach.check_email(email, services, use_ai=_ai_on(), online=online)
            if "error" not in result:
                cid = _case_id()
                log_scan("breach", breach._mask_email(result["email"]),
                         result["verdict"], result["risk_score"],
                         f"{len(result['matched_breaches'])} breach(es) linked, "
                         f"{len(result['exposed_data_types'])} data type(s) exposed",
                         {k: v for k, v in result.items() if k != "email"},
                         cid, result.get("ai", {}).get("available"),
                         int((time.time() - t0) * 1000))
                if cid:
                    add_ioc(cid, "email", result["email"], "breach", 70)
    return render_template("breach.html", result=result,
                           stats=breach.catalog_stats(),
                           services=breach.COMMON_SERVICES,
                           watch=breach.watchlist(),
                           corpus=breach.corpus_stats(),
                           top_breaches=breach.search_breaches("", 12),
                           sync=breach.hibp_sync_status(),
                           has_key=bool(breach.hibp_api_key()),
                           online_on=breach.online_enabled())


@app.post("/api/breach/sync")
def api_breach_sync():
    return jsonify(breach.sync_hibp_catalogue(force=True))


@app.post("/api/breach/settings")
def api_breach_settings():
    d = request.get_json(silent=True) or {}
    if "hibp_api_key" in d:
        breach.set_hibp_api_key(d["hibp_api_key"])
    if "online" in d:
        breach.set_online_enabled(bool(d["online"]))
    return jsonify({"ok": True, "has_key": bool(breach.hibp_api_key()),
                    "online": breach.online_enabled()})


@app.post("/api/breach/test-key")
def api_breach_test_key():
    d = request.get_json(silent=True) or {}
    key = (d.get("hibp_api_key") or breach.hibp_api_key()).strip()
    if not key:
        return jsonify({"ok": False, "error": "No API key supplied."})
    from modules import breach_providers as bpv
    r = bpv.hibp_official("test@example.com", key, timeout=20)
    if r.get("ok"):
        return jsonify({"ok": True,
                        "message": f"Key works. HIBP answered with "
                                   f"{len(r['breaches'])} breach(es) for the test address."})
    return jsonify({"ok": False, "error": r.get("error") or "unknown error"})


@app.get("/breach/catalog")
def breach_catalog_page():
    q = request.args.get("q", "")
    return render_template("breach_catalog.html",
                           breaches=breach.search_breaches(q, 200),
                           q=q, stats=breach.catalog_stats())


@app.post("/api/breach/password")
def api_breach_password():
    d = request.get_json(silent=True) or {}
    r = breach.check_password_pwned(d.get("password", ""),
                                    allow_network=bool(d.get("allow_network")))
    if "error" not in r:
        log_scan("breach-password", f"sha1:{r['sha1_prefix']}…",
                 "found" if r["found"] else "not found",
                 90 if r.get("count", 0) > 100000 else 70 if r["found"] else 5,
                 f"Pwned count: {r.get('count', 0)} | network={r['network_used']}",
                 {k: v for k, v in r.items()})
    return jsonify(r)


@app.post("/api/breach/watch")
def api_breach_watch():
    d = request.get_json(silent=True) or {}
    return jsonify(breach.add_to_watchlist(d.get("email", ""), d.get("label", "")))


@app.post("/api/breach/recheck")
def api_breach_recheck():
    return jsonify(breach.recheck_watchlist())


@app.post("/breach/watch/<int:wid>/delete")
def breach_watch_delete(wid):
    breach.remove_from_watchlist(wid)
    return redirect(url_for("breach_page"))


@app.post("/breach/import")
def breach_import():
    text = request.form.get("corpus_text", "")
    f = request.files.get("corpus_file")
    if f and f.filename:
        try:
            text = f.read().decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            text = ""
    name = request.form.get("source_name") or (f.filename if f else "pasted import")
    if not text.strip():
        return redirect(url_for("breach_page"))
    breach.import_corpus(text, name)
    return redirect(url_for("breach_page"))


@app.post("/breach/corpus/clear")
def breach_corpus_clear():
    breach.clear_corpus(request.form.get("source") or None)
    return redirect(url_for("breach_page"))


@app.post("/api/breach/explain")
def api_breach_explain():
    d = request.get_json(silent=True) or {}
    return jsonify(breach.explain_breach(d.get("name", ""), use_ai=d.get("use_ai", True)))


# ================================================================== reports
@app.route("/reports")
def reports_page():
    return render_template("reports.html", reports=reports.list_reports(),
                           cases=ev.list_cases())


@app.get("/reports/case/<int:case_id>")
def report_case(case_id):
    r = reports.case_report(case_id, include_ai=request.args.get("ai", "1") == "1")
    if "error" in r:
        abort(404)
    if request.args.get("download") == "1":
        return send_file(r["path"], as_attachment=True, download_name=r["filename"])
    return Response(r["html"], mimetype="text/html")


@app.get("/reports/case/<int:case_id>/markdown")
def report_case_md(case_id):
    md = reports.case_markdown(case_id)
    return Response(md, mimetype="text/markdown",
                    headers={"Content-Disposition":
                             f'attachment; filename="case_{case_id}_report.md"'})


@app.get("/reports/scan/<int:scan_id>")
def report_scan(scan_id):
    s = query_one("SELECT * FROM scans WHERE id=?", (scan_id,))
    if not s:
        abort(404)
    try:
        details = json.loads(s["details"] or "{}")
    except json.JSONDecodeError:
        details = {}
    r = reports.module_report(s["module"], details)
    return Response(r["html"], mimetype="text/html")


@app.get("/reports/view/<int:rid>")
def report_view(rid):
    r = query_one("SELECT * FROM reports WHERE id=?", (rid,))
    if not r or not os.path.exists(r["path"]):
        abort(404)
    if request.args.get("download") == "1":
        return send_file(r["path"], as_attachment=True,
                         download_name=os.path.basename(r["path"]))
    return send_file(r["path"])


# ================================================================== history & settings
@app.route("/history")
def history_page():
    module = request.args.get("module", "all")
    sql = "SELECT * FROM scans WHERE 1=1"
    params = []
    if module != "all":
        sql += " AND module=?"; params.append(module)
    sql += " ORDER BY id DESC LIMIT 300"
    return render_template("history.html", scans=query(sql, tuple(params)), module=module,
                           modules=query("SELECT DISTINCT module FROM scans ORDER BY module"))


@app.get("/history/<int:sid>")
def history_detail(sid):
    s = query_one("SELECT * FROM scans WHERE id=?", (sid,))
    if not s:
        abort(404)
    try:
        s["details_obj"] = json.loads(s["details"] or "{}")
    except json.JSONDecodeError:
        s["details_obj"] = {}
    return render_template("history_detail.html", s=s)


@app.post("/history/clear")
def history_clear():
    execute("DELETE FROM scans")
    return redirect(url_for("history_page"))


@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    msg = None
    if request.method == "POST":
        host = request.form.get("ollama_host", "").strip()
        model = request.form.get("ollama_model", "").strip()
        if host:
            Config.OLLAMA_HOST = host; set_setting("ollama_host", host)
        if model:
            Config.OLLAMA_MODEL = model; set_setting("ollama_model", model)
        inv = request.form.get("investigator", "").strip()
        if inv:
            Config.DEFAULT_INVESTIGATOR = inv; set_setting("investigator", inv)
        ollama_client.status(force=True)
        msg = "Settings saved."
    st = ollama_client.status(force=True)
    db_size = os.path.getsize(Config.DB_PATH) if os.path.exists(Config.DB_PATH) else 0
    return render_template("settings.html", status=st, msg=msg, db_size=human_size(db_size),
                           stats=ev.stats(), config=Config)


@app.get("/api/ollama/status")
def api_ollama_status():
    return jsonify(ollama_client.status(force=True))


@app.post("/api/ollama/test")
def api_ollama_test():
    r = ollama_client.generate("Reply with exactly: CyberSafe AI is online and ready.",
                               temperature=0, max_tokens=30)
    return jsonify(r)


@app.route("/help")
def help_page():
    return render_template("help.html")


# ------------------------------------------------------------------ errors
@app.errorhandler(404)
def e404(e):
    return render_template("error.html", code=404, msg="Page not found"), 404


@app.errorhandler(413)
def e413(e):
    return render_template("error.html", code=413,
                           msg=f"File too large. Maximum upload size is "
                               f"{Config.MAX_CONTENT_LENGTH // (1024*1024)} MB. "
                               f"Increase it with the MAX_UPLOAD_MB environment variable."), 413


@app.errorhandler(500)
def e500(e):
    app.logger.exception("server error")
    return render_template("error.html", code=500,
                           msg="Internal error. Check the console for the traceback."), 500


if __name__ == "__main__":
    print("=" * 74)
    print(f"  {Config.APP_NAME}")
    print(f"  \"{Config.APP_TAGLINE}\"  v{Config.APP_VERSION}")
    print("=" * 74)
    st = ollama_client.status(force=True)
    if st["online"]:
        print(f"  [OK]   Ollama online at {Config.OLLAMA_HOST}")
        print(f"         Active model: {st['model']}")
        print(f"         Available:    {', '.join(st['models'][:6]) or '(none)'}")
    else:
        print(f"  [WARN] Ollama NOT reachable at {Config.OLLAMA_HOST}")
        print( "         All rule engines still work. To enable AI features:")
        print( "           1) ollama serve")
        print(f"           2) ollama pull {Config.OLLAMA_MODEL}")
    print(f"  [OK]   Database: {Config.DB_PATH}")
    print(f"  [OK]   Evidence vault: {Config.EVIDENCE_DIR}")
    print("-" * 74)
    print("  Open http://127.0.0.1:5000 in your browser")
    print("=" * 74)
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "5000")),
            debug=os.environ.get("DEBUG", "0") == "1", threaded=True)
