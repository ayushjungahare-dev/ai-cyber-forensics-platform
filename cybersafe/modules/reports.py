"""
Report Generator -- professional investigation reports.

Outputs self-contained HTML (printable to PDF from the browser) and Markdown.
No external template engine, no wkhtmltopdf, no API keys.
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime
from pathlib import Path

from config import Config
from core import ollama_client
from core.database import execute, query, query_one, scalar
from core.utils import human_size, safe_name, utcnow
from modules import evidence as ev

CSS = """
*{box-sizing:border-box}
body{font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.6;color:#1a1a2e;
 max-width:1000px;margin:0 auto;padding:40px 32px;background:#fff}
h1{font-size:26px;margin:0 0 4px;color:#0f172a;border-bottom:3px solid #2563eb;padding-bottom:10px}
h2{font-size:19px;margin:32px 0 12px;color:#1e40af;border-left:4px solid #2563eb;padding-left:10px}
h3{font-size:15px;margin:20px 0 8px;color:#334155}
.meta{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin:18px 0}
.meta table{width:100%;border-collapse:collapse}
.meta td{padding:5px 8px;font-size:13px;vertical-align:top}
.meta td:first-child{font-weight:600;color:#475569;width:170px}
table.data{width:100%;border-collapse:collapse;margin:12px 0;font-size:12.5px}
table.data th{background:#1e40af;color:#fff;text-align:left;padding:8px 10px;font-weight:600}
table.data td{border-bottom:1px solid #e2e8f0;padding:7px 10px;vertical-align:top}
table.data tr:nth-child(even) td{background:#f8fafc}
.badge{display:inline-block;padding:2px 9px;border-radius:11px;font-size:11px;font-weight:700;
 text-transform:uppercase;letter-spacing:.4px}
.critical{background:#fee2e2;color:#991b1b}.high{background:#ffedd5;color:#9a3412}
.medium{background:#fef9c3;color:#854d0e}.low{background:#dcfce7;color:#166534}
.info{background:#dbeafe;color:#1e40af}.good{background:#dcfce7;color:#166534}
.scorebox{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0}
.score{flex:1;min-width:140px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
 padding:14px;text-align:center}
.score .n{font-size:26px;font-weight:800;color:#1e40af;display:block}
.score .l{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
.finding{border-left:4px solid #cbd5e1;background:#f8fafc;padding:10px 14px;margin:8px 0;
 border-radius:0 6px 6px 0}
.finding.critical{border-color:#dc2626;background:#fef2f2}
.finding.high{border-color:#ea580c;background:#fff7ed}
.finding.medium{border-color:#ca8a04;background:#fefce8}
.finding.low{border-color:#16a34a;background:#f0fdf4}
.finding b{display:block;font-size:13.5px;margin-bottom:2px}
.finding span{font-size:12.5px;color:#475569}
.ai{background:linear-gradient(135deg,#eff6ff,#f5f3ff);border:1px solid #c7d2fe;
 border-radius:8px;padding:16px;margin:14px 0}
.ai h3{margin-top:0;color:#4338ca}
code,.mono{font-family:'Consolas','Courier New',monospace;font-size:11.5px;
 background:#f1f5f9;padding:1px 5px;border-radius:3px;word-break:break-all}
.footer{margin-top:44px;padding-top:16px;border-top:2px solid #e2e8f0;font-size:11px;
 color:#64748b;text-align:center}
ul{margin:6px 0 6px 20px;padding:0}li{margin:3px 0;font-size:13px}
.hashline{font-family:monospace;font-size:11px;background:#f8fafc;padding:3px 6px;
 border-radius:3px;display:block;margin:2px 0;word-break:break-all}
@media print{body{padding:12px}h2{page-break-after:avoid}.finding{page-break-inside:avoid}
 table.data{page-break-inside:auto}tr{page-break-inside:avoid}}
"""


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _sev_badge(sev: str) -> str:
    s = (sev or "info").lower()
    cls = s if s in ("critical", "high", "medium", "low", "info", "good") else "info"
    return f'<span class="badge {cls}">{_e(s)}</span>'


def _findings_html(findings: list, limit=40) -> str:
    if not findings:
        return "<p><i>No findings recorded.</i></p>"
    out = []
    for f in findings[:limit]:
        sev = (f.get("severity") or "info").lower()
        out.append(
            f'<div class="finding {sev}">{_sev_badge(sev)} '
            f'<b>{_e(f.get("title"))}</b><span>{_e(f.get("detail"))}</span></div>')
    return "".join(out)


def _ai_block(ai: dict, title="AI Analysis") -> str:
    if not ai or not ai.get("available"):
        return ('<div class="ai"><h3>AI Analysis</h3><p><i>The local AI model (Ollama) was '
                'not available when this analysis ran. All findings above come from the '
                'deterministic rule engines.</i></p></div>')
    rows = []
    for key, label in [("verdict", "Verdict"), ("assessment", "Assessment"),
                       ("severity", "Severity"), ("risk_assessment", "Risk"),
                       ("likely_family", "Likely family"), ("confidence", "Confidence")]:
        if ai.get(key) not in (None, "", []):
            v = ai[key]
            rows.append(f"<b>{label}:</b> {_e(v)}" + ("%" if key == "confidence" else ""))
    text = (ai.get("reasoning") or ai.get("explanation") or ai.get("summary") or
            ai.get("behaviour_summary") or ai.get("text") or "")
    lists = ""
    for key, label in [("key_findings", "Key findings"), ("red_flags", "Red flags"),
                       ("tactics", "Tactics"),
                       ("capabilities", "Capabilities"), ("attack_techniques", "Techniques"),
                       ("compromise_indicators", "Indicators"), ("key_artefacts", "Key artefacts"),
                       ("affected_assets", "Affected assets"),
                       ("recommended_actions", "Recommended actions"),
                       ("analyst_next_steps", "Next steps"), ("next_steps", "Next steps"),
                       ("investigative_next_steps", "Investigative steps"),
                       ("immediate_actions", "Immediate actions"),
                       ("containment", "Containment"),
                       ("hardening_recommendations", "Hardening"),
                       ("user_advice", "User advice")]:
        items = ai.get(key)
        if isinstance(items, list) and items:
            lists += f"<h3>{label}</h3><ul>" + "".join(f"<li>{_e(i)}</li>" for i in items[:8]) + "</ul>"
    narrative = ai.get("attack_narrative")
    nar = f"<h3>Attack narrative</h3><p>{_e(narrative)}</p>" if narrative else ""
    return (f'<div class="ai"><h3>{_e(title)}</h3>'
            f'<p>{" &nbsp;|&nbsp; ".join(rows)}</p>'
            f'<p>{_e(text)}</p>{nar}{lists}'
            f'<p style="font-size:11px;color:#6366f1;margin-top:10px">'
            f'Generated locally by Ollama model <code>{_e(ai.get("model") or "local")}</code> '
            f'- no data left this machine.</p></div>')


def _auto_summary(case, items, scans, iocs) -> str:
    """Deterministic executive summary used when the AI layer is unavailable."""
    high = [s for s in scans if (s.get("risk_score") or 0) >= 55]
    failed = [e for e in items if not e.get("verified")]
    worst = max((s.get("risk_score") or 0) for s in scans) if scans else 0
    modules = sorted({s["module"] for s in scans})
    parts = [
        f"Case <b>{_e(case['case_number'])}</b> (\"{_e(case['title'])}\") is a "
        f"<b>{_e(case.get('incident_type') or 'general')}</b> investigation at "
        f"<b>{_e(case.get('priority'))}</b> priority, currently <b>{_e(case['status'])}</b>, "
        f"led by {_e(case.get('investigator') or 'the assigned analyst')}.",
        f"A total of <b>{len(items)}</b> evidence item(s) totalling {_e(case['total_size'])} were "
        f"acquired and hashed, producing {len(_custody_count(case))} custody event(s).",
    ]
    if scans:
        parts.append(
            f"<b>{len(scans)}</b> analysis run(s) were performed using the "
            f"{_e(', '.join(modules))} module(s). The highest risk score observed was "
            f"<b>{worst}/100</b>, with <b>{len(high)}</b> result(s) at high or critical severity.")
    else:
        parts.append("No automated analyses have been attached to this case yet.")
    if iocs:
        parts.append(f"<b>{len(iocs)}</b> indicator(s) of compromise were registered.")
    if failed:
        parts.append(f"<b class='crit-t'>{len(failed)} evidence item(s) failed integrity "
                     f"verification</b> and must be explained before being relied upon.")
    else:
        parts.append("All evidence currently passes hash verification against its acquisition "
                     "baseline.")
    return ('<div class="meta"><p style="font-size:13.5px;line-height:1.75">' +
            " ".join(parts) +
            '</p><p style="font-size:11.5px;color:#64748b;margin-top:10px">'
            'This summary was generated deterministically from the case record because the local '
            'AI model was not available. Start Ollama and regenerate the report for a narrative '
            'analyst summary.</p></div>')


def _custody_count(case):
    return query("""SELECT cu.id FROM custody cu JOIN evidence e ON e.id=cu.evidence_id
                    WHERE e.case_id=?""", (case["id"],))


def _shell(title: str, subtitle: str, body: str, case_ref="") -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title><style>{CSS}</style></head><body>
<h1>{_e(title)}</h1>
<p style="color:#64748b;margin:0 0 6px;font-size:14px">{_e(subtitle)}</p>
{body}
<div class="footer">
Generated by <b>{_e(Config.APP_NAME)}</b> v{Config.APP_VERSION} &mdash; "{_e(Config.APP_TAGLINE)}"<br>
Report produced {_e(utcnow())} UTC {('&mdash; ' + _e(case_ref)) if case_ref else ''}<br>
100% local processing &mdash; no cloud services, no API keys, no data transmitted.<br>
<i>This report is generated by an educational platform. For legal proceedings, findings should be
corroborated by a certified forensic examiner.</i>
</div></body></html>"""


# ---------------------------------------------------------------- case report
def case_report(case_id: int, include_ai=True) -> dict:
    case = ev.get_case(case_id)
    if not case:
        return {"error": "case not found"}
    items = ev.list_evidence(case_id)
    custody = ev.custody_chain(case_id)
    timeline = ev.case_timeline(case_id)
    iocs = ev.case_iocs(case_id)
    scans = query("SELECT * FROM scans WHERE case_id=? ORDER BY created_at DESC", (case_id,))

    body = []

    # ---- case metadata
    body.append(f"""<div class="meta"><table>
<tr><td>Case Number</td><td><b>{_e(case['case_number'])}</b></td></tr>
<tr><td>Title</td><td>{_e(case['title'])}</td></tr>
<tr><td>Incident Type</td><td>{_e(case.get('incident_type'))}</td></tr>
<tr><td>Status</td><td>{_sev_badge('high' if case['status']=='open' else 'info')} {_e(case['status'].replace('_',' ').title())}</td></tr>
<tr><td>Priority</td><td>{_sev_badge(case.get('priority','medium'))}</td></tr>
<tr><td>Lead Investigator</td><td>{_e(case.get('investigator'))}</td></tr>
<tr><td>Opened</td><td>{_e(case.get('created_at'))} UTC</td></tr>
<tr><td>Last Updated</td><td>{_e(case.get('updated_at'))} UTC</td></tr>
{'<tr><td>Closed</td><td>' + _e(case.get('closed_at')) + ' UTC</td></tr>' if case.get('closed_at') else ''}
</table></div>""")

    body.append(f"""<div class="scorebox">
<div class="score"><span class="n">{len(items)}</span><span class="l">Evidence Items</span></div>
<div class="score"><span class="n">{case['total_size']}</span><span class="l">Total Volume</span></div>
<div class="score"><span class="n">{len(custody)}</span><span class="l">Custody Events</span></div>
<div class="score"><span class="n">{len(iocs)}</span><span class="l">IOCs</span></div>
<div class="score"><span class="n">{len(scans)}</span><span class="l">Analyses Run</span></div>
<div class="score"><span class="n">{case.get('integrity_issues',0)}</span><span class="l">Integrity Failures</span></div>
</div>""")

    body.append("<h2>1. Case Summary</h2>")
    body.append(f"<p>{_e(case['description'])}</p>" if case.get("description")
                else "<p><i>No case description was recorded.</i></p>")

    # ---- executive summary (AI when available, deterministic otherwise)
    body.append("<h2>2. Executive Summary</h2>")
    if include_ai:
        ai = ai_case_summary(case, items, scans, iocs, timeline)
        if ai.get("available"):
            body.append(_ai_block(ai, "AI-Generated Executive Summary"))
        else:
            body.append(_auto_summary(case, items, scans, iocs))
    else:
        body.append(_auto_summary(case, items, scans, iocs))

    # ---- evidence register
    body.append("<h2>3. Evidence Register</h2>")
    if items:
        rows = ""
        for i, e in enumerate(items, 1):
            integ = ("<span class='badge low'>intact</span>" if e.get("verified")
                     else "<span class='badge critical'>MISMATCH</span>")
            rows += f"""<tr><td>{i}</td><td><b>{_e(e['name'])}</b><br>
<span style="font-size:11px;color:#64748b">{_e(e.get('original_filename'))}</span></td>
<td>{_e(e.get('evidence_type'))}</td><td>{_e(e.get('size_human'))}</td>
<td>{_e(e.get('collected_by'))}<br><span style="font-size:11px">{_e(e.get('collected_at'))}</span></td>
<td>{integ}</td>
<td class="mono" style="font-size:10px">MD5: {_e((e.get('md5') or '')[:32])}<br>
SHA-256: {_e((e.get('sha256') or '')[:64])}</td></tr>"""
        body.append(f"""<table class="data"><thead><tr><th>#</th><th>Evidence</th><th>Type</th>
<th>Size</th><th>Collected By / At</th><th>Integrity</th><th>Hashes</th></tr></thead>
<tbody>{rows}</tbody></table>""")
    else:
        body.append("<p><i>No evidence has been registered to this case.</i></p>")

    # ---- chain of custody
    body.append("<h2>4. Chain of Custody</h2>")
    body.append("<p style='font-size:12.5px;color:#475569'>Complete chronological record of every "
                "interaction with the evidence in this case. Each entry is immutable once written.</p>")
    if custody:
        rows = ""
        for c in custody[:200]:
            integ_cls = "low" if c.get("integrity") == "intact" else "critical"
            rows += (f"<tr><td class='mono'>{_e(c['ts'])}</td><td>#{_e(c['eid'])} {_e(c['evidence_name'])}</td>"
                     f"<td><b>{_e(c['action'].upper())}</b></td><td>{_e(c['actor'])}</td>"
                     f"<td><span class='badge {integ_cls}'>{_e(c.get('integrity'))}</span></td>"
                     f"<td style='font-size:11.5px'>{_e(c.get('notes'))}</td></tr>")
        body.append(f"""<table class="data"><thead><tr><th>Timestamp (UTC)</th><th>Evidence</th>
<th>Action</th><th>Actor</th><th>Integrity</th><th>Notes</th></tr></thead><tbody>{rows}</tbody></table>""")
    else:
        body.append("<p><i>No custody events recorded.</i></p>")

    # ---- analyses
    body.append("<h2>5. Forensic Analyses Performed</h2>")
    if scans:
        rows = ""
        for s in scans[:60]:
            rows += (f"<tr><td class='mono'>{_e(s['created_at'])}</td>"
                     f"<td><b>{_e(s['module'].title())}</b></td>"
                     f"<td class='mono' style='font-size:11px'>{_e((s.get('target') or '')[:80])}</td>"
                     f"<td>{_sev_badge('critical' if s['risk_score']>=80 else 'high' if s['risk_score']>=55 else 'medium' if s['risk_score']>=25 else 'low')} "
                     f"{s['risk_score']}/100</td>"
                     f"<td>{_e(s.get('verdict'))}</td>"
                     f"<td style='font-size:11.5px'>{_e((s.get('summary') or '')[:220])}</td></tr>")
        body.append(f"""<table class="data"><thead><tr><th>When (UTC)</th><th>Module</th><th>Target</th>
<th>Risk</th><th>Verdict</th><th>Summary</th></tr></thead><tbody>{rows}</tbody></table>""")
    else:
        body.append("<p><i>No analyses linked to this case.</i></p>")

    # ---- IOCs
    body.append("<h2>6. Indicators of Compromise</h2>")
    if iocs:
        rows = "".join(f"<tr><td>{_e(i['ioc_type'])}</td><td class='mono'>{_e(i['value'])}</td>"
                       f"<td>{_e(i['source_module'])}</td><td>{_e(i['confidence'])}%</td>"
                       f"<td class='mono'>{_e(i['first_seen'])}</td></tr>" for i in iocs[:200])
        body.append(f"""<table class="data"><thead><tr><th>Type</th><th>Indicator</th><th>Source</th>
<th>Confidence</th><th>First Seen</th></tr></thead><tbody>{rows}</tbody></table>""")
    else:
        body.append("<p><i>No indicators of compromise registered.</i></p>")

    # ---- timeline
    body.append("<h2>7. Investigation Timeline</h2>")
    if timeline:
        rows = "".join(f"<tr><td class='mono'>{_e(t['ts'])}</td><td>{_sev_badge(t.get('severity'))}</td>"
                       f"<td>{_e(t['source'])}</td><td>{_e(t['event'])}</td></tr>"
                       for t in timeline[:150])
        body.append(f"""<table class="data"><thead><tr><th>Timestamp (UTC)</th><th>Severity</th>
<th>Source</th><th>Event</th></tr></thead><tbody>{rows}</tbody></table>""")
    else:
        body.append("<p><i>No timeline entries.</i></p>")

    # ---- integrity statement
    failed = [e for e in items if not e.get("verified")]
    body.append("<h2>8. Evidence Integrity Statement</h2>")
    if items and not failed:
        body.append(f"""<div class="finding low"><b>ALL EVIDENCE VERIFIED INTACT</b>
<span>All {len(items)} evidence item(s) were cryptographically hashed at the moment of
acquisition using MD5, SHA-1 and SHA-256. Re-verification confirms every item's current hash
matches its acquisition baseline. No tampering or corruption has occurred while the evidence has
been in the custody of this platform.</span></div>""")
    elif failed:
        body.append(f"""<div class="finding critical"><b>INTEGRITY FAILURE DETECTED</b>
<span>{len(failed)} of {len(items)} evidence item(s) FAILED hash verification: """ +
                    _e(", ".join(f"#{f['id']} {f['name']}" for f in failed[:8])) +
                    """. These items must not be relied upon without explanation of the discrepancy.
The custody log records when the mismatch was first observed.</span></div>""")
    else:
        body.append("<p><i>No evidence to verify.</i></p>")

    body.append("""<h2>9. Methodology &amp; Limitations</h2>
<p style="font-size:13px">All analysis was performed locally using deterministic rule engines and a
locally-hosted large language model (Ollama). No file, hash, URL or message was transmitted to any
third-party service, and no API keys were used at any point.</p>
<ul>
<li>Evidence is copied into a managed vault and hashed at acquisition; originals are never modified.</li>
<li>Analysis is performed on the stored copy only.</li>
<li>Malware analysis is <b>static</b> - samples are never executed.</li>
<li>Memory analysis uses string/pattern carving, not kernel symbol reconstruction, so results are
investigative leads rather than definitive process listings.</li>
<li>AI commentary is generated by a local model and may contain errors; it supplements, and never
replaces, the deterministic findings and human judgement.</li>
</ul>""")

    html_doc = _shell(f"Digital Forensics Investigation Report",
                      f"{case['case_number']} - {case['title']}",
                      "".join(body), case_ref=case["case_number"])

    fn = f"{safe_name(case['case_number'])}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    path = Path(Config.REPORT_DIR) / fn
    path.write_text(html_doc, encoding="utf-8")
    execute("INSERT INTO reports(case_id,title,path,kind,created_at) VALUES(?,?,?,?,?)",
            (case_id, f"Case report {case['case_number']}", str(path), "case", utcnow()))
    return {"path": str(path), "filename": fn, "html": html_doc}


# ---------------------------------------------------------------- module reports
def module_report(module: str, result: dict, title: str = "") -> dict:
    body = []
    score = result.get("risk_score", result.get("score", 0))
    verdict = result.get("verdict", result.get("rating", "-"))
    band = result.get("band", "info")

    body.append(f"""<div class="scorebox">
<div class="score"><span class="n">{score}/100</span><span class="l">Risk Score</span></div>
<div class="score"><span class="n">{_e(verdict)}</span><span class="l">Verdict</span></div>
<div class="score"><span class="n">{len(result.get('findings',[]))}</span><span class="l">Findings</span></div>
</div>""")

    meta_rows = ""
    for k in ("filename", "kind", "input", "true_type", "size_human", "entropy",
              "log_type_label", "total_lines", "parsed_records", "browser",
              "file_size_human", "analyzed_human", "length", "entropy_bits"):
        if result.get(k) not in (None, "", []):
            v = str(result[k])
            meta_rows += f"<tr><td>{_e(k.replace('_',' ').title())}</td><td class='mono'>{_e(v[:300])}</td></tr>"
    if result.get("hashes"):
        for a, h in result["hashes"].items():
            meta_rows += f"<tr><td>{a.upper()}</td><td class='mono'>{_e(h)}</td></tr>"
    if meta_rows:
        body.append(f'<div class="meta"><table>{meta_rows}</table></div>')

    body.append("<h2>Findings</h2>" + _findings_html(result.get("findings", [])))

    if result.get("ai"):
        body.append("<h2>AI Assessment</h2>" + _ai_block(result["ai"]))

    # module extras
    if result.get("iocs") and result["iocs"].get("total"):
        i = result["iocs"]
        rows = ""
        for t in ("urls", "domains", "ips", "emails", "bitcoin", "upi_ids", "phones"):
            if i.get(t):
                rows += (f"<tr><td>{t.title()}</td><td class='mono' style='font-size:11px'>"
                         f"{_e(', '.join(i[t][:14]))}</td></tr>")
        if rows:
            body.append(f'<h2>Indicators Extracted</h2><table class="data">'
                        f'<thead><tr><th>Type</th><th>Values</th></tr></thead><tbody>{rows}</tbody></table>')

    if result.get("recommended_action"):
        body.append("<h2>Recommended Actions</h2><ul>" +
                    "".join(f"<li>{_e(a)}</li>" for a in result["recommended_action"]) + "</ul>")

    if result.get("crack_times"):
        rows = "".join(f"<tr><td>{_e(k)}</td><td><b>{_e(v)}</b></td></tr>"
                       for k, v in result["crack_times"].items())
        body.append(f'<h2>Estimated Crack Time</h2><table class="data">'
                    f'<thead><tr><th>Attack scenario</th><th>Time to crack</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table>')

    if result.get("timeline"):
        rows = "".join(f"<tr><td class='mono'>{_e(t.get('ts'))}</td><td>{_sev_badge(t.get('severity'))}</td>"
                       f"<td>{_e(t.get('source'))}</td><td>{_e(t.get('event'))}</td></tr>"
                       for t in result["timeline"][:80])
        body.append(f'<h2>Timeline</h2><table class="data"><thead><tr><th>Time</th><th>Severity</th>'
                    f'<th>Source</th><th>Event</th></tr></thead><tbody>{rows}</tbody></table>')

    names = {"phishing": "Phishing Analysis Report", "password": "Password Security Report",
             "malware": "Malware Static Analysis Report", "browser": "Browser Forensics Report",
             "memory": "Memory Forensics Report", "logs": "Log Analysis Report"}
    doc_title = title or names.get(module, f"{module.title()} Report")
    html_doc = _shell(doc_title, f"Generated {utcnow()} UTC", "".join(body))

    fn = f"{safe_name(module)}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    path = Path(Config.REPORT_DIR) / fn
    path.write_text(html_doc, encoding="utf-8")
    execute("INSERT INTO reports(case_id,title,path,kind,created_at) VALUES(?,?,?,?,?)",
            (None, doc_title, str(path), module, utcnow()))
    return {"path": str(path), "filename": fn, "html": html_doc}


# ---------------------------------------------------------------- markdown
def case_markdown(case_id: int) -> str:
    case = ev.get_case(case_id)
    if not case:
        return "# Case not found"
    items = ev.list_evidence(case_id)
    custody = ev.custody_chain(case_id)
    iocs = ev.case_iocs(case_id)
    scans = query("SELECT * FROM scans WHERE case_id=? ORDER BY created_at DESC", (case_id,))

    md = [f"# Digital Forensics Investigation Report",
          f"## {case['case_number']} - {case['title']}", "",
          "| Field | Value |", "|---|---|",
          f"| Case Number | **{case['case_number']}** |",
          f"| Incident Type | {case.get('incident_type')} |",
          f"| Status | {case['status']} |",
          f"| Priority | {case.get('priority')} |",
          f"| Investigator | {case.get('investigator')} |",
          f"| Opened | {case.get('created_at')} UTC |",
          f"| Evidence Items | {len(items)} |",
          f"| Total Volume | {case['total_size']} |",
          f"| Custody Events | {len(custody)} |", ""]
    if case.get("description"):
        md += ["## Case Summary", case["description"], ""]

    md += ["## Evidence Register", "",
           "| # | Name | Type | Size | Collected | Integrity | SHA-256 |", "|---|---|---|---|---|---|---|"]
    for i, e in enumerate(items, 1):
        md.append(f"| {i} | {e['name']} | {e.get('evidence_type')} | {e.get('size_human')} | "
                  f"{e.get('collected_at')} | {'intact' if e.get('verified') else 'MISMATCH'} | "
                  f"`{(e.get('sha256') or '')[:32]}...` |")

    md += ["", "## Chain of Custody", "", "| Timestamp | Evidence | Action | Actor | Notes |",
           "|---|---|---|---|---|"]
    for c in custody[:120]:
        md.append(f"| {c['ts']} | #{c['eid']} {c['evidence_name']} | {c['action']} | "
                  f"{c['actor']} | {(c.get('notes') or '')[:110]} |")

    if scans:
        md += ["", "## Analyses Performed", "", "| When | Module | Risk | Verdict | Summary |",
               "|---|---|---|---|---|"]
        for s in scans[:40]:
            md.append(f"| {s['created_at']} | {s['module']} | {s['risk_score']}/100 | "
                      f"{s.get('verdict')} | {(s.get('summary') or '')[:110]} |")

    if iocs:
        md += ["", "## Indicators of Compromise", "", "| Type | Value | Source |", "|---|---|---|"]
        for i in iocs[:120]:
            md.append(f"| {i['ioc_type']} | `{i['value']}` | {i['source_module']} |")

    md += ["", "---", f"*Generated by {Config.APP_NAME} v{Config.APP_VERSION} on {utcnow()} UTC.*",
           "*100% local analysis - no cloud services, no API keys.*"]
    return "\n".join(md)


# ---------------------------------------------------------------- AI summary
AI_SYSTEM = ("You are a lead digital forensics investigator writing the executive summary of a "
             "case report for management and possibly law enforcement. Be factual, structured "
             "and clear. Do not invent evidence that is not listed.")

SCHEMA = """{
  "executive_summary": "4-6 sentences a non-technical manager can understand",
  "key_findings": ["the most important findings"],
  "assessment": "your professional assessment of what occurred",
  "evidence_quality": "comment on completeness and integrity of the evidence",
  "recommendations": ["recommended actions"],
  "next_steps": ["further investigation required"]
}"""


def ai_case_summary(case, items, scans, iocs, timeline) -> dict:
    ev_txt = "\n".join(f"- {e['name']} ({e.get('evidence_type')}, {e.get('size_human')}, "
                       f"integrity={'intact' if e.get('verified') else 'MISMATCH'})"
                       for e in items[:20]) or "- none"
    sc_txt = "\n".join(f"- {s['module']}: risk {s['risk_score']}/100, verdict {s.get('verdict')} "
                       f"- {(s.get('summary') or '')[:140]}" for s in scans[:15]) or "- none"
    ioc_txt = ", ".join(f"{i['ioc_type']}:{i['value'][:50]}" for i in iocs[:20]) or "none"
    tl_txt = "\n".join(f"- {t['ts']} [{t.get('severity')}] {t['event'][:110]}"
                       for t in timeline[:20]) or "- none"
    prompt = (
        f"CASE {case['case_number']}: {case['title']}\n"
        f"Incident type: {case.get('incident_type')} | Priority: {case.get('priority')} | "
        f"Status: {case['status']}\n"
        f"Description: {case.get('description') or '(none provided)'}\n\n"
        f"EVIDENCE ({len(items)} items):\n{ev_txt}\n\n"
        f"ANALYSES PERFORMED:\n{sc_txt}\n\nIOCs: {ioc_txt}\n\nTIMELINE:\n{tl_txt}\n\n"
        "Write the executive summary section of the report."
    )
    res = ollama_client.generate_json(prompt, SCHEMA, system=AI_SYSTEM, temperature=0.25, max_tokens=900)
    if not res["ok"]:
        return {"available": False, "error": res.get("error")}
    d = res["data"]
    return {"available": True,
            "summary": str(d.get("executive_summary", ""))[:1800],
            "assessment": str(d.get("assessment", ""))[:900],
            "key_findings": d.get("key_findings", [])[:10] if isinstance(d.get("key_findings"), list) else [],
            "recommended_actions": d.get("recommendations", [])[:8] if isinstance(d.get("recommendations"), list) else [],
            "next_steps": d.get("next_steps", [])[:8] if isinstance(d.get("next_steps"), list) else [],
            "evidence_quality": str(d.get("evidence_quality", ""))[:500],
            "model": res.get("model")}


def list_reports(limit=50) -> list[dict]:
    rows = query("SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,))
    for r in rows:
        r["exists"] = os.path.exists(r["path"] or "")
        r["size"] = human_size(os.path.getsize(r["path"])) if r["exists"] else "-"
    return rows
