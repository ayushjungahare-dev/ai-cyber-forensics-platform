"""
Module 5 -- Browser Forensics.

Parses real browser artifacts with the standard library only:
  * Chrome/Edge/Brave  `History`  (SQLite: urls, visits, downloads, keyword_search_terms)
  * Firefox `places.sqlite` (moz_places, moz_historyvisits, moz_bookmarks)
  * Chrome `Cookies` / Firefox `cookies.sqlite`  (metadata only - values never decrypted)
  * Chrome `Login Data`  (METADATA ONLY: site + username + timestamps, never passwords)
  * Generic CSV/JSON history exports

Produces a risk assessment, category breakdown, timeline and IOCs.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sqlite3
import tempfile
from collections import Counter
from datetime import timedelta
from urllib.parse import unquote, urlparse

from core import ollama_client
from core.utils import (clamp, firefox_to_dt, human_time, webkit_to_dt)
from modules.phishing import analyze_url_rules

RISKY_CATEGORIES = {
    "hacking_tools": ["exploit-db", "metasploit", "hackforums", "crackstation", "nulled",
                      "cracked", "keygen", "warez", "torrent", "piratebay", "1337x",
                      "rarbg", "kickass", "serial key", "activator", "kmspico"],
    "darkweb": [".onion", "torproject.org/download", "tails.boum", "dark web", "darknet",
                "hidden wiki", "dread", "i2p"],
    "anonymity": ["hide.me", "protonvpn", "nordvpn", "tunnelbear", "hola vpn", "proxy site",
                  "kproxy", "hidemyass", "whoer.net", "temp-mail", "guerrillamail",
                  "10minutemail", "mailinator", "throwaway email"],
    "crypto": ["binance", "coinbase", "localbitcoins", "paxful", "coinjoin", "tornado.cash",
               "monero", "wasabi wallet", "mixer", "tumbler"],
    "data_exfil": ["anonfiles", "mega.nz", "wetransfer", "file.io", "transfer.sh",
                   "pastebin", "ghostbin", "privnote", "0bin", "justpaste.it",
                   "sendspace", "dropmefiles"],
    "credential_theft": ["phish", "login-", "-login", "verify-account", "account-verify",
                         "secure-update", "signin-", "webmail-"],
    "malware_dist": ["download crack", "free download full version", ".apk download",
                     "modded apk", "cracked apk", "software crack"],
    "adult": ["porn", "xxx", "adult", "xvideos", "pornhub"],
    "gambling": ["casino", "betting", "poker", "rummy", "teenpatti", "1xbet", "parimatch",
                 "dream11", "satta"],
    "job_scam": ["work from home earn", "part time job daily payment", "easy money online",
                 "task based job", "telegram job"],
}

SEVERITY = {"hacking_tools": ("high", 18), "darkweb": ("critical", 26),
            "anonymity": ("medium", 12), "crypto": ("medium", 10),
            "data_exfil": ("high", 18), "credential_theft": ("critical", 24),
            "malware_dist": ("critical", 24), "adult": ("low", 4),
            "gambling": ("medium", 8), "job_scam": ("high", 16)}

RISKY_DOWNLOAD_EXT = {".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                      ".jar", ".apk", ".hta", ".iso", ".img", ".dmg", ".zip", ".rar", ".7z"}


# ---------------------------------------------------------------- helpers
def _copy_to_temp(path: str) -> str:
    """Browsers lock their DBs; always work on a copy (also preserves the original)."""
    fd, tmp = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    with open(path, "rb") as src, open(tmp, "wb") as dst:
        while chunk := src.read(1024 * 1024):
            dst.write(chunk)
    return tmp


def _tables(conn) -> set:
    return {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}


def detect_browser(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            if fh.read(15) != b"SQLite format 3":
                return "unknown"
    except OSError:
        return "unknown"
    tmp = _copy_to_temp(path)
    try:
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        t = _tables(conn)
        conn.close()
        if {"urls", "visits"} <= t:
            return "chromium"       # Chrome / Edge / Brave / Opera / Vivaldi
        if {"moz_places", "moz_historyvisits"} <= t:
            return "firefox"
        if "cookies" in t or "moz_cookies" in t:
            return "cookies"
        if "logins" in t:
            return "logins"
        return "sqlite_other"
    except sqlite3.Error:
        return "unknown"
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------- parsers
def parse_chromium(path: str) -> dict:
    tmp = _copy_to_temp(path)
    out = {"browser": "Chromium-based (Chrome/Edge/Brave/Opera)",
           "history": [], "downloads": [], "searches": [], "cookies": []}
    try:
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        t = _tables(conn)

        if "urls" in t:
            for r in conn.execute(
                "SELECT id,url,title,visit_count,typed_count,last_visit_time "
                "FROM urls ORDER BY last_visit_time DESC LIMIT 5000"):
                dt = webkit_to_dt(r["last_visit_time"])
                out["history"].append({
                    "url": r["url"], "title": r["title"] or "",
                    "visit_count": r["visit_count"], "typed_count": r["typed_count"],
                    "last_visit": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "",
                })

        if "downloads" in t:
            cols = {c[1] for c in conn.execute("PRAGMA table_info(downloads)")}
            tgt = "target_path" if "target_path" in cols else "full_path"
            src = "tab_url" if "tab_url" in cols else ("referrer" if "referrer" in cols else "'?'")
            q = (f"SELECT {tgt} AS target, {src} AS source, total_bytes, start_time, "
                 f"{'danger_type' if 'danger_type' in cols else '0'} AS danger "
                 f"FROM downloads ORDER BY start_time DESC LIMIT 1000")
            for r in conn.execute(q):
                dt = webkit_to_dt(r["start_time"])
                out["downloads"].append({
                    "target": r["target"] or "", "source": r["source"] or "",
                    "size": r["total_bytes"] or 0,
                    "when": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "",
                    "danger_type": r["danger"],
                })

        if "keyword_search_terms" in t:
            for r in conn.execute(
                "SELECT term, url_id FROM keyword_search_terms LIMIT 1000"):
                out["searches"].append({"term": r["term"]})

        if "cookies" in t:
            cols = {c[1] for c in conn.execute("PRAGMA table_info(cookies)")}
            hk = "host_key" if "host_key" in cols else "domain"
            for r in conn.execute(
                f"SELECT {hk} AS host, name, path, expires_utc, is_secure, is_httponly "
                f"FROM cookies LIMIT 2000"):
                out["cookies"].append({
                    "host": r["host"], "name": r["name"], "path": r["path"],
                    "secure": bool(r["is_secure"]), "httponly": bool(r["is_httponly"]),
                    "value": "[REDACTED - encrypted, not extracted]",
                })

        if "logins" in t:
            out["logins"] = []
            for r in conn.execute(
                "SELECT origin_url, username_value, date_created, times_used FROM logins LIMIT 500"):
                dt = webkit_to_dt(r["date_created"])
                out["logins"].append({
                    "site": r["origin_url"], "username": r["username_value"],
                    "created": dt.strftime("%Y-%m-%d") if dt else "",
                    "times_used": r["times_used"],
                    "password": "[NEVER EXTRACTED - metadata only]",
                })
        conn.close()
    except sqlite3.Error as e:
        out["error"] = str(e)[:200]
    finally:
        os.unlink(tmp)
    return out


def parse_firefox(path: str) -> dict:
    tmp = _copy_to_temp(path)
    out = {"browser": "Mozilla Firefox", "history": [], "downloads": [],
           "searches": [], "bookmarks": [], "cookies": []}
    try:
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        t = _tables(conn)

        if "moz_places" in t:
            for r in conn.execute(
                "SELECT id,url,title,visit_count,typed,last_visit_date FROM moz_places "
                "WHERE url IS NOT NULL ORDER BY last_visit_date DESC LIMIT 5000"):
                dt = firefox_to_dt(r["last_visit_date"])
                out["history"].append({
                    "url": r["url"], "title": r["title"] or "",
                    "visit_count": r["visit_count"] or 0, "typed_count": r["typed"] or 0,
                    "last_visit": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "",
                })

        if "moz_bookmarks" in t and "moz_places" in t:
            for r in conn.execute(
                "SELECT b.title, p.url, b.dateAdded FROM moz_bookmarks b "
                "JOIN moz_places p ON p.id=b.fk WHERE p.url IS NOT NULL LIMIT 1000"):
                dt = firefox_to_dt(r["dateAdded"])
                out["bookmarks"].append({"title": r["title"] or "", "url": r["url"],
                                         "added": dt.strftime("%Y-%m-%d") if dt else ""})

        if "moz_annos" in t:
            try:
                for r in conn.execute(
                    "SELECT p.url, a.content FROM moz_annos a JOIN moz_places p ON p.id=a.place_id "
                    "LIMIT 500"):
                    if r["content"] and str(r["content"]).startswith("file://"):
                        out["downloads"].append({"target": r["content"], "source": r["url"],
                                                 "size": 0, "when": "", "danger_type": 0})
            except sqlite3.Error:
                pass

        if "moz_cookies" in t:
            for r in conn.execute(
                "SELECT host,name,path,isSecure,isHttpOnly FROM moz_cookies LIMIT 2000"):
                out["cookies"].append({"host": r["host"], "name": r["name"], "path": r["path"],
                                       "secure": bool(r["isSecure"]),
                                       "httponly": bool(r["isHttpOnly"]),
                                       "value": "[REDACTED - not extracted]"})
        conn.close()
    except sqlite3.Error as e:
        out["error"] = str(e)[:200]
    finally:
        os.unlink(tmp)
    return out


def parse_generic_export(path: str) -> dict:
    """CSV / JSON history exports (Google Takeout, browser add-ons, manual lists)."""
    out = {"browser": "Generic export", "history": [], "downloads": [],
           "searches": [], "cookies": []}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.read(12 * 1024 * 1024)
    except OSError as e:
        return {"error": str(e)}

    stripped = raw.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(raw)
            items = data if isinstance(data, list) else (
                data.get("Browser History") or data.get("history") or
                data.get("items") or data.get("data") or [])
            for it in items[:8000]:
                if not isinstance(it, dict):
                    continue
                url = it.get("url") or it.get("URL") or it.get("link") or ""
                if not url:
                    continue
                out["history"].append({
                    "url": url,
                    "title": it.get("title") or it.get("name") or "",
                    "visit_count": int(it.get("visit_count") or it.get("visitCount") or 1),
                    "typed_count": 0,
                    "last_visit": str(it.get("time_usec") or it.get("time") or
                                      it.get("lastVisitTime") or it.get("date") or "")[:19],
                })
            return out
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    try:
        sample = raw[:8000]
        dialect = csv.Sniffer().sniff(sample) if "," in sample or "\t" in sample else csv.excel
        rd = csv.DictReader(io.StringIO(raw), dialect=dialect)
        for row in rd:
            lower = {(k or "").strip().lower(): (v or "") for k, v in row.items()}
            url = lower.get("url") or lower.get("link") or lower.get("address") or ""
            if not url:
                continue
            out["history"].append({
                "url": url,
                "title": lower.get("title") or lower.get("page title") or "",
                "visit_count": int(re.sub(r"\D", "", lower.get("visit count", "1")) or 1),
                "typed_count": 0,
                "last_visit": (lower.get("date") or lower.get("time") or
                               lower.get("visit time") or lower.get("last visit") or "")[:19],
            })
    except (csv.Error, ValueError):
        # last resort: one URL per line
        for line in raw.splitlines()[:8000]:
            m = re.search(r"https?://\S+", line)
            if m:
                out["history"].append({"url": m.group(0), "title": "", "visit_count": 1,
                                       "typed_count": 0, "last_visit": ""})
    return out


# ---------------------------------------------------------------- analysis
def categorise(url: str, title: str = "") -> list[str]:
    blob = f"{url} {title}".lower()
    return [cat for cat, kws in RISKY_CATEGORIES.items() if any(k in blob for k in kws)]


def analyze_artifacts(parsed: dict, use_ai: bool = True) -> dict:
    history = parsed.get("history", [])
    downloads = parsed.get("downloads", [])
    findings, flagged, domains, hours = [], [], Counter(), Counter()
    cat_counter = Counter()

    for h in history:
        url = h.get("url", "")
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            host = ""
        if host:
            domains[host] += max(1, h.get("visit_count", 1))
        cats = categorise(url, h.get("title", ""))
        if cats:
            for c in cats:
                cat_counter[c] += 1
            sev = max((SEVERITY[c] for c in cats), key=lambda x: x[1])
            flagged.append({"url": url[:180], "title": (h.get("title") or "")[:100],
                            "categories": cats, "severity": sev[0],
                            "when": h.get("last_visit", ""),
                            "visits": h.get("visit_count", 0)})
        lv = h.get("last_visit", "")
        m = re.search(r"\b(\d{2}):\d{2}:\d{2}", str(lv))
        if m:
            hours[int(m.group(1))] += 1

    for cat, n in cat_counter.items():
        sev, pts = SEVERITY[cat]
        findings.append({"severity": sev,
                         "title": f"{cat.replace('_', ' ').title()} browsing activity",
                         "detail": f"{n} URL(s) matched this category.",
                         "points": min(pts + n, pts * 2)})

    # phishing scoring on the riskiest URLs
    phish = []
    checked = 0
    for h in history:
        if checked >= 120:
            break
        url = h.get("url", "")
        if not url.startswith("http"):
            continue
        checked += 1
        r = analyze_url_rules(url)
        if r["score"] >= 55:
            phish.append({"url": url[:180], "score": r["score"],
                          "reasons": [f["title"] for f in r["findings"][:3]],
                          "when": h.get("last_visit", "")})
    if phish:
        findings.append({"severity": "critical", "title": "Phishing-pattern URLs in history",
                         "detail": f"{len(phish)} visited URL(s) scored 55+ on the phishing engine.",
                         "points": min(20 + 5 * len(phish), 40)})

    # downloads
    risky_dl = []
    for d in downloads:
        tgt = (d.get("target") or "").lower()
        ext = os.path.splitext(tgt)[1]
        reasons = []
        if ext in RISKY_DOWNLOAD_EXT:
            reasons.append(f"executable/archive type ({ext})")
        if d.get("danger_type"):
            reasons.append("browser flagged it as dangerous")
        src = (d.get("source") or "")
        if src:
            sr = analyze_url_rules(src)
            if sr["score"] >= 50:
                reasons.append(f"downloaded from a suspicious source ({sr['score']}/100)")
        if re.search(r"\.(pdf|doc|jpg|png)\.(exe|scr|js)", tgt):
            reasons.append("double extension")
        if reasons:
            risky_dl.append({"target": os.path.basename(tgt)[:100] or tgt[:100],
                             "source": src[:140], "when": d.get("when", ""),
                             "reasons": reasons})
    if risky_dl:
        findings.append({"severity": "critical", "title": "Risky file downloads",
                         "detail": f"{len(risky_dl)} download(s) with executable or "
                                   f"suspicious characteristics.",
                         "points": min(18 + 6 * len(risky_dl), 40)})

    # odd-hours activity
    night = sum(v for h, v in hours.items() if h in (0, 1, 2, 3, 4))
    total_h = sum(hours.values()) or 1
    if night / total_h > 0.25 and total_h > 20:
        findings.append({"severity": "medium", "title": "Significant late-night activity",
                         "detail": f"{night}/{total_h} visits between 00:00-05:00 - "
                                   f"may indicate unauthorised use or automation.",
                         "points": 10})

    # searches
    risky_terms = []
    for s in parsed.get("searches", []):
        term = (s.get("term") or "").lower()
        if any(k in term for k in ("hack", "crack", "keygen", "bypass", "ddos", "carding",
                                   "how to steal", "free premium", "phishing page")):
            risky_terms.append(s.get("term"))
    if risky_terms:
        findings.append({"severity": "high", "title": "Concerning search terms",
                         "detail": "Terms: " + ", ".join(risky_terms[:5]),
                         "points": min(14 + 4 * len(risky_terms), 26)})

    # saved-login exposure (metadata only)
    logins = parsed.get("logins", [])
    if logins:
        findings.append({"severity": "medium", "title": "Browser-saved credentials present",
                         "detail": f"{len(logins)} site(s) have credentials stored in the browser "
                                   f"(passwords were NOT extracted). Malware routinely steals this store.",
                         "points": 12})

    # insecure cookies
    cookies = parsed.get("cookies", [])
    insecure = [c for c in cookies if not c.get("secure")]
    if cookies and len(insecure) / len(cookies) > 0.5:
        findings.append({"severity": "low", "title": "Many cookies without the Secure flag",
                         "detail": f"{len(insecure)}/{len(cookies)} cookies can travel over plain HTTP.",
                         "points": 6})

    score = clamp(sum(f["points"] for f in findings))
    result = {
        "browser": parsed.get("browser", "unknown"),
        "counts": {"history": len(history), "downloads": len(downloads),
                   "cookies": len(cookies), "searches": len(parsed.get("searches", [])),
                   "bookmarks": len(parsed.get("bookmarks", [])), "logins": len(logins)},
        "risk_score": score,
        "band": ("critical" if score >= 80 else "high" if score >= 55
                 else "medium" if score >= 25 else "low"),
        "findings": sorted(findings, key=lambda f: -f["points"]),
        "flagged_urls": sorted(flagged, key=lambda x: -x["visits"])[:60],
        "phishing_urls": sorted(phish, key=lambda x: -x["score"])[:30],
        "risky_downloads": risky_dl[:40],
        "top_domains": [{"domain": d, "visits": n} for d, n in domains.most_common(20)],
        "category_breakdown": [{"category": c.replace("_", " ").title(), "count": n}
                               for c, n in cat_counter.most_common()],
        "hourly_activity": [{"hour": h, "count": hours.get(h, 0)} for h in range(24)],
        "recent_history": history[:80],
        "logins_metadata": logins[:40],
        "searches": parsed.get("searches", [])[:60],
        "privacy_note": "Saved passwords and cookie VALUES are never decrypted or displayed "
                        "by this tool - only metadata is shown, in line with lawful "
                        "educational forensic practice.",
    }
    if use_ai:
        result["ai"] = ai_summary(result)
    return result


AI_SYSTEM = ("You are a digital forensics analyst reviewing browser artifacts. "
             "Summarise user behaviour, highlight compromise indicators and suggest "
             "investigative next steps. Be factual and avoid speculation beyond the data.")

SCHEMA = """{
  "behaviour_summary": "3-4 sentences on what the browsing shows",
  "compromise_indicators": ["specific indicators"],
  "risk_assessment": "low|medium|high|critical",
  "investigative_next_steps": ["what to examine next"],
  "user_advice": ["security advice for the device owner"]
}"""


def ai_summary(result: dict) -> dict:
    top_dom = ", ".join(f"{d['domain']}({d['visits']})" for d in result["top_domains"][:12])
    flags = "\n".join(f"- [{f['severity']}] {f['title']}: {f['detail']}"
                      for f in result["findings"][:10])
    phish = "\n".join(f"- {p['url'][:90]} (score {p['score']})" for p in result["phishing_urls"][:8])
    dls = "\n".join(f"- {d['target']} <- {d['source'][:60]} ({'; '.join(d['reasons'])})"
                    for d in result["risky_downloads"][:8])
    prompt = (
        f"Browser: {result['browser']}\n"
        f"Artifacts: {result['counts']}\n"
        f"Heuristic risk score: {result['risk_score']}/100\n\n"
        f"TOP DOMAINS: {top_dom}\n\nFINDINGS:\n{flags or '- none'}\n\n"
        f"PHISHING-PATTERN URLS:\n{phish or '- none'}\n\n"
        f"RISKY DOWNLOADS:\n{dls or '- none'}\n\n"
        "Produce your forensic summary."
    )
    res = ollama_client.generate_json(prompt, SCHEMA, system=AI_SYSTEM, temperature=0.2, max_tokens=800)
    if not res["ok"]:
        return {"available": False, "error": res.get("error")}
    d = res["data"]
    return {"available": True,
            "behaviour_summary": str(d.get("behaviour_summary", ""))[:1200],
            "compromise_indicators": d.get("compromise_indicators", [])[:10] if isinstance(d.get("compromise_indicators"), list) else [],
            "risk_assessment": str(d.get("risk_assessment", "medium")),
            "investigative_next_steps": d.get("investigative_next_steps", [])[:8] if isinstance(d.get("investigative_next_steps"), list) else [],
            "user_advice": d.get("user_advice", [])[:8] if isinstance(d.get("user_advice"), list) else [],
            "model": res.get("model")}


def analyze_file(path: str, use_ai: bool = True) -> dict:
    kind = detect_browser(path)
    if kind == "chromium":
        parsed = parse_chromium(path)
    elif kind == "firefox":
        parsed = parse_firefox(path)
    elif kind in ("cookies", "logins", "sqlite_other"):
        parsed = parse_chromium(path)
        if not any(parsed.get(k) for k in ("history", "cookies", "downloads")):
            parsed = parse_firefox(path)
    else:
        parsed = parse_generic_export(path)
    if parsed.get("error") and not parsed.get("history"):
        return {"error": parsed["error"], "hint": "Unsupported or corrupted artifact."}
    res = analyze_artifacts(parsed, use_ai=use_ai)
    res["source_type"] = kind
    return res
