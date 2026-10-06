"""
Module 7 -- Log Analysis.

Auto-detects and parses:
  * Windows Event Logs (EVTX binary carving + exported CSV/XML/text)
  * Linux auth.log / syslog / secure
  * Apache / Nginx access & error logs (combined + common)
  * Firewall logs (iptables, pfSense, Windows Firewall)
  * Generic key=value and JSON-lines logs

Then runs a detection engine: brute force, password spraying, privilege escalation,
web attacks (SQLi/XSS/LFI/RCE), scanning, data exfiltration, impossible travel,
off-hours access, log tampering, and more. Builds a timeline + AI summary.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from core import ollama_client
from core.utils import clamp, extract_iocs, parse_any_time

# ---------------------------------------------------------------- Event IDs
WINDOWS_EVENTS = {
    "4624": ("Successful logon", "info"),
    "4625": ("Failed logon attempt", "medium"),
    "4634": ("Account logged off", "info"),
    "4647": ("User-initiated logoff", "info"),
    "4648": ("Logon with explicit credentials (runas)", "medium"),
    "4672": ("Special/admin privileges assigned to logon", "medium"),
    "4720": ("User account CREATED", "high"),
    "4722": ("User account enabled", "medium"),
    "4723": ("Password change attempted", "medium"),
    "4724": ("Password RESET by administrator", "high"),
    "4725": ("User account disabled", "medium"),
    "4726": ("User account DELETED", "high"),
    "4728": ("Member added to global security group", "high"),
    "4732": ("Member added to LOCAL security group (e.g. Administrators)", "high"),
    "4738": ("User account changed", "medium"),
    "4740": ("User account LOCKED OUT", "high"),
    "4767": ("User account unlocked", "medium"),
    "4768": ("Kerberos TGT requested", "info"),
    "4769": ("Kerberos service ticket requested", "info"),
    "4771": ("Kerberos pre-authentication failed", "medium"),
    "4776": ("NTLM credential validation", "info"),
    "4778": ("RDP session reconnected", "medium"),
    "4779": ("RDP session disconnected", "info"),
    "1102": ("AUDIT LOG CLEARED", "critical"),
    "104": ("Event log cleared", "critical"),
    "7045": ("New SERVICE installed", "high"),
    "7040": ("Service start type changed", "medium"),
    "4697": ("Service installed (security log)", "high"),
    "4698": ("Scheduled task CREATED", "high"),
    "4699": ("Scheduled task deleted", "medium"),
    "4700": ("Scheduled task enabled", "medium"),
    "4702": ("Scheduled task updated", "medium"),
    "4688": ("New process created", "info"),
    "4689": ("Process exited", "info"),
    "5140": ("Network share accessed", "medium"),
    "5145": ("Detailed file share access", "medium"),
    "5156": ("Firewall permitted a connection", "info"),
    "5157": ("Firewall BLOCKED a connection", "medium"),
    "1116": ("Defender detected MALWARE", "critical"),
    "1117": ("Defender took action on malware", "high"),
    "1118": ("Defender remediation started", "medium"),
    "1006": ("Defender malware detected", "critical"),
    "5001": ("Defender real-time protection DISABLED", "critical"),
    "4104": ("PowerShell script block logged", "medium"),
    "4103": ("PowerShell module logging", "info"),
    "400": ("PowerShell engine started", "info"),
    "800": ("PowerShell pipeline execution", "info"),
    "6005": ("Event log service started (boot)", "info"),
    "6006": ("Event log service stopped (shutdown)", "info"),
    "6008": ("UNEXPECTED shutdown", "medium"),
    "1074": ("System shutdown/restart initiated", "info"),
}

LOGON_TYPES = {
    "2": "Interactive (console)", "3": "Network (SMB/share)", "4": "Batch (scheduled task)",
    "5": "Service", "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials (runas)",
    "10": "RemoteInteractive (RDP)", "11": "CachedInteractive",
}

WEB_ATTACKS = [
    (r"(\%27)|(\')|(\-\-)|(\%23)|(#).*(\bor\b|\bunion\b|\bselect\b)", "SQL Injection", "critical"),
    (r"\bunion\b[\s\/\*]+\bselect\b", "SQL Injection (UNION)", "critical"),
    (r"\b(select|insert|update|delete|drop|alter)\b.{0,30}\b(from|into|table|database)\b", "SQL Injection", "critical"),
    (r"(sleep\(|benchmark\(|waitfor\s+delay|pg_sleep)", "Blind SQL Injection", "critical"),
    (r"(<script|%3cscript|javascript:|onerror=|onload=|onmouseover=)", "Cross-Site Scripting", "high"),
    (r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", "Path Traversal", "high"),
    (r"(/etc/passwd|/etc/shadow|boot\.ini|win\.ini|/proc/self/environ)", "Local File Inclusion", "critical"),
    (r"(;|\||`|\$\()\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\b", "Command Injection", "critical"),
    (r"(cmd\.exe|/bin/bash|/bin/sh|powershell)", "Command Execution attempt", "critical"),
    (r"\b(base64_decode|eval\(|system\(|exec\(|passthru|shell_exec)\b", "PHP Code Injection", "critical"),
    (r"(\{\{.*\}\}|\$\{.*\})", "Template/Expression Injection", "high"),
    (r"jndi:(ldap|rmi|dns)", "Log4Shell (CVE-2021-44228)", "critical"),
    (r"/(wp-admin|wp-login|xmlrpc\.php|phpmyadmin|adminer)", "CMS/Admin probing", "medium"),
    (r"/\.(git|env|svn|htaccess|aws|ssh)", "Sensitive file probing", "high"),
    (r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nessus|havij|zgrab)", "Automated scanner", "high"),
    (r"/(shell|c99|r57|webshell|cmd)\.(php|asp|jsp)", "Web shell access", "critical"),
    (r"\b(admin|administrator|root|test)\b.{0,10}(password|passwd|pwd)=", "Credential in URL", "high"),
]

SUSPICIOUS_UA = ["sqlmap", "nikto", "curl", "wget", "python-requests", "go-http-client",
                 "libwww-perl", "masscan", "zgrab", "nmap", "havij", "acunetix", "burp",
                 "hydra", "dirbuster", "gobuster", "ffuf", "scanner", "bot"]

# ---------------------------------------------------------------- regexes
APACHE_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^"\s]*)\s*(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?')
SYSLOG_RE = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
ISO_SYSLOG_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+(?P<host>\S+)\s+"
    r"(?P<proc>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
IPTABLES_RE = re.compile(r"SRC=(?P<src>\S+)")
IPT_DST_RE = re.compile(r"DST=(\S+)")
IPT_DPT_RE = re.compile(r"DPT=(\d+)")
IPT_PROTO_RE = re.compile(r"PROTO=(\w+)")
EVENTID_RE = re.compile(r"(?:event\s*id|eventid|\bid\b)[\s:=\"']*(\d{1,5})", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"(?:user|username|account name|for user|for invalid user|logon account)"
                     r"[\s:=\"']+([A-Za-z0-9._\\$@\-]{1,64})", re.I)


def detect_log_type(sample: str, filename: str = "") -> str:
    fn = filename.lower()
    if fn.endswith(".evtx") or sample[:7] == "ElfFile":
        return "evtx"
    s = sample[:20000]
    if APACHE_RE.search(s):
        return "webserver"
    if re.search(r"EventID|Event ID|Microsoft-Windows|Security-Auditing|<Event xmlns", s, re.I):
        return "windows"
    # Firewall must be tested BEFORE Linux: UFW/iptables entries are syslog-framed
    # and would otherwise be swallowed by the generic "kernel:" match.
    fw_hits = len(re.findall(r"(SRC=\d|DPT=\d|UFW (BLOCK|ALLOW|AUDIT)|iptables|"
                             r"filterlog|pfSense|Windows Firewall|DROP\s+TCP)", s, re.I))
    if fw_hits >= 3 or "firewall" in fn or fn.startswith("ufw") or "iptables" in fn:
        return "firewall"
    if re.search(r"sshd\[|sudo:|pam_unix|systemd\[|kernel:", s):
        return "linux"
    if s.strip().startswith("{") and '"' in s:
        return "json"
    if SYSLOG_RE.search(s) or ISO_SYSLOG_RE.search(s):
        return "linux"
    return "generic"


# ---------------------------------------------------------------- EVTX
def carve_evtx(path: str, limit: int = 60000) -> list[dict]:
    """
    EVTX records are binary but embed UTF-16LE XML fragments. We carve the
    <Event> XML chunks - good enough for teaching and for most triage.
    """
    events = []
    with open(path, "rb") as fh:
        data = fh.read(min(os.path.getsize(path), 300 * 1024 * 1024))
    text = data.decode("utf-16-le", "ignore")
    if text.count("<Event") < 3:
        text = data.decode("utf-8", "ignore")
    for m in re.finditer(r"<Event\b.*?</Event>", text, re.S):
        frag = m.group(0)
        eid = (re.search(r"<EventID[^>]*>(\d+)</EventID>", frag) or [None, ""])[1]
        ts = (re.search(r'SystemTime=["\']([^"\']+)', frag) or [None, ""])[1]
        comp = (re.search(r"<Computer>([^<]*)</Computer>", frag) or [None, ""])[1]
        chan = (re.search(r"<Channel>([^<]*)</Channel>", frag) or [None, ""])[1]
        datas = dict(re.findall(r'<Data Name=["\']([^"\']+)["\']>([^<]*)</Data>', frag))
        events.append({"event_id": eid, "time": ts[:19].replace("T", " "),
                       "computer": comp, "channel": chan, "data": datas,
                       "raw": frag[:800]})
        if len(events) >= limit:
            break
    return events


# ---------------------------------------------------------------- parsers
def parse_windows(lines: list[str]) -> list[dict]:
    events, buf = [], []
    for raw in lines:
        line = raw.rstrip("\n")
        if EVENTID_RE.search(line) and buf:
            events.append(_win_record("\n".join(buf)))
            buf = [line]
        else:
            buf.append(line)
        if len(buf) > 60:
            events.append(_win_record("\n".join(buf))); buf = []
    if buf:
        events.append(_win_record("\n".join(buf)))
    return [e for e in events if e.get("event_id")]


def _win_record(block: str) -> dict:
    eid = (EVENTID_RE.search(block) or [None, ""])[1]
    ips = [i for i in IP_RE.findall(block) if not i.startswith(("0.", "255."))]
    user = (USER_RE.search(block) or [None, ""])[1]
    ltype = (re.search(r"logon type[\s:=\"']+(\d+)", block, re.I) or [None, ""])[1]
    t = parse_any_time((re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", block) or
                        re.search(r"\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*[AP]M", block) or
                        [None])[0] if re.search(r"\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4}", block) else None)
    return {"event_id": eid, "user": user, "ip": ips[0] if ips else "",
            "logon_type": ltype, "time": t.strftime("%Y-%m-%d %H:%M:%S") if t else "",
            "raw": block[:600]}


def parse_linux(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        m = SYSLOG_RE.match(line) or ISO_SYSLOG_RE.match(line)
        if not m:
            continue
        g = m.groupdict()
        msg = g.get("msg", "")
        ips = IP_RE.findall(msg)
        user = ""
        um = re.search(r"(?:for(?: invalid user)?|user)\s+(\S+)", msg)
        if um:
            user = um.group(1)
        out.append({"time": g.get("time", ""), "host": g.get("host", ""),
                    "process": (g.get("proc") or "").strip(), "pid": g.get("pid"),
                    "message": msg[:400], "ip": ips[0] if ips else "", "user": user})
    return out


def parse_webserver(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        m = APACHE_RE.search(line)
        if not m:
            continue
        g = m.groupdict()
        try:
            size = int(g.get("size") or 0)
        except ValueError:
            size = 0
        out.append({"ip": g["ip"], "user": g.get("user", "-"), "time": g["time"],
                    "method": g["method"], "path": g["path"][:400],
                    "status": int(g["status"]), "size": size,
                    "referer": g.get("ref") or "", "ua": g.get("ua") or ""})
    return out


def parse_firewall(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        m = IPTABLES_RE.search(line)
        if m:
            action = "BLOCK" if re.search(r"(drop|block|deny|reject)", line, re.I) else "ALLOW"
            dst = IPT_DST_RE.search(line)
            dpt = IPT_DPT_RE.search(line)
            proto = IPT_PROTO_RE.search(line)
            out.append({"src": m.group("src"), "dst": dst.group(1) if dst else "",
                        "port": dpt.group(1) if dpt else "",
                        "proto": proto.group(1) if proto else "",
                        "action": action, "raw": line[:300]})
            continue
        ips = IP_RE.findall(line)
        if ips and re.search(r"(drop|block|deny|allow|accept|permit)", line, re.I):
            action = "BLOCK" if re.search(r"(drop|block|deny|reject)", line, re.I) else "ALLOW"
            port = (re.search(r"[:\s](\d{2,5})(?:\s|$)", line) or [None, ""])[1]
            out.append({"src": ips[0], "dst": ips[1] if len(ips) > 1 else "",
                        "port": port, "action": action, "raw": line[:300]})
    return out


def parse_json_lines(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# ---------------------------------------------------------------- detections
def detect_threats(log_type: str, records: list[dict], raw_lines: list[str]) -> tuple[list, list, dict]:
    findings, timeline = [], []
    stats = {}

    def add(sev, title, detail, pts, evidence=None):
        findings.append({"severity": sev, "title": title, "detail": detail,
                         "points": pts, "evidence": (evidence or [])[:6]})

    # ---------- Windows
    if log_type in ("windows", "evtx"):
        eids = Counter(r.get("event_id") for r in records if r.get("event_id"))
        stats["event_id_counts"] = [{"id": k, "name": WINDOWS_EVENTS.get(k, ("Unknown", "info"))[0],
                                     "count": v} for k, v in eids.most_common(25)]
        failed = [r for r in records if r.get("event_id") == "4625"]
        success = [r for r in records if r.get("event_id") == "4624"]

        by_user = Counter(r.get("user", "").lower() for r in failed if r.get("user"))
        by_ip = Counter(r.get("ip") for r in failed if r.get("ip"))
        for user, n in by_user.most_common(6):
            if n >= 5:
                add("critical" if n >= 15 else "high", "Brute-force: repeated failed logons",
                    f"Account '{user}' failed to log on {n} times (Event ID 4625).",
                    min(20 + n, 40), [r["raw"][:160] for r in failed if r.get("user", "").lower() == user][:3])
        for ip, n in by_ip.most_common(6):
            if n >= 5:
                add("critical" if n >= 15 else "high", "Brute-force from a single source IP",
                    f"{n} failed logons originated from {ip}.", min(20 + n, 40))
        if len(by_user) >= 5 and max(by_user.values()) <= 4:
            add("critical", "Password spraying pattern",
                f"{len(by_user)} different accounts each saw a few failures - "
                f"classic low-and-slow spray.", 34)
        # success right after failures = likely successful brute force
        if failed and success:
            fu = {r.get("user", "").lower() for r in failed if r.get("user")}
            su = {r.get("user", "").lower() for r in success if r.get("user")}
            both = fu & su
            for u in list(both)[:4]:
                if by_user.get(u, 0) >= 5:
                    add("critical", "Successful logon after repeated failures",
                        f"Account '{u}' succeeded (4624) after {by_user[u]} failures - "
                        f"probable account compromise.", 40)

        for eid, (name, sev) in WINDOWS_EVENTS.items():
            if sev in ("high", "critical") and eids.get(eid):
                pts = {"critical": 30, "high": 18}[sev]
                add(sev, f"Event {eid}: {name}", f"Observed {eids[eid]} time(s).", pts)

        rdp = [r for r in success if r.get("logon_type") == "10"]
        ext_rdp = [r for r in rdp if r.get("ip") and not _is_private(r["ip"])]
        if ext_rdp:
            add("critical", "RDP logon from an external IP address",
                f"{len(ext_rdp)} remote-interactive logon(s) from outside the local network: " +
                ", ".join(sorted({r['ip'] for r in ext_rdp})[:4]), 32)

        for r in records:
            eid = r.get("event_id")
            if eid in WINDOWS_EVENTS:
                nm, sv = WINDOWS_EVENTS[eid]
                if sv != "info" and r.get("time"):
                    timeline.append({"ts": r["time"], "source": f"EventID {eid}",
                                     "event": f"{nm}" + (f" | user={r['user']}" if r.get("user") else "") +
                                              (f" | src={r['ip']}" if r.get("ip") else ""),
                                     "severity": sv})

    # ---------- Linux
    elif log_type == "linux":
        fails = [r for r in records if re.search(r"failed password|authentication failure|invalid user",
                                                 r.get("message", ""), re.I)]
        succ = [r for r in records if re.search(r"accepted (password|publickey)",
                                                r.get("message", ""), re.I)]
        by_ip = Counter(r["ip"] for r in fails if r.get("ip"))
        by_user = Counter(r["user"] for r in fails if r.get("user"))
        stats["failed_ssh"] = len(fails)
        stats["successful_ssh"] = len(succ)
        for ip, n in by_ip.most_common(6):
            if n >= 5:
                add("critical" if n >= 20 else "high", "SSH brute-force attack",
                    f"{n} failed SSH authentications from {ip}.", min(20 + n // 2, 40),
                    [r["message"][:140] for r in fails if r.get("ip") == ip][:3])
        invalid = [r for r in fails if "invalid user" in r.get("message", "").lower()]
        if len(invalid) >= 5:
            names = sorted({r.get("user", "") for r in invalid})[:8]
            add("high", "Username enumeration attempt",
                f"{len(invalid)} attempts against non-existent accounts: {', '.join(names)}", 24)
        if by_ip and succ:
            bad_ips = {ip for ip, n in by_ip.items() if n >= 5}
            hit = [r for r in succ if r.get("ip") in bad_ips]
            if hit:
                add("critical", "Successful SSH login from a brute-forcing IP",
                    f"IP(s) {', '.join(sorted({r['ip'] for r in hit}))} eventually authenticated "
                    f"successfully - treat as compromise.", 42)
        for pat, title, sev, pts in [
            (r"sudo:.*COMMAND=", "Privileged sudo command executed", "medium", 8),
            (r"sudo:.*authentication failure", "Failed sudo escalation attempt", "high", 20),
            (r"useradd|adduser", "New user account created", "high", 22),
            (r"usermod.*-G\s*(sudo|wheel|admin|root)", "User added to privileged group", "critical", 30),
            (r"passwd.*password changed", "Password changed", "medium", 10),
            (r"session opened for user root", "Root session opened", "medium", 12),
            (r"POSSIBLE BREAK-IN ATTEMPT", "Reverse-DNS mismatch (break-in attempt)", "high", 20),
            (r"segfault|kernel panic", "Process crash / possible exploitation", "medium", 12),
            (r"iptables.*flush|ufw disable", "Firewall disabled/flushed", "critical", 32),
            (r"rm -rf /|shred |history -c", "Anti-forensics / destructive command", "critical", 34),
            (r"chmod\s+777|chmod\s+\+s", "Dangerous permission change (world-writable/SUID)", "high", 22),
            (r"nc\s+-l|/dev/tcp/", "Possible reverse shell / listener", "critical", 34),
            (r"crontab.*-e|/etc/cron", "Cron modification (persistence)", "high", 20),
            (r"wget\s+http|curl\s+http", "Remote file download on host", "medium", 12),
        ]:
            hits = [r for r in records if re.search(pat, r.get("message", ""), re.I)]
            if hits:
                add(sev, title, f"{len(hits)} occurrence(s).", pts,
                    [h["message"][:140] for h in hits[:3]])
                for h in hits[:20]:
                    timeline.append({"ts": h.get("time", ""), "source": h.get("process", "linux"),
                                     "event": title + ": " + h.get("message", "")[:120],
                                     "severity": sev})

    # ---------- web server
    elif log_type == "webserver":
        stats["requests"] = len(records)
        status_counts = Counter(r["status"] for r in records)
        stats["status_counts"] = [{"status": k, "count": v} for k, v in status_counts.most_common(12)]
        by_ip = Counter(r["ip"] for r in records)
        stats["top_ips"] = [{"ip": k, "requests": v} for k, v in by_ip.most_common(15)]

        attacks = defaultdict(list)
        for r in records:
            blob = f"{r['path']} {r.get('referer','')} {r.get('ua','')}"
            try:
                blob_dec = __import__("urllib.parse", fromlist=["unquote"]).unquote(blob)
            except Exception:  # noqa: BLE001
                blob_dec = blob
            for pat, name, sev in WEB_ATTACKS:
                if re.search(pat, blob_dec, re.I):
                    attacks[name].append(r)
                    break
        for name, rows in attacks.items():
            sev = next(s for p, n, s in WEB_ATTACKS if n == name)
            ips = sorted({r["ip"] for r in rows})[:5]
            add(sev, f"Web attack: {name}",
                f"{len(rows)} request(s) from {len(set(r['ip'] for r in rows))} IP(s): {', '.join(ips)}",
                {"critical": 32, "high": 22, "medium": 12}[sev],
                [f"{r['ip']} {r['method']} {r['path'][:120]}" for r in rows[:4]])
            for r in rows[:20]:
                timeline.append({"ts": r["time"][:20], "source": r["ip"],
                                 "event": f"{name}: {r['method']} {r['path'][:120]}",
                                 "severity": sev})

        # error/scan bursts
        err404 = [r for r in records if r["status"] == 404]
        by_ip404 = Counter(r["ip"] for r in err404)
        for ip, n in by_ip404.most_common(5):
            if n >= 25:
                add("high", "Directory/file enumeration scan",
                    f"{ip} generated {n} 404 responses - automated content discovery.", 24)
        err401 = [r for r in records if r["status"] in (401, 403)]
        by_ip401 = Counter(r["ip"] for r in err401)
        for ip, n in by_ip401.most_common(5):
            if n >= 15:
                add("high", "Repeated unauthorized access attempts",
                    f"{ip} received {n} 401/403 responses.", 22)
        err5xx = sum(v for k, v in status_counts.items() if 500 <= k < 600)
        if err5xx > max(10, len(records) * 0.05):
            add("medium", "Elevated server-error rate",
                f"{err5xx} 5xx responses - possible exploitation attempts or instability.", 12)

        for ip, n in by_ip.most_common(5):
            if n > max(200, len(records) * 0.35):
                add("medium", "Traffic concentration from a single IP",
                    f"{ip} sent {n} requests ({n / max(len(records),1):.0%} of all traffic).", 14)

        uas = Counter((r.get("ua") or "").lower() for r in records)
        for ua, n in uas.most_common(20):
            if any(s in ua for s in SUSPICIOUS_UA) and n >= 3:
                add("high", "Attack-tool User-Agent observed",
                    f"'{ua[:80]}' seen {n} time(s).", 20)
                break

        big = [r for r in records if r["size"] > 10 * 1024 * 1024]
        if big:
            add("high", "Large data transfers (possible exfiltration)",
                f"{len(big)} response(s) exceeded 10 MB. Largest: "
                f"{max(r['size'] for r in big) / 1048576:.1f} MB", 20,
                [f"{r['ip']} {r['path'][:90]} {r['size']}B" for r in big[:3]])

        # successful attack = attack pattern with 200 status
        succ_attacks = [r for name, rows in attacks.items() for r in rows if r["status"] == 200]
        if succ_attacks:
            add("critical", "Attack request returned HTTP 200",
                f"{len(succ_attacks)} malicious request(s) were answered successfully - "
                f"the attack may have WORKED.", 38,
                [f"{r['ip']} {r['path'][:110]}" for r in succ_attacks[:4]])

    # ---------- firewall
    elif log_type == "firewall":
        blocks = [r for r in records if r.get("action") == "BLOCK"]
        allows = [r for r in records if r.get("action") == "ALLOW"]
        stats["blocked"] = len(blocks); stats["allowed"] = len(allows)
        by_src = Counter(r["src"] for r in blocks if r.get("src"))
        stats["top_blocked_sources"] = [{"ip": k, "count": v} for k, v in by_src.most_common(15)]
        for ip, n in by_src.most_common(6):
            if n >= 20:
                add("high" if n < 100 else "critical", "Sustained blocked traffic from one source",
                    f"{n} packets from {ip} were blocked - scanning or DoS attempt.",
                    min(18 + n // 10, 34))
        ports = Counter(r["port"] for r in blocks if r.get("port"))
        distinct_by_ip = defaultdict(set)
        for r in blocks:
            if r.get("src") and r.get("port"):
                distinct_by_ip[r["src"]].add(r["port"])
        for ip, ps in sorted(distinct_by_ip.items(), key=lambda kv: -len(kv[1]))[:5]:
            if len(ps) >= 15:
                add("critical", "Port-scan detected",
                    f"{ip} probed {len(ps)} distinct ports.", 32)
        stats["top_ports"] = [{"port": k, "count": v} for k, v in ports.most_common(15)]
        risky = {"23": "Telnet", "445": "SMB", "3389": "RDP", "1433": "MSSQL",
                 "3306": "MySQL", "5432": "PostgreSQL", "27017": "MongoDB",
                 "6379": "Redis", "9200": "Elasticsearch", "22": "SSH"}
        for p, name in risky.items():
            if ports.get(p, 0) >= 10:
                add("high", f"Repeated probing of {name} (port {p})",
                    f"{ports[p]} attempts - this service is a common intrusion target.", 20)

    # ---------- generic / json
    else:
        joined = "\n".join(raw_lines[:20000])
        for pat, title, sev, pts in [
            (r"\b(error|critical|fatal|panic)\b", "Error-level entries present", "low", 4),
            (r"\bfail(ed|ure)?\b.*\b(login|auth|password)\b", "Authentication failures", "medium", 14),
            (r"\b(denied|unauthorized|forbidden)\b", "Access denials", "medium", 10),
            (r"\b(malware|virus|trojan|ransom|exploit)\b", "Malware-related keywords", "high", 22),
            (r"\b(attack|intrusion|breach|compromise)\b", "Security-incident keywords", "high", 20),
        ]:
            n = len(re.findall(pat, joined, re.I))
            if n:
                add(sev, title, f"{n} matching line(s).", min(pts + n // 20, pts * 2))

    # ---------- universal checks
    joined_all = "\n".join(raw_lines[:30000])
    if re.search(r"(log.{0,10}clear|audit.{0,10}(clear|disabl)|wevtutil\s+cl|"
                 r"truncate.{0,20}\.log|>\s*/var/log/)", joined_all, re.I):
        add("critical", "Log tampering / clearing detected",
            "Commands or events indicating logs were cleared - deliberate anti-forensics.", 38)

    all_ips = Counter(IP_RE.findall(joined_all))
    ext = [(ip, n) for ip, n in all_ips.most_common(200) if not _is_private(ip)
           and not ip.startswith(("0.", "255."))]
    stats["unique_ips"] = len(all_ips)
    stats["external_ips"] = [{"ip": ip, "count": n} for ip, n in ext[:20]]

    # off-hours
    night = 0
    for line in raw_lines[:30000]:
        m = re.search(r"\b(0[0-4]):[0-5]\d:[0-5]\d\b", line)
        if m:
            night += 1
    if night > 20 and night > len(raw_lines) * 0.12:
        add("medium", "Significant off-hours activity",
            f"{night} entries timestamped between 00:00 and 05:00.", 12)

    return findings, timeline, stats


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


# ---------------------------------------------------------------- entry point
def analyze_log(path: str, filename: str = "", use_ai: bool = True) -> dict:
    filename = filename or os.path.basename(path)
    size = os.path.getsize(path)

    if filename.lower().endswith(".evtx"):
        evts = carve_evtx(path)
        records = [{"event_id": e["event_id"], "time": e["time"],
                    "user": e["data"].get("TargetUserName") or e["data"].get("SubjectUserName", ""),
                    "ip": e["data"].get("IpAddress", ""),
                    "logon_type": e["data"].get("LogonType", ""),
                    "raw": e["raw"]} for e in evts]
        log_type, raw_lines = "windows", [e["raw"] for e in evts]
        parsed_count = len(records)
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            raw_lines = fh.read(80 * 1024 * 1024).splitlines()
        sample = "\n".join(raw_lines[:400])
        log_type = detect_log_type(sample, filename)
        if log_type == "windows":
            records = parse_windows(raw_lines)
        elif log_type == "linux":
            records = parse_linux(raw_lines)
        elif log_type == "webserver":
            records = parse_webserver(raw_lines)
        elif log_type == "firewall":
            records = parse_firewall(raw_lines)
        elif log_type == "json":
            records = parse_json_lines(raw_lines)
        else:
            records = [{"raw": l} for l in raw_lines[:5000]]
        parsed_count = len(records)

    findings, timeline, stats = detect_threats(log_type, records, raw_lines)
    score = clamp(sum(f["points"] for f in findings))
    iocs = extract_iocs("\n".join(raw_lines[:8000]))

    result = {
        "filename": filename,
        "size": size,
        "log_type": log_type,
        "log_type_label": {"windows": "Windows Event Log", "linux": "Linux / Syslog",
                           "webserver": "Web Server Access Log", "firewall": "Firewall Log",
                           "json": "JSON Lines", "generic": "Generic Log",
                           "evtx": "Windows EVTX"}.get(log_type, log_type),
        "total_lines": len(raw_lines),
        "parsed_records": parsed_count,
        "risk_score": score,
        "band": ("critical" if score >= 80 else "high" if score >= 55
                 else "medium" if score >= 25 else "low"),
        "findings": sorted(findings, key=lambda f: -f["points"]),
        "timeline": sorted(timeline, key=lambda t: t.get("ts") or "", reverse=True)[:200],
        "stats": stats,
        "iocs": iocs,
        "sample_lines": raw_lines[:60],
    }
    if use_ai:
        result["ai"] = ai_summary(result)
    return result


AI_SYSTEM = ("You are a SOC analyst reviewing log analysis output. Explain what happened, "
             "whether it constitutes an incident, and what the responder should do. "
             "Reference specific evidence. Be concise and practical.")

SCHEMA = """{
  "incident_detected": true|false,
  "severity": "none|low|medium|high|critical",
  "summary": "4-6 sentences explaining the story the logs tell",
  "attack_narrative": "chronological description of the attacker's actions, or 'no attack observed'",
  "affected_assets": ["users, hosts or IPs involved"],
  "immediate_actions": ["what to do in the next hour"],
  "hardening_recommendations": ["how to prevent recurrence"]
}"""


def ai_summary(result: dict) -> dict:
    f = "\n".join(f"- [{x['severity']}] {x['title']}: {x['detail']}"
                  for x in result["findings"][:14]) or "- no findings"
    tl = "\n".join(f"- {t['ts']} [{t['severity']}] {t['event'][:130]}"
                   for t in result["timeline"][:18]) or "- none"
    stats_txt = json.dumps(result["stats"], default=str)[:1200]
    prompt = (
        f"LOG FILE: {result['filename']} ({result['log_type_label']})\n"
        f"Lines: {result['total_lines']}, parsed records: {result['parsed_records']}\n"
        f"Heuristic risk score: {result['risk_score']}/100\n\n"
        f"DETECTIONS:\n{f}\n\nTIMELINE (most recent first):\n{tl}\n\n"
        f"STATISTICS: {stats_txt}\n\nAnalyse this incident."
    )
    res = ollama_client.generate_json(prompt, SCHEMA, system=AI_SYSTEM, temperature=0.2, max_tokens=900)
    if not res["ok"]:
        return {"available": False, "error": res.get("error")}
    d = res["data"]
    return {"available": True,
            "incident_detected": bool(d.get("incident_detected", False)),
            "severity": str(d.get("severity", "medium")),
            "summary": str(d.get("summary", ""))[:1600],
            "attack_narrative": str(d.get("attack_narrative", ""))[:1600],
            "affected_assets": d.get("affected_assets", [])[:12] if isinstance(d.get("affected_assets"), list) else [],
            "immediate_actions": d.get("immediate_actions", [])[:8] if isinstance(d.get("immediate_actions"), list) else [],
            "hardening_recommendations": d.get("hardening_recommendations", [])[:8] if isinstance(d.get("hardening_recommendations"), list) else [],
            "model": res.get("model")}


def explain_event_id(eid: str, use_ai: bool = True) -> dict:
    eid = str(eid).strip()
    known = WINDOWS_EVENTS.get(eid)
    base = {"event_id": eid,
            "name": known[0] if known else "Not in local database",
            "severity": known[1] if known else "unknown",
            "known": bool(known)}
    if use_ai:
        r = ollama_client.generate(
            f"Explain Windows Security Event ID {eid} for a beginner investigator. Cover: "
            f"what triggers it, what the important fields mean, when it is normal versus "
            f"suspicious, and what an analyst should check next. Under 220 words.",
            system="You are a Windows event log expert teaching beginners.",
            temperature=0.2, max_tokens=420)
        base["ai_explanation"] = r["text"] if r["ok"] else None
    return base
