"""
Module 6 -- Memory Forensics (educational, dependency-free).

Volatility needs profiles/symbols and heavy deps. For a beginner-friendly, offline
platform we implement a *carving* approach that works on any RAM dump:

  * Process name carving (PE names, /proc paths, ELF names, common binaries)
  * Network artifact carving (IPs, ports, URLs, socket strings)
  * Loaded module / DLL carving
  * Command-line & PowerShell reconstruction
  * Credential-material detection (hashes, tokens, keys, LSASS artefacts)
  * Injected-code indicators (RWX strings, shellcode stubs, hollowing markers)
  * Malware-family string signatures
  * Registry/Persistence key carving
  * Entropy profiling of the dump

This is explicitly a *learning* tool, and the UI says so.
"""
from __future__ import annotations

import os
import re
from collections import Counter, defaultdict

from config import Config
from core import ollama_client
from core.utils import clamp, extract_iocs, extract_strings, human_size, shannon_entropy

# ------------------------------------------------------------ knowledge base
SYSTEM_PROCS = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "lsm.exe", "spoolsv.exe", "explorer.exe", "taskhost.exe",
    "taskhostw.exe", "dwm.exe", "conhost.exe", "sihost.exe", "runtimebroker.exe",
    "searchindexer.exe", "fontdrvhost.exe", "ctfmon.exe", "audiodg.exe", "wmiprvse.exe",
    "systemd", "init", "kthreadd", "sshd", "bash", "cron", "dbus-daemon", "networkd",
}
EXPECTED_PARENT = {
    "lsass.exe": "wininit.exe", "services.exe": "wininit.exe", "svchost.exe": "services.exe",
    "csrss.exe": "smss.exe", "winlogon.exe": "smss.exe", "explorer.exe": "userinit.exe",
    "spoolsv.exe": "services.exe", "taskhostw.exe": "svchost.exe",
}
LOLBINS = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "cmstp.exe", "forfiles.exe", "pcalua.exe", "wmic.exe",
    "at.exe", "schtasks.exe", "net.exe", "net1.exe", "netsh.exe", "sc.exe", "reg.exe",
    "vssadmin.exe", "bcdedit.exe", "wbadmin.exe", "cipher.exe", "esentutl.exe",
}
HACKTOOLS = {
    "mimikatz.exe": ("critical", "Credential dumping tool (Mimikatz)"),
    "procdump.exe": ("high", "Can dump LSASS memory for offline credential theft"),
    "psexec.exe": ("high", "Remote execution / lateral movement"),
    "nc.exe": ("critical", "Netcat - reverse shell / data transfer"),
    "ncat.exe": ("critical", "Ncat - reverse shell"),
    "nmap.exe": ("medium", "Network scanner"),
    "wce.exe": ("critical", "Windows Credentials Editor"),
    "pwdump.exe": ("critical", "SAM hash dumper"),
    "lazagne.exe": ("critical", "Multi-application credential recovery"),
    "rubeus.exe": ("critical", "Kerberos ticket abuse"),
    "sharphound.exe": ("high", "Active Directory reconnaissance"),
    "bloodhound.exe": ("high", "Active Directory attack-path mapping"),
    "cobaltstrike": ("critical", "Cobalt Strike C2 framework"),
    "meterpreter": ("critical", "Metasploit Meterpreter payload"),
    "beacon.dll": ("critical", "Cobalt Strike beacon"),
    "empire": ("critical", "PowerShell Empire C2"),
    "xmrig": ("high", "Monero cryptocurrency miner"),
    "anydesk.exe": ("medium", "Remote access tool (often abused in scams)"),
    "teamviewer.exe": ("medium", "Remote access tool (often abused in scams)"),
    "ultraviewer.exe": ("high", "Remote access tool heavily used in tech-support fraud"),
    "rustdesk.exe": ("medium", "Remote access tool"),
    "quickassist.exe": ("medium", "Windows Quick Assist - abused in vishing scams"),
}
MALWARE_STRINGS = [
    (rb"cobaltstrike", "critical", "Cobalt Strike C2 framework"),
    (rb"meterpreter", "critical", "Metasploit Meterpreter"),
    (rb"beacon\.x64\.dll|beacon\.dll", "critical", "Cobalt Strike beacon module"),
    (rb"mimikatz|sekurlsa|kerberos::", "critical", "Mimikatz credential dumping"),
    (rb"invoke-mimikatz|invoke-shellcode", "critical", "PowerSploit offensive module"),
    (rb"powershell.*-enc\s+[a-z0-9+/=]{40,}", "critical", "Encoded PowerShell command"),
    (rb"downloadstring|downloadfile|net\.webclient", "high", "In-memory download cradle"),
    (rb"vssadmin\s+delete\s+shadows", "critical", "Shadow copy deletion (ransomware)"),
    (rb"your files have been encrypted|readme.*decrypt", "critical", "Ransomware note in memory"),
    (rb"\.onion", "high", "Tor hidden service reference"),
    (rb"stratum\+tcp://", "high", "Cryptominer pool connection"),
    (rb"virtualallocex|writeprocessmemory|createremotethread", "critical",
     "Process injection API sequence"),
    (rb"reflectiveloader|reflective_dll", "critical", "Reflective DLL injection"),
    (rb"\\\\\.\\pipe\\(msagent|postex|status)", "critical", "Known C2 named pipe"),
    (rb"lsass\.dmp|lsass_dump", "critical", "LSASS memory dump artefact"),
    (rb"sam\\domains\\account", "critical", "SAM hive credential access"),
    (rb"AAAAAAAA{20,}|\x90{40,}", "high", "NOP sled / shellcode padding"),
    (rb"eicar-standard-antivirus-test-file", "medium", "EICAR test signature"),
    (rb"telegram\.org/bot\d+:", "high", "Telegram bot exfiltration channel"),
    (rb"discord\.com/api/webhooks", "high", "Discord webhook exfiltration"),
]
CRED_PATTERNS = [
    (rb"\b[a-f0-9]{32}:[a-f0-9]{32}\b", "critical", "NTLM hash pair (LM:NT)"),
    (rb"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", "high", "bcrypt hash"),
    (rb"\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}", "high", "SHA-512 crypt (/etc/shadow)"),
    (rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "high", "JWT token"),
    (rb"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical", "Private key material"),
    (rb"AKIA[0-9A-Z]{16}", "critical", "AWS access key ID"),
    (rb"gh[pousr]_[A-Za-z0-9]{36}", "critical", "GitHub token"),
    (rb"xox[baprs]-[A-Za-z0-9-]{10,}", "high", "Slack token"),
    (rb"password\s*[:=]\s*\S{4,40}", "high", "Plaintext password string"),
    (rb"passwd\s*[:=]\s*\S{4,40}", "high", "Plaintext password string"),
    (rb"connectionstring\s*=.*password=", "critical", "DB connection string with password"),
]
PERSIST_PATTERNS = [
    (rb"software\\microsoft\\windows\\currentversion\\run", "high", "Run-key persistence"),
    (rb"software\\microsoft\\windows\\currentversion\\runonce", "high", "RunOnce persistence"),
    (rb"currentcontrolset\\services\\", "medium", "Service registration"),
    (rb"\\startup\\", "medium", "Startup folder persistence"),
    (rb"schtasks\s+/create", "high", "Scheduled task creation"),
    (rb"wmi.*__eventfilter|commandlineeventconsumer", "critical", "WMI event subscription persistence"),
    (rb"/etc/cron|crontab -", "medium", "Linux cron persistence"),
    (rb"\.bashrc|\.bash_profile|/etc/rc\.local", "medium", "Linux shell persistence"),
    (rb"systemctl enable|/etc/systemd/system/", "medium", "systemd service persistence"),
    (rb"ld\.so\.preload", "critical", "Linux LD_PRELOAD rootkit persistence"),
]

PROC_RE = re.compile(rb"\b([A-Za-z0-9_\-\.]{3,40}\.exe)\b", re.I)
UNIX_PROC_RE = re.compile(rb"/(?:usr/)?(?:s?bin|local/bin)/([a-z0-9_\-\.]{2,30})\b")
DLL_RE = re.compile(rb"\b([A-Za-z0-9_\-\.]{3,40}\.dll)\b", re.I)
CMD_RE = re.compile(
    rb"((?:[A-Za-z]:\\|/)[^\x00\n\r]{4,200}?\.(?:exe|sh|py|ps1)[^\x00\n\r]{0,200})", re.I)
PSCMD_RE = re.compile(rb"(powershell(?:\.exe)?[^\x00\n\r]{5,300})", re.I)
IPPORT_RE = re.compile(rb"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b")
SUSPICIOUS_PORTS = {4444: "Metasploit default", 4445: "Metasploit alt", 1337: "Common backdoor",
                    31337: "Elite/backdoor", 8080: "HTTP proxy/C2", 8443: "HTTPS alt C2",
                    50050: "Cobalt Strike team server", 6667: "IRC botnet",
                    3389: "RDP", 5900: "VNC", 23: "Telnet (insecure)", 445: "SMB",
                    1080: "SOCKS proxy", 9001: "Tor ORPort", 9050: "Tor SOCKS"}


# ------------------------------------------------------------ analysis
def analyze_dump(path: str, use_ai: bool = True, max_bytes: int = 400 * 1024 * 1024) -> dict:
    size = os.path.getsize(path)
    read_n = min(size, max_bytes)
    chunks, offset = [], 0
    with open(path, "rb") as fh:
        while offset < read_n:
            c = fh.read(min(8 * 1024 * 1024, read_n - offset))
            if not c:
                break
            chunks.append(c)
            offset += len(c)
    data = b"".join(chunks)
    del chunks

    low = data.lower()
    findings = []

    def add(sev, title, detail, pts):
        findings.append({"severity": sev, "title": title, "detail": detail, "points": pts})

    # ---------- processes
    proc_counter = Counter()
    for m in PROC_RE.finditer(data):
        proc_counter[m.group(1).decode("ascii", "ignore").lower()] += 1
    for m in UNIX_PROC_RE.finditer(data):
        proc_counter[m.group(1).decode("ascii", "ignore").lower()] += 1

    processes = []
    for name, count in proc_counter.most_common(220):
        entry = {"name": name, "occurrences": count, "flags": [], "severity": "info"}
        if name in HACKTOOLS:
            sev, why = HACKTOOLS[name]
            entry["flags"].append(why); entry["severity"] = sev
        elif name in LOLBINS:
            entry["flags"].append("Living-off-the-land binary (legitimate but heavily abused)")
            entry["severity"] = "medium"
        elif name in SYSTEM_PROCS:
            entry["flags"].append("Standard system process"); entry["severity"] = "info"
        # masquerading checks
        base = name.rsplit(".", 1)[0]
        for sysp in ("svchost", "csrss", "lsass", "explorer", "services", "winlogon"):
            if base != sysp and (base.startswith(sysp) or _looks_like(base, sysp)):
                entry["flags"].append(f"Possible masquerade of '{sysp}.exe'")
                entry["severity"] = "critical"
                break
        if re.fullmatch(r"[a-z0-9]{8,20}", base) and shannon_entropy(base) > 3.3:
            entry["flags"].append("Random-looking name (dropper/packed sample pattern)")
            entry["severity"] = "high" if entry["severity"] == "info" else entry["severity"]
        processes.append(entry)

    hack_found = [p for p in processes if p["severity"] == "critical" and p["flags"]]
    if hack_found:
        add("critical", "Attack tooling present in memory",
            ", ".join(f"{p['name']} ({p['flags'][0]})" for p in hack_found[:5]), 40)
    lol_found = [p for p in processes if p["severity"] == "medium" and "Living-off" in "".join(p["flags"])]
    if len(lol_found) >= 4:
        add("high", "Many living-off-the-land binaries referenced",
            ", ".join(p["name"] for p in lol_found[:8]), 20)

    # ---------- modules
    dll_counter = Counter(m.group(1).decode("ascii", "ignore").lower()
                          for m in DLL_RE.finditer(data))
    suspicious_dlls = []
    for d, c in dll_counter.most_common(200):
        risky = None
        if d in ("wininet.dll", "winhttp.dll", "ws2_32.dll"):
            risky = "Networking capability"
        if d in ("crypt32.dll", "bcrypt.dll", "advapi32.dll"):
            risky = risky or "Crypto/credential API"
        if d in ("ntdll.dll",) and c > 200:
            risky = "Very heavy direct ntdll usage (syscall evasion possible)"
        if re.fullmatch(r"[a-z0-9]{8,}\.dll", d) and shannon_entropy(d) > 3.4:
            risky = "Random-looking module name"
        if risky:
            suspicious_dlls.append({"module": d, "occurrences": c, "note": risky})

    # ---------- network
    conns = defaultdict(int)
    for m in IPPORT_RE.finditer(data):
        ip = m.group(1).decode(); port = int(m.group(2))
        if port == 0 or port > 65535:
            continue
        if ip.startswith(("0.", "255.")) or ip == "127.0.0.1":
            continue
        conns[(ip, port)] += 1
    connections = []
    for (ip, port), n in sorted(conns.items(), key=lambda kv: -kv[1])[:120]:
        note, sev = "", "info"
        if port in SUSPICIOUS_PORTS:
            note = SUSPICIOUS_PORTS[port]
            sev = "critical" if port in (4444, 4445, 1337, 31337, 50050, 6667) else "medium"
        private = ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                                 "172.19.", "172.2", "172.30.", "172.31.", "169.254."))
        connections.append({"ip": ip, "port": port, "count": n, "note": note,
                            "severity": sev, "scope": "internal" if private else "external"})
    bad_conns = [c for c in connections if c["severity"] == "critical"]
    if bad_conns:
        add("critical", "Connections on known C2/backdoor ports",
            ", ".join(f"{c['ip']}:{c['port']} ({c['note']})" for c in bad_conns[:5]), 35)

    # ---------- command lines
    cmdlines = []
    for m in list(CMD_RE.finditer(data))[:4000]:
        s = m.group(1).decode("utf-8", "ignore").strip()
        if 8 < len(s) < 260 and s.count(" ") < 30:
            cmdlines.append(s)
    ps_cmds = []
    for m in list(PSCMD_RE.finditer(data))[:2000]:
        s = m.group(1).decode("utf-8", "ignore").strip()
        if len(s) > 20:
            ps_cmds.append(s[:300])
    cmdlines = list(dict.fromkeys(cmdlines))[:120]
    ps_cmds = list(dict.fromkeys(ps_cmds))[:60]

    evil_cmds = [c for c in cmdlines + ps_cmds if re.search(
        r"(-enc\s|-encodedcommand|downloadstring|iex\s*\(|invoke-expression|"
        r"vssadmin|bypass|hidden|certutil.*-decode|bitsadmin|regsvr32.*scrobj|"
        r"nc\s+-e|/bin/sh\s+-i|base64\s+-d)", c, re.I)]
    if evil_cmds:
        add("critical", "Malicious command lines recovered",
            f"{len(evil_cmds)} command(s) containing attack patterns.", 34)

    # ---------- signature sweep
    sig_hits = []
    for pat, sev, desc in MALWARE_STRINGS:
        n = len(pat.findall(low)) if hasattr(pat, "findall") else len(re.findall(pat, low))
        if n:
            sig_hits.append({"signature": desc, "severity": sev, "hits": n})
            add(sev, f"Memory signature: {desc}", f"{n} occurrence(s) in the dump.",
                {"critical": 30, "high": 20, "medium": 10}.get(sev, 8))

    # ---------- credentials
    cred_hits = []
    for pat, sev, desc in CRED_PATTERNS:
        found = re.findall(pat, data, re.I)
        if found:
            cred_hits.append({"type": desc, "severity": sev, "count": len(found),
                              "sample": _redact(found[0])})
            add(sev, f"Credential material: {desc}",
                f"{len(found)} instance(s) recoverable from memory.",
                28 if sev == "critical" else 18)

    # ---------- persistence
    persist_hits = []
    for pat, sev, desc in PERSIST_PATTERNS:
        n = len(re.findall(pat, low))
        if n:
            persist_hits.append({"mechanism": desc, "severity": sev, "hits": n})
            add(sev, f"Persistence artefact: {desc}", f"{n} reference(s).",
                {"critical": 26, "high": 18, "medium": 10}.get(sev, 6))

    # ---------- injection indicators
    inject = []
    for pat, desc in [
        (rb"virtualallocex", "VirtualAllocEx (remote memory allocation)"),
        (rb"writeprocessmemory", "WriteProcessMemory (remote write)"),
        (rb"createremotethread", "CreateRemoteThread (remote execution)"),
        (rb"ntunmapviewofsection|zwunmapviewofsection", "Process hollowing primitive"),
        (rb"setthreadcontext", "SetThreadContext (hollowing/hijack)"),
        (rb"queueuserapc", "APC injection"),
        (rb"rtlcreateuserthread", "RtlCreateUserThread injection"),
        (rb"page_execute_readwrite|pagerwx", "RWX memory permission"),
    ]:
        n = len(re.findall(pat, low))
        if n:
            inject.append({"indicator": desc, "hits": n})
    if len(inject) >= 3:
        add("critical", "Code-injection API chain detected",
            ", ".join(i["indicator"] for i in inject[:5]), 32)
    elif inject:
        add("high", "Code-injection related APIs present",
            ", ".join(i["indicator"] for i in inject), 16)

    # ---------- IOCs & entropy
    sample_text = "\n".join(extract_strings(data[: 64 * 1024 * 1024], min_len=7,
                                            limit=Config.MAX_STRINGS_EXTRACT)[:80000])
    iocs = extract_iocs(sample_text)
    if iocs["bitcoin"]:
        add("critical", "Cryptocurrency wallet in memory",
            "Addresses: " + ", ".join(iocs["bitcoin"][:2]), 24)
    ent = shannon_entropy(data[: 16 * 1024 * 1024])

    score = clamp(sum(f["points"] for f in findings))
    result = {
        "file_size": size,
        "file_size_human": human_size(size),
        "analyzed_bytes": len(data),
        "analyzed_human": human_size(len(data)),
        "truncated": size > len(data),
        "entropy": ent,
        "risk_score": score,
        "band": ("critical" if score >= 80 else "high" if score >= 55
                 else "medium" if score >= 25 else "low"),
        "findings": sorted(findings, key=lambda f: -f["points"]),
        "processes": processes[:120],
        "suspicious_processes": [p for p in processes if p["severity"] in ("critical", "high")][:40],
        "modules": suspicious_dlls[:40],
        "all_modules_count": len(dll_counter),
        "connections": connections,
        "external_connections": [c for c in connections if c["scope"] == "external"][:60],
        "command_lines": cmdlines,
        "powershell_commands": ps_cmds,
        "malicious_commands": evil_cmds[:40],
        "signatures": sig_hits,
        "credentials": cred_hits,
        "persistence": persist_hits,
        "injection_indicators": inject,
        "iocs": iocs,
        "note": ("This is a string/pattern-carving analyzer built for education. It works on any "
                 "RAM dump without kernel symbol profiles, but it does NOT rebuild the kernel "
                 "process list like Volatility. Treat results as investigative leads."),
    }
    if use_ai:
        result["ai"] = ai_summary(result)
    return result


def _looks_like(candidate: str, target: str) -> bool:
    """Detect svch0st / lsasss / explore style masquerades."""
    if abs(len(candidate) - len(target)) > 2 or candidate == target:
        return False
    subs = {"0": "o", "1": "l", "5": "s", "rn": "m", "vv": "w", "l": "i"}
    norm = candidate
    for a, b in subs.items():
        norm = norm.replace(a, b)
    if norm == target:
        return True
    diff = sum(1 for a, b in zip(candidate.ljust(len(target)), target.ljust(len(candidate))) if a != b)
    return diff == 1 and len(candidate) >= 5


def _redact(b: bytes) -> str:
    s = b.decode("utf-8", "ignore") if isinstance(b, bytes) else str(b)
    if len(s) <= 12:
        return s[:4] + "…"
    return s[:10] + "…[REDACTED]…" + s[-4:]


AI_SYSTEM = ("You are a memory-forensics analyst. You receive carved artefacts from a RAM dump. "
             "Identify likely malicious activity, map it to attacker techniques (MITRE ATT&CK "
             "names where obvious), and recommend next investigative steps. Be measured: carving "
             "produces false positives, so state confidence.")

SCHEMA = """{
  "assessment": "clean|suspicious|compromised",
  "confidence": 0-100,
  "summary": "4-6 sentences describing what happened on this machine",
  "attack_techniques": ["MITRE-style technique names"],
  "key_artefacts": ["the most important evidence items"],
  "next_steps": ["concrete investigative actions"],
  "containment": ["immediate response actions"]
}"""


def ai_summary(result: dict) -> dict:
    procs = ", ".join(f"{p['name']}" for p in result["suspicious_processes"][:15]) or "none flagged"
    sigs = "; ".join(f"{s['signature']} x{s['hits']}" for s in result["signatures"][:10]) or "none"
    conns = ", ".join(f"{c['ip']}:{c['port']}{' [' + c['note'] + ']' if c['note'] else ''}"
                      for c in result["connections"][:12]) or "none"
    cmds = "\n".join(f"- {c[:150]}" for c in result["malicious_commands"][:10]) or "- none"
    creds = "; ".join(f"{c['type']} x{c['count']}" for c in result["credentials"][:8]) or "none"
    pers = "; ".join(f"{p['mechanism']}" for p in result["persistence"][:8]) or "none"
    prompt = (
        f"MEMORY DUMP: {result['file_size_human']} (analyzed {result['analyzed_human']})\n"
        f"Heuristic score: {result['risk_score']}/100\n\n"
        f"SUSPICIOUS PROCESSES: {procs}\n\nSIGNATURES: {sigs}\n\n"
        f"NETWORK: {conns}\n\nSUSPECT COMMANDS:\n{cmds}\n\n"
        f"CREDENTIAL MATERIAL: {creds}\n\nPERSISTENCE: {pers}\n\n"
        f"INJECTION INDICATORS: {', '.join(i['indicator'] for i in result['injection_indicators'][:6]) or 'none'}\n\n"
        "Give your memory forensics assessment."
    )
    res = ollama_client.generate_json(prompt, SCHEMA, system=AI_SYSTEM, temperature=0.2, max_tokens=900)
    if not res["ok"]:
        return {"available": False, "error": res.get("error")}
    d = res["data"]
    return {"available": True,
            "assessment": str(d.get("assessment", "suspicious")),
            "confidence": clamp(int(float(d.get("confidence", 60) or 60))),
            "summary": str(d.get("summary", ""))[:1600],
            "attack_techniques": d.get("attack_techniques", [])[:10] if isinstance(d.get("attack_techniques"), list) else [],
            "key_artefacts": d.get("key_artefacts", [])[:10] if isinstance(d.get("key_artefacts"), list) else [],
            "next_steps": d.get("next_steps", [])[:8] if isinstance(d.get("next_steps"), list) else [],
            "containment": d.get("containment", [])[:6] if isinstance(d.get("containment"), list) else [],
            "model": res.get("model")}
