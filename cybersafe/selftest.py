#!/usr/bin/env python3
"""
Self-test for the AI Cyber Safety & Digital Forensics Platform.

    python selftest.py

Exercises every detection engine with known-good and known-bad inputs and
asserts the results land in the expected range. Runs completely offline and
does not require Ollama (AI layers are skipped).
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS, FAIL = 0, 0
FAILURES = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  \033[92mPASS\033[0m  {name}")
    else:
        FAIL += 1
        FAILURES.append(f"{name} :: {detail}")
        print(f"  \033[91mFAIL\033[0m  {name}   {detail}")


def section(t):
    print(f"\n\033[1m{t}\033[0m")


# ============================================================ phishing
def test_phishing():
    section("Module 1 — Phishing Detector")
    from modules import phishing as ph

    r = ph.analyze("http://amazon.in.delivery-update.secure-login.xyz/track", "url", use_ai=False)
    check("malicious URL scores high", r["risk_score"] >= 70, f"got {r['risk_score']}")
    check("brand impersonation detected",
          any("impersonation" in f["title"].lower() for f in r["findings"]))

    r = ph.analyze("https://www.google.com/search?q=test", "url", use_ai=False)
    check("safe URL scores low", r["risk_score"] < 25, f"got {r['risk_score']}")

    r = ph.analyze("https://www.hdfcbank.com/personal", "url", use_ai=False)
    check("known-good bank domain scores low", r["risk_score"] < 25, f"got {r['risk_score']}")

    r = ph.analyze("https://paypa1.com/login", "url", use_ai=False)
    check("typosquat detected", r["risk_score"] >= 50, f"got {r['risk_score']}")

    r = ph.analyze("http://apple.com@evil-site.tk/login", "url", use_ai=False)
    check("@ userinfo obfuscation detected",
          any("@" in f["title"] or "obfusc" in f["title"].lower() for f in r["findings"]))

    r = ph.analyze("http://192.0.2.55/secure/login/verify.php", "url", use_ai=False)
    check("raw IP host detected",
          any("IP address" in f["title"] for f in r["findings"]))

    sms = ("URGENT: Your SBI account is BLOCKED. Update KYC: http://bit.ly/sbi-x "
           "Share OTP with our executive immediately.")
    r = ph.analyze(sms, "sms", use_ai=False)
    check("smishing scores critical", r["risk_score"] >= 80, f"got {r['risk_score']}")
    check("OTP request flagged",
          any("secret data" in f["title"].lower() or "otp" in f["title"].lower()
              for f in r["findings"]))

    email = ("From: \"HDFC Bank\" <alerts@hdfcbank.com>\nReply-To: thief@gmail.com\n"
             "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
             "Subject: URGENT account suspended\n\nDear Customer, verify your account "
             "immediately or it will be closed. Enter your CVV and OTP here: "
             "http://hdfc-verify.tk/login")
    r = ph.analyze(email, "email", use_ai=False)
    check("spoofed email scores critical", r["risk_score"] >= 80, f"got {r['risk_score']}")
    check("SPF/DKIM failure detected",
          any("FAILED" in f["title"] or "mismatch" in f["title"].lower() for f in r["findings"]))

    r = ph.analyze("Hi, are we still meeting at 3pm today? Thanks.", "sms", use_ai=False)
    check("benign SMS scores low", r["risk_score"] < 25, f"got {r['risk_score']}")

    # ---- India-specific scam archetypes (regression: these all used to score <25)
    scams = [
        ("parcel/customs", "Your parcel is held at customs. Pay Rs 45 http://bit.ly/parcel-in"),
        ("lottery/KBC", "Congratulations! You won KBC lottery 25 lakh. Send Aadhaar to claim"),
        ("new number", "Hi mom, this is my new number, please save it and send money urgently"),
        ("electricity", "Dear customer your electricity will be disconnected tonight. Call 9876543210"),
        ("account block", "Your SBI YONO account will be deactivated today. Update PAN at http://sbi-yono.tk"),
        ("digital arrest", "We are from Mumbai Cyber Crime. You are under digital arrest. Join video call now"),
        ("remote access", "Your KYC is expired. Download AnyDesk and share screen with our executive"),
        ("QR receive", "Scan this QR code to receive your Rs 5000 refund immediately"),
        ("task job", "Work from home! Earn Rs 3000 per day. Just like videos. Pay Rs 999 registration"),
        ("loan app", "Instant loan approved without CIBIL! No documents needed. Click now"),
        ("army buyer", "I am Major Sharma, posting transfer urgent, I will pay advance for your bike"),
        ("OTP handover", "Please share the OTP you received, I am calling from bank"),
        ("pending refund", "Your refund of Rs 5000 is pending. Click http://refund-claim.tk to approve"),
    ]
    missed = [n for n, t in scams if ph.analyze(t, "sms", use_ai=False)["risk_score"] < 55]
    check(f"all {len(scams)} Indian scam archetypes detected", not missed, f"missed: {missed}")

    # ---- legitimate messages must NOT be flagged
    ham = [
        ("bank OTP alert", "482910 is your OTP for HDFC NetBanking. Never share this OTP with anyone."),
        ("OTP do-not-share", "Your OTP for login is 482910. Valid for 10 minutes. Do not share with anyone."),
        ("debit alert", "Dear Customer, your HDFC Bank a/c XX4421 is debited Rs.2,450.00. Not you? Call 18002586161"),
        ("delivery", "Your Amazon order #408-2231 has been delivered. Rate your experience in the app."),
        ("bill reminder", "Reminder: Your electricity bill of Rs 1,240 is due on 15-Oct. Pay via the official MSEDCL app."),
        ("food order", "Swiggy: Your order from Haldirams is on the way. Arriving in 12 mins."),
        ("completed refund", "Flipkart: Your refund of Rs 899 has been credited to your original payment method."),
        ("train PNR", "Your train PNR 2451887744 is CONFIRMED, coach B4 seat 32. Happy journey - IRCTC"),
    ]
    fps = [n for n, t in ham if ph.analyze(t, "sms", use_ai=False)["risk_score"] >= 55]
    check("no false positives on legitimate SMS", not fps, f"flagged: {fps}")

    check("archetypes exposed in result",
          "Parcel / customs delivery scam" in
          ph.analyze(scams[0][1], "sms", use_ai=False)["stats"]["scam_archetypes"])


# ============================================================ password
def test_password():
    section("Module 2 — Password Analyzer")
    from modules import password as pw

    weak = pw.analyze("123456", use_ai=False)
    check("'123456' rated very weak", weak["score"] < 15, f"got {weak['score']}")
    check("common password flagged", weak["breach"]["found"])

    strong = pw.analyze("copper-violin-42-monsoon-Tide", use_ai=False)
    check("long passphrase rated strong", strong["score"] >= 75, f"got {strong['score']}")
    # Diceware maths: ~12.9 bits per word, so a 5-component phrase lands near 60 bits.
    check("passphrase entropy is realistic (not inflated)",
          50 <= strong["entropy_bits"] <= 90, f"got {strong['entropy_bits']}")
    check("passphrase recognised as such", pw.is_passphrase("copper-violin-42-monsoon-Tide")[0])
    check("passphrase not penalised for dictionary words",
          not any("dictionary" in f["title"].lower() and f["points"] > 0
                  for f in strong["findings"]))
    check("short 3-word phrase correctly rated weak",
          pw.analyze("sage-pine-reef", use_ai=False)["score"] < 45)

    tmpl = pw.analyze("Summer2026!", use_ai=False)
    check("Word+digits template penalised", tmpl["score"] < 40, f"got {tmpl['score']}")

    kb = pw.analyze("qwerty123", use_ai=False)
    check("keyboard walk detected",
          any("keyboard" in f["title"].lower() or "sequential" in f["title"].lower()
              for f in kb["findings"]))

    ctx = pw.analyze("rahul1998secure", use_ai=False, context="rahul 1998")
    check("personal info detected",
          any("personal" in f["title"].lower() for f in ctx["findings"]))

    g = pw.generate_password(20)
    check("generator length correct", len(g) == 20, f"got {len(g)}")
    check("generated password is strong", pw.analyze(g, use_ai=False)["score"] >= 90)

    p = pw.generate_passphrase(5)
    check("passphrase generator works", p.count("-") >= 5, p)
    check("generated passphrase is strong", pw.analyze(p, use_ai=False)["score"] >= 90)

    check("crack times present", len(strong["crack_times"]) == 5)
    check("password never returned in plain", "password" not in strong)


# ============================================================ malware
def test_malware():
    section("Module 3 — Malware Analyzer")
    from modules import malware as mw
    import struct

    eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    fd, p = tempfile.mkstemp(suffix=".txt")
    os.write(fd, eicar.encode())
    os.close(fd)
    r = mw.analyze_file(p, "eicar.txt", use_ai=False)
    check("EICAR detected as dangerous", r["risk_score"] >= 80, f"got {r['risk_score']}")
    check("EICAR md5 correct", r["hashes"]["md5"] == "44d88612fea8a8f36de82e1278abb02f")
    check("known-bad hash reported once",
          sum(1 for f in r["findings"] if "Known-malicious hash" in f["title"]) == 1)
    os.unlink(p)

    data = bytearray(b"MZ" + b"\x90" * 0x3a)
    data += (0x80).to_bytes(4, "little")
    data += b"\x00" * (0x80 - len(data))
    data += b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14c, 3, 1700000000, 0, 0, 224, 0x102)
    data += b"\x0b\x01" + b"\x00" * 222
    data += (b"VirtualAllocEx WriteProcessMemory CreateRemoteThread "
             b"vssadmin delete shadows powershell -enc AAAA mimikatz sekurlsa "
             b"http://evil-c2.xyz/gate.php 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") * 3
    fd, p = tempfile.mkstemp(suffix=".exe")
    os.write(fd, bytes(data))
    os.close(fd)
    r = mw.analyze_file(p, "invoice.pdf.exe", use_ai=False)
    check("malicious PE scores critical", r["risk_score"] >= 80, f"got {r['risk_score']}")
    check("PE header parsed", r["pe"]["is_pe"])
    check("PE machine identified", "x86" in str(r["pe"].get("machine", "")))
    check("double extension detected",
          any("Double file extension" in f["title"] for f in r["findings"]))
    check("dangerous imports found", len(r["imports"]) >= 3, f"got {len(r['imports'])}")
    check("signatures matched", len(r["signatures"]) >= 3, f"got {len(r['signatures'])}")
    check("bitcoin IOC extracted", len(r["iocs"]["bitcoin"]) >= 1)
    os.unlink(p)

    fd, p = tempfile.mkstemp(suffix=".txt")
    os.write(fd, b"Just some ordinary notes about the weather.\n" * 60)
    os.close(fd)
    r = mw.analyze_file(p, "notes.txt", use_ai=False)
    check("clean file scores low", r["risk_score"] < 25, f"got {r['risk_score']}")
    os.unlink(p)

    s = mw.analyze_script("$a='SQBFAFgA'; IEX ([Text.Encoding]::Unicode.GetString("
                          "[Convert]::FromBase64String($a)))")
    check("obfuscated script detected", len(s["findings"]) >= 1)


# ============================================================ evidence
def test_evidence():
    section("Module 4 — Evidence & Chain of Custody")
    from core.database import init_db
    from modules import evidence as ev, reports

    init_db()
    c = ev.create_case("Selftest case", "automated", "selftest", "high", "Other")
    check("case created with number", c["case_number"].startswith("CASE-"))

    fd, p = tempfile.mkstemp()
    os.write(fd, b"evidence content http://bad.example.com 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    os.close(fd)
    e = ev.add_evidence(c["id"], existing_path=p, name="Test artefact",
                        evidence_type="document", collected_by="selftest")
    os.unlink(p)
    check("evidence hashed at acquisition", len(e["sha256"]) == 64)
    check("custody opened on acquisition", len(e["custody"]) >= 1)

    v = ev.verify_evidence(e["id"], "selftest")
    check("integrity verifies intact", v["ok"] and v["status"] == "intact")

    with open(e["stored_path"], "ab") as f:
        f.write(b"TAMPER")
    v = ev.verify_evidence(e["id"], "selftest")
    check("tampering detected", (not v["ok"]) and v["status"] == "mismatch")
    check("mismatch written to custody",
          any(x["integrity"] == "mismatch" for x in ev.get_evidence(e["id"])["custody"]))

    h = ev.harvest_iocs_from_evidence(e["id"])
    check("IOCs harvested from evidence", h.get("registered", 0) >= 2, str(h))

    rep = reports.case_report(c["id"], include_ai=False)
    check("HTML report generated", os.path.exists(rep["path"]))
    check("report has all 9 sections", rep["html"].count("<h2>") >= 9,
          f"got {rep['html'].count('<h2>')}")
    check("report shows integrity failure", "INTEGRITY FAILURE" in rep["html"])

    md = reports.case_markdown(c["id"])
    check("markdown report generated", "Chain of Custody" in md)

    ev.delete_case(c["id"])
    check("case deleted cleanly", ev.get_case(c["id"]) is None)


# ============================================================ browser
def test_browser():
    section("Module 5 — Browser Forensics")
    from modules import browser_forensics as bf

    p = tempfile.mktemp(suffix=".db")
    conn = sqlite3.connect(p)
    conn.executescript("""
      CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INT,
        typed_count INT,last_visit_time INT);
      CREATE TABLE visits(id INTEGER PRIMARY KEY,url INT,visit_time INT);
      CREATE TABLE downloads(id INTEGER PRIMARY KEY,target_path TEXT,tab_url TEXT,
        total_bytes INT,start_time INT,danger_type INT);
    """)

    def wk(d):
        return int((d - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1e6)

    b = datetime(2026, 3, 15, 2, 30, tzinfo=timezone.utc)
    conn.execute("INSERT INTO urls VALUES(1,?,?,3,1,?)",
                 ("http://free-crack-download.xyz/keygen", "CRACK", wk(b)))
    conn.execute("INSERT INTO urls VALUES(2,?,?,1,0,?)",
                 ("https://amazon-security-login.xyz/verify", "Verify",
                  wk(b + timedelta(minutes=3))))
    conn.execute("INSERT INTO urls VALUES(3,?,?,50,20,?)",
                 ("https://www.google.com/", "Google", wk(b + timedelta(minutes=10))))
    conn.execute("INSERT INTO downloads VALUES(1,?,?,5242880,?,0)",
                 ("C:\\dl\\keygen.exe", "http://free-crack-download.xyz/keygen",
                  wk(b + timedelta(minutes=5))))
    conn.commit()
    conn.close()

    check("chromium format detected", bf.detect_browser(p) == "chromium")
    r = bf.analyze_file(p, use_ai=False)
    check("browser risk scored high", r["risk_score"] >= 55, f"got {r['risk_score']}")
    check("history parsed", r["counts"]["history"] == 3)
    check("risky download flagged", len(r["risky_downloads"]) >= 1)
    check("phishing URL in history found", len(r["phishing_urls"]) >= 1)
    check("crack site categorised", len(r["flagged_urls"]) >= 1)
    check("privacy note present", "never decrypted" in r["privacy_note"])
    os.unlink(p)


# ============================================================ memory
def test_memory():
    section("Module 6 — Memory Forensics")
    from modules import memory_forensics as mf

    blob = (b"svch0st.exe mimikatz.exe nc.exe explorer.exe lsass.exe svchost.exe "
            b"203.0.113.99:4444 198.51.100.7:50050 "
            b"VirtualAllocEx WriteProcessMemory CreateRemoteThread SetThreadContext "
            b"powershell -nop -w hidden -enc SQBFAFgA cobaltstrike beacon.dll "
            b"sekurlsa::logonpasswords vssadmin delete shadows "
            b"Software\\Microsoft\\Windows\\CurrentVersion\\Run schtasks /create "
            b"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 "
            b"-----BEGIN RSA PRIVATE KEY----- ") * 4
    fd, p = tempfile.mkstemp(suffix=".raw")
    os.write(fd, os.urandom(80000) + blob + os.urandom(40000))
    os.close(fd)
    r = mf.analyze_dump(p, use_ai=False)
    check("memory risk critical", r["risk_score"] >= 80, f"got {r['risk_score']}")
    check("masquerade detected",
          any("svch0st" in x["name"] for x in r["suspicious_processes"]))
    check("C2 port flagged", any(c["port"] == 4444 for c in r["connections"]))
    check("injection chain detected", len(r["injection_indicators"]) >= 3)
    check("credential material found", len(r["credentials"]) >= 2)
    check("persistence detected", len(r["persistence"]) >= 1)
    check("malware signatures matched", len(r["signatures"]) >= 3)
    check("educational note present", "education" in r["note"].lower())
    os.unlink(p)


# ============================================================ logs
def test_logs():
    section("Module 7 — Log Analysis")
    from modules import log_analysis as la

    def run(text, fn):
        fd, p = tempfile.mkstemp(suffix=".log")
        os.write(fd, text.encode())
        os.close(fd)
        r = la.analyze_log(p, fn, use_ai=False)
        os.unlink(p)
        return r

    linux = "\n".join(
        [f"Mar 15 02:14:{22+i:02d} web sshd[{i}]: Failed password for root "
         f"from 203.0.113.45 port {5000+i} ssh2" for i in range(8)] +
        ["Mar 15 02:19:02 web sshd[99]: Accepted password for root from 203.0.113.45 port 51302 ssh2",
         "Mar 15 02:20:11 web useradd[101]: new user: name=svcbackup, UID=0",
         "Mar 15 02:22:05 web sudo:  svcbackup : COMMAND=/bin/bash -c history -c"])
    r = run(linux, "auth.log")
    check("linux format detected", r["log_type"] == "linux", r["log_type"])
    check("linux brute force scored critical", r["risk_score"] >= 80, f"got {r['risk_score']}")
    check("successful compromise correlated",
          any("brute-forcing IP" in f["title"] for f in r["findings"]))
    check("anti-forensics detected",
          any("anti-forensics" in f["title"].lower() or "tampering" in f["title"].lower()
              for f in r["findings"]))

    web = "\n".join([
        '198.51.100.23 - - [15/Mar/2026:03:12:01 +0530] "GET /i.php?id=1%27+OR+%271%27%3D%271 HTTP/1.1" 200 4821 "-" "sqlmap/1.7"',
        '198.51.100.23 - - [15/Mar/2026:03:12:04 +0530] "GET /i.php?id=1+UNION+SELECT+u,p+FROM+users-- HTTP/1.1" 200 9134 "-" "sqlmap/1.7"',
        '198.51.100.23 - - [15/Mar/2026:03:13:10 +0530] "GET /p.php?f=../../../../etc/passwd HTTP/1.1" 200 2317 "-" "curl/8.2"',
        '198.51.100.23 - - [15/Mar/2026:03:15:02 +0530] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 44 "-" "curl/8.2"',
        '198.51.100.23 - - [15/Mar/2026:03:16:20 +0530] "GET /export/customers.csv HTTP/1.1" 200 48211934 "-" "curl/8.2"'])
    r = run(web, "access.log")
    check("webserver format detected", r["log_type"] == "webserver", r["log_type"])
    check("web attacks scored critical", r["risk_score"] >= 80, f"got {r['risk_score']}")
    check("SQL injection detected",
          any("SQL Injection" in f["title"] for f in r["findings"]))
    check("web shell detected", any("shell" in f["title"].lower() for f in r["findings"]))
    check("exfiltration detected", any("exfiltration" in f["title"].lower() for f in r["findings"]))

    win = "\n".join(
        [f"Event ID: 4625  Account Name: administrator  Source Network Address: 203.0.113.99  Logon Type: 10"
         for _ in range(8)] +
        ["Event ID: 4624  Account Name: administrator  Source Network Address: 203.0.113.99  Logon Type: 10",
         "Event ID: 4720  A user account was created. Account Name: backdoor",
         "Event ID: 1102  The audit log was cleared."])
    r = run(win, "security.txt")
    check("windows format detected", r["log_type"] == "windows", r["log_type"])
    check("windows attack scored critical", r["risk_score"] >= 80, f"got {r['risk_score']}")
    check("log clearing detected", any("1102" in f["title"] for f in r["findings"]))

    fw = "\n".join(
        [f"Mar 15 02:00:{i%60:02d} gw kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.77 "
         f"DST=10.0.0.5 PROTO=TCP SPT=40000 DPT={1000+i} SYN" for i in range(40)])
    r = run(fw, "firewall.log")
    check("firewall format detected", r["log_type"] == "firewall", r["log_type"])
    check("port scan detected", any("scan" in f["title"].lower() for f in r["findings"]))

    e = la.explain_event_id("4625", use_ai=False)
    check("event ID lookup works", e["known"] and "Failed logon" in e["name"])


# ============================================================ assistant
def test_assistant():
    section("Module 8 — AI Assistant (offline paths)")
    from modules import assistant as a

    docs = a.retrieve("What does Event ID 4625 mean?", 3)
    check("RAG retrieves relevant article", any(d["id"] == "event-4625" for d in docs),
          str([d["id"] for d in docs]))

    docs = a.retrieve("How do I report cybercrime in India?", 3)
    check("RAG finds India reporting article",
          any("report-cybercrime" in d["id"] for d in docs), str([d["id"] for d in docs]))

    docs = a.retrieve("ransomware encrypted my files", 3)
    check("RAG finds ransomware article", any("ransom" in d["id"] for d in docs))

    fb = a.fallback_answer("what is phishing", a.retrieve("what is phishing", 2))
    check("offline fallback answers", len(fb) > 200 and "phishing" in fb.lower())

    check("knowledge base populated", len(a.KB) >= 25, f"got {len(a.KB)}")
    check("all KB entries well formed",
          all({"id", "title", "tags", "text"} <= set(d) for d in a.KB))


# ============================================================ learning
def test_learning():
    section("Module 9 — Learning Center")
    from modules import learning as L

    check("6 quiz topics", len(L.QUIZ_BANK) == 6, str(list(L.QUIZ_BANK)))
    check("9 labs", len(L.LABS) == 9, f"got {len(L.LABS)}")
    check("phishing simulator has emails", len(L.SIM_EMAILS) >= 6)
    check("learning paths defined", len(L.LEARNING_PATHS) == 3)

    for topic, bank in L.QUIZ_BANK.items():
        ok = all(0 <= q["answer"] < len(q["options"]) and q.get("why") for q in bank)
        check(f"quiz '{topic}' answers valid", ok)

    qs, picks = L.get_quiz("phishing", 5)
    check("quiz generation works", len(qs) == 5 and len(picks) == 5)

    res = L.grade_quiz("phishing", picks, [p["answer"] for p in picks], "selftest")
    check("perfect quiz scores 100%", res["percent"] == 100, str(res["percent"]))

    res = L.grade_quiz("phishing", picks, [-1] * len(picks), "selftest")
    check("empty quiz scores 0%", res["percent"] == 0)

    sim = L.grade_sim({e["id"]: ("phishing" if e["phishing"] else "legitimate")
                       for e in L.SIM_EMAILS})
    check("perfect simulator scores 100%", sim["percent"] == 100)

    L.mark_lab("selftest", "lab-phish-url")
    prog = L.progress("selftest")
    check("lab progress recorded", "lab-phish-url" in prog["labs_completed"])
    check("badges awarded", len(prog["badges"]) >= 1)

    for lab in L.LABS:
        ok = all(k in lab for k in ("id", "title", "objective", "steps", "questions", "takeaway"))
        if not ok:
            check(f"lab {lab.get('id')} well formed", False)
            break
    else:
        check("all labs well formed", True)


# ============================================================ breach
def test_breach():
    section("Module 11 — Data Breach Checker")
    from core.database import init_db
    from modules import breach as br, breach_providers as bpv

    init_db()
    st = br.catalog_stats()
    check("catalogue loaded", st["breach_count"] >= 90, f"got {st['breach_count']}")
    check("catalogue totals billions of accounts", st["total_accounts"] > 10_000_000_000)
    check("all entries well formed",
          all({"name", "year", "data", "severity"} <= set(b) for b in br.all_breaches()))
    check("India detection works", st["indian"] >= 5, f"got {st['indian']}")

    # --- cross-provider name normalisation (the dedupe fix)
    check("TLD stripped when matching", br._norm("Paidwork") == br._norm("Paidwork.com"))
    check("year suffix stripped", br._norm("Twitter") == br._norm("Twitter (2023)"))
    check("distinct names stay distinct", br._norm("Adobe") != br._norm("Canva"))

    # --- severity / category classification
    check("password class is critical",
          bpv._severity(["Email addresses", "Passwords"], 1000) == "critical")
    check("benign class is not critical",
          bpv._severity(["Email addresses"], 500) in ("low", "medium"))
    check("html stripped from descriptions",
          "<" not in bpv._strip_html('<a href="x">Adobe</a> was breached'))

    # --- offline inference path (no network)
    r = br.check_email("someone@yahoo.com", use_ai=False, online=False)
    check("offline mode is labelled an estimate", r["lookup_mode"] == "offline_estimate")
    check("offline mode never claims BREACHED", r["verdict"] != "BREACHED")
    r = br.check_email("user@example.org", ["linkedin.com", "adobe.com"],
                       use_ai=False, online=False)
    check("declared services matched offline", len(r["service_breaches"]) >= 1)
    check("action plan generated", len(r["action_plan"]) >= 5)

    r = br.check_email("admin@somecompany.com", use_ai=False, online=False)
    check("role account flagged", any("Role-based" in f["title"] for f in r["findings"]))
    check("invalid email rejected", "error" in br.check_email("not-an-email"))
    check("email masked for logging",
          br._mask_email("rahul@gmail.com") == "r***l@gmail.com",
          br._mask_email("rahul@gmail.com"))
    check("short local part fully masked", br._mask_email("ab@x.com") == "**@x.com")

    # --- live lookup result shape (works whether or not the network is up)
    live = br.check_email("test@example.com", use_ai=False, online=True)
    L = live["live"]
    check("live lookup attempted", L["attempted"])
    check("provider list populated", len(L["providers"]) >= 2)
    check("confidence reported", L.get("confidence") in ("high", "medium", "low", "none"))
    if L["any_response"]:
        check("live mode labelled correctly", live["lookup_mode"] == "live")
        check("verdict is decisive",
              live["verdict"] in ("BREACHED", "NOT FOUND"), live["verdict"])
        if live["breached"]:
            check("breached result carries breaches", L["breach_count"] > 0)
            check("no duplicate breach names after merge",
                  len({br._norm(b["name"]) for b in L["breaches"]}) == L["breach_count"])
            check("breaches enriched with data classes",
                  any(b.get("data") for b in L["breaches"]))
        print(f"        (live: {L['responded']} -> {live['verdict']}, "
              f"{L['breach_count']} breaches)")
    else:
        check("falls back to estimate when offline",
              live["lookup_mode"] == "offline_estimate")
        print("        (no network - live providers unreachable, fallback verified)")

    # --- corpus import
    br.clear_corpus()
    res = br.import_corpus("a@test.com:pw1\nb@test.com;pw2\nc@test.com,pw3\nd@test.com\nbadline",
                           "selftest dump")
    check("corpus import parses mixed delimiters", res["imported"] == 4, str(res))
    check("corpus import skips bad lines", res["skipped"] == 1)
    res = br.import_corpus("email,password\ncsv1@test.com,x\ncsv2@test.com,y", "selftest csv")
    check("corpus CSV import works", res["imported"] == 2, str(res))
    check("exact match found", len(br.check_local_corpus("a@test.com")) == 1)
    check("non-member not matched", len(br.check_local_corpus("zz@test.com")) == 0)

    from core.database import query
    rows = query("SELECT pw_sha1_prefix FROM breach_records WHERE record_type='email'")
    check("passwords stored only as 5-char hash prefix",
          all(len(x["pw_sha1_prefix"]) in (0, 5) for x in rows))
    leak = query("SELECT COUNT(*) AS c FROM breach_records "
                 "WHERE pw_sha1_prefix IN ('pw1','pw2','pw3')")
    check("no plaintext password stored", leak[0]["c"] == 0)

    r = br.check_email("a@test.com", use_ai=False, online=False)
    check("corpus hit surfaces in email check", len(r["corpus_hits"]) == 1)
    check("corpus hit marks the address breached", r["breached"] is True)
    check("exact match raises a critical finding",
          any("EXACT MATCH" in f["title"] for f in r["findings"]))

    # --- password (offline path; network is opt-in)
    p = br.check_password_pwned("password123", allow_network=False)
    check("known-bad password found offline", p["found"])
    check("offline check uses no network", p["network_used"] is False)
    check("only 5 hash chars would be sent", len(p["sha1_prefix"]) == 5)
    check("unknown password not flagged offline",
          br.check_password_pwned("zQ7!mXv2-neverused-9931x", allow_network=False)["found"] is False)
    check("empty password handled", "error" in br.check_password_pwned(""))

    # --- settings
    br.set_hibp_api_key("TESTKEY123")
    check("HIBP key persists", br.hibp_api_key() == "TESTKEY123")
    br.set_hibp_api_key("")
    check("HIBP key clears", br.hibp_api_key() == "")
    br.set_online_enabled(False)
    check("online toggle persists", br.online_enabled() is False)
    br.set_online_enabled(True)
    check("key absent means HIBP skipped",
          bpv.hibp_official("x@y.com", "")["error"] == "no_api_key")

    # --- watchlist
    br.add_to_watchlist("watch@yahoo.com", "selftest")
    check("watchlist add works", any(w["email"] == "watch@yahoo.com" for w in br.watchlist()))
    check("watchlist dedupes", br.add_to_watchlist("watch@yahoo.com").get("already") is True)
    wid = next(w["id"] for w in br.watchlist() if w["email"] == "watch@yahoo.com")
    br.remove_from_watchlist(wid)
    check("watchlist remove works",
          not any(w["email"] == "watch@yahoo.com" for w in br.watchlist()))

    # --- search
    check("catalogue search by company", len(br.search_breaches("Adobe")) >= 1)
    check("catalogue search by data class", len(br.search_breaches("Passwords")) >= 50)
    check("catalogue search by India", len(br.search_breaches("India")) >= 5)
    check("explain_breach rejects unknown",
          "error" in br.explain_breach("NotARealBreachXyz", use_ai=False))
    br.clear_corpus()


# ============================================================ templates
def test_templates():
    section("Templates — form integrity")
    import collections
    import pathlib as _pl
    import re as _re

    # Regression: phishing.html once had three inputs all named "content".
    # Hidden tab panes are only display:none, so the browser submitted ALL of
    # them and Flask's .get() returned the first (empty) one -> blank page.
    bad = []
    for f in sorted(_pl.Path("templates").glob("*.html")):
        html = f.read_text()
        for m in _re.finditer(r"<form\b.*?</form>", html, _re.S | _re.I):
            block = m.group(0)
            fields = _re.findall(
                r'<(input|textarea|select)\b([^>]*)\bname="([^"]+)"([^>]*)>', block)
            counts = collections.Counter(n for _, _, n, _ in fields)
            for name, c in counts.items():
                if c < 2:
                    continue
                attrs = " ".join(a + b for tg, a, n, b in fields if n == name)
                # radio/checkbox groups and the hidden+checkbox pair are fine
                if 'type="radio"' in attrs or 'type="checkbox"' in attrs:
                    continue
                # {% if %}/{% else %} branches render only one of them
                if _re.search(r"{%\s*(if|else|elif)", block):
                    continue
                bad.append(f"{f.name}:{name} x{c}")
    check("no duplicate text-field names in any form", not bad, f"{bad}")

    # The phishing tabs must each have their own field name.
    ph_html = _pl.Path("templates/phishing.html").read_text()
    for n in ("content_url", "content_email", "content_sms"):
        check(f"phishing form has {n}", f'name="{n}"' in ph_html)
    check("phishing form no longer uses the shared name",
          'name="content"' not in ph_html)
    check("phishing tab is restored after submit", "selectKind(" in ph_html)


# ============================================================ toolkit
def test_toolkit():
    section("Bonus — Daily Toolkit")
    from modules import toolkit as tk

    t = ("Aadhaar: 4521 8834 9012\nPAN: ABCPS1234K\nCard: 4532778912345678\n"
         "Mobile: +91 98765 43210\nUPI: x@okhdfcbank\nDB_PASSWORD=Secret123!\n"
         "AWS: AKIAIOSFODNN7EXAMPLE")
    r = tk.scan_pii(t)
    types = {f["type"] for f in r["findings"]}
    check("Aadhaar detected", "Aadhaar number" in types)
    check("PAN detected", "PAN card" in types)
    check("card detected", "Credit/Debit card" in types)
    check("AWS key detected", "AWS access key" in types)
    check("redaction removes secrets",
          "4521 8834 9012" not in r["redacted"] and "AKIAIOSFODNN7EXAMPLE" not in r["redacted"])
    check("clean text marked safe", tk.scan_pii("Hello, nice weather today.")["safe"])

    r = tk.detect_scam("Pay refundable security deposit of Rs 1999 to get this job. "
                       "Earn Rs 5000 per day. Send Aadhaar and PAN.", use_ai=False)
    check("job scam scored critical", r["risk_score"] >= 80, f"got {r['risk_score']}")

    check("base64 roundtrip",
          tk.encode_decode(tk.encode_decode("CyberSafe", "base64_encode")["result"],
                           "base64_decode")["result"] == "CyberSafe")
    check("hex roundtrip",
          tk.encode_decode(tk.encode_decode("CyberSafe", "hex_encode")["result"],
                           "hex_decode")["result"] == "CyberSafe")
    check("rot13 involutive",
          tk.encode_decode(tk.encode_decode("CyberSafe", "rot13")["result"],
                           "rot13")["result"] == "CyberSafe")
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.sig")
    check("JWT decodes", "HS256" in tk.encode_decode(jwt, "jwt_decode")["result"])
    check("bad base64 handled", tk.encode_decode("!!!not base64!!!", "base64_decode")["ok"] is False)

    hashes = tk.hash_text("test")
    check("sha256 correct",
          hashes["sha256"] == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")

    q = tk.check_qr_payload("upi://pay?pa=fraud@ybl&pn=Refund&am=4999")
    check("UPI QR identified", q["kind"] == "upi_payment")
    check("UPI QR warns about payment", any("PAYMENT" in n for n in q["notes"]))

    c = tk.score_checkup({"unique_pw": "yes", "2fa_email": "yes"})
    check("checkup scores", 0 < c["percent"] < 100)
    check("checkup lists gaps", len(c["gaps"]) > 0)
    check("perfect checkup grades A+",
          tk.score_checkup({i["id"]: "yes" for i in tk.CHECKUP_ITEMS})["grade"] == "A+")

    fd, a = tempfile.mkstemp(); os.write(fd, b"same"); os.close(fd)
    fd, b = tempfile.mkstemp(); os.write(fd, b"same"); os.close(fd)
    fd, c2 = tempfile.mkstemp(); os.write(fd, b"diff"); os.close(fd)
    check("identical files match", tk.compare_files(a, b)["identical"])
    check("different files differ", not tk.compare_files(a, c2)["identical"])
    fd, s = tempfile.mkstemp(); os.write(fd, b"delete me" * 100); os.close(fd)
    check("shredder works", tk.shred_file(s)["ok"] and not os.path.exists(s))
    for f in (a, b, c2):
        os.unlink(f)


# ============================================================ core
def test_core():
    section("Core — utilities & AI client")
    from core import ollama_client as oc, utils as u

    check("entropy of random is high", u.shannon_entropy(os.urandom(4096)) > 7.5)
    check("entropy of zeros is 0", u.shannon_entropy(b"\x00" * 1000) == 0.0)
    check("PE magic recognised", "Windows Exec" in u.file_type_guess(b"MZ\x90\x00", "x.exe"))
    check("PDF magic recognised", "PDF" in u.file_type_guess(b"%PDF-1.7", "x.pdf"))
    check("ZIP magic recognised", "ZIP" in u.file_type_guess(b"PK\x03\x04", "x.docx"))

    iocs = u.extract_iocs("Visit http://evil.com or mail a@b.com from 8.8.8.8. "
                          "Wallet 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 upi x@okaxis")
    check("URL extracted", len(iocs["urls"]) >= 1)
    check("email extracted", len(iocs["emails"]) >= 1)
    check("IP extracted", "8.8.8.8" in iocs["ips"])
    check("bitcoin extracted", len(iocs["bitcoin"]) >= 1)
    check("UPI extracted", len(iocs["upi_ids"]) >= 1)

    check("defang works", "hxxp" in u.defang("http://evil.com") and "[.]" in u.defang("evil.com"))
    check("risk bands correct",
          u.risk_band(90) == "critical" and u.risk_band(60) == "high"
          and u.risk_band(30) == "medium" and u.risk_band(10) == "low")
    check("human_size works", u.human_size(1536) == "1.50 KB")
    check("safe_name sanitises", "/" not in u.safe_name("../../etc/passwd"))
    check("strings extraction works",
          "HelloWorld" in u.extract_strings(b"\x00\x01HelloWorld\x00\xff"))

    st = oc.status(force=True)
    check("ollama status returns dict", isinstance(st, dict) and "online" in st)
    if not st["online"]:
        res = oc.generate("test")
        check("offline generate degrades safely", res["ok"] is False and res["error"])
        print("        (Ollama offline — AI layers correctly skipped)")
    else:
        print(f"        (Ollama online: {st['model']})")

    check("loose JSON parser handles fences",
          oc._parse_json_loose('```json\n{"a":1}\n```') == {"a": 1})
    check("loose JSON parser repairs trailing comma",
          oc._parse_json_loose('{"a":1,}') == {"a": 1})
    check("loose JSON parser extracts embedded",
          oc._parse_json_loose('Sure! {"a":1} hope that helps') == {"a": 1})


# ============================================================ main
def main():
    print("=" * 68)
    print("  AI Cyber Safety & Digital Forensics Platform — Self Test")
    print("=" * 68)
    for fn in (test_core, test_phishing, test_password, test_malware, test_evidence,
               test_browser, test_memory, test_logs, test_assistant, test_learning,
               test_breach, test_toolkit, test_templates):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            import traceback
            global FAIL
            FAIL += 1
            FAILURES.append(f"{fn.__name__} CRASHED: {exc}")
            print(f"  \033[91mCRASH\033[0m {fn.__name__}: {exc}")
            traceback.print_exc()

    print("\n" + "=" * 68)
    total = PASS + FAIL
    if FAIL == 0:
        print(f"  \033[92mALL {total} CHECKS PASSED\033[0m")
    else:
        print(f"  \033[91m{FAIL} of {total} CHECKS FAILED\033[0m")
        for f in FAILURES:
            print(f"    - {f}")
    print("=" * 68)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
