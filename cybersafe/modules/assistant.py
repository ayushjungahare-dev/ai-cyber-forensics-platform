"""
Module 8 -- AI Cyber Assistant.

A local RAG-lite assistant: a curated offline knowledge base is retrieved with
TF-IDF-ish scoring and injected into the Ollama prompt, so answers stay grounded
even on a small 3B model. Falls back to pure knowledge-base answers when Ollama
is offline, so the assistant is NEVER completely dead.
"""
from __future__ import annotations

import math
import re
import uuid
from collections import Counter

from core import ollama_client
from core.database import execute, query, utcnow

# ---------------------------------------------------------------- knowledge base
KB = [
    {"id": "phishing-basics", "title": "What is phishing and how does it work?",
     "tags": ["phishing", "email", "scam", "fake", "link"],
     "text": "Phishing is a social-engineering attack where an attacker impersonates a trusted "
             "organisation to trick you into revealing credentials, OTPs or payment details, or "
             "into running malware. The typical chain is: (1) a lure arrives by email/SMS/WhatsApp/"
             "call, (2) it creates urgency or fear ('your account will be closed in 24 hours'), "
             "(3) it links to a look-alike website, (4) you enter your credentials, (5) the "
             "attacker replays them on the real site. Key defences: never act on urgency, always "
             "type the official address yourself, check the domain carefully (paypal.com vs "
             "paypa1-secure.xyz), and enable two-factor authentication so a stolen password alone "
             "is useless."},
    {"id": "phishing-indicators", "title": "How to spot a phishing message",
     "tags": ["phishing", "indicators", "spot", "identify", "red flags", "suspicious"],
     "text": "Red flags: generic greeting ('Dear Customer'); mismatched sender domain; reply-to "
             "different from from-address; urgency or threats; requests for OTP, CVV, PIN or "
             "passwords; links whose visible text differs from the real destination; unexpected "
             "attachments especially .exe/.zip/.docm/.lnk; spelling and grammar errors; a bank or "
             "government claim sent from gmail.com; shortened URLs; and payment redirection to a "
             "personal UPI ID or crypto wallet. Hover over links before clicking to preview the "
             "true destination. In India, report phishing at cybercrime.gov.in or by calling 1930."},
    {"id": "ransomware", "title": "Ransomware: how it spreads and what to do",
     "tags": ["ransomware", "encrypt", "malware", "locky", "wannacry", "recovery"],
     "text": "Ransomware encrypts your files and demands payment. Common entry points: phishing "
             "attachments and macro documents, exposed RDP with weak passwords, unpatched VPN/"
             "server vulnerabilities, malicious software cracks, and infected USB drives. Before "
             "encrypting, modern families delete Volume Shadow Copies (vssadmin delete shadows), "
             "disable Defender, and exfiltrate data for double extortion. If hit: disconnect the "
             "machine from the network immediately, DO NOT power it off if memory evidence matters "
             "(capture RAM first), photograph the ransom note, preserve logs, do not pay (payment "
             "funds crime and rarely restores everything), check nomoreransom.org for a free "
             "decryptor, and restore from offline backups. Prevention: 3-2-1 backups with one "
             "offline copy, patching, MFA on all remote access, and disabling Office macros."},
    {"id": "malware-removal", "title": "How to remove malware from a computer",
     "tags": ["malware", "remove", "clean", "infected", "virus", "trojan"],
     "text": "Step 1: disconnect from the internet to cut off C2 and stop data theft. Step 2: if "
             "the machine matters forensically, capture a RAM image and disk image FIRST - "
             "cleaning destroys evidence. Step 3: boot into Safe Mode. Step 4: run a full scan "
             "with an updated reputable AV plus a second-opinion scanner (Microsoft Defender "
             "Offline, Malwarebytes free). Step 5: inspect persistence: Task Scheduler, Run keys, "
             "Startup folder, Services, WMI subscriptions, and browser extensions. Step 6: reset "
             "browser settings and remove unknown extensions. Step 7: change every important "
             "password FROM A DIFFERENT CLEAN DEVICE and enable 2FA. Step 8: patch the OS and all "
             "software. If a rootkit or ransomware is suspected, or the machine handles money or "
             "sensitive data, a full wipe and reinstall is the only trustworthy remedy."},
    {"id": "event-4625", "title": "Windows Event ID 4625 explained",
     "tags": ["4625", "event", "windows", "logon", "failed", "log"],
     "text": "Event ID 4625 = 'An account failed to log on', written to the Security log. Key "
             "fields: Account Name (who was targeted), Logon Type (2=console, 3=network/SMB, "
             "10=RDP), Source Network Address (attacker IP), and Failure Reason / Status codes "
             "(0xC000006A = bad password, 0xC0000064 = user does not exist, 0xC0000234 = account "
             "locked out, 0xC0000072 = account disabled). A handful of 4625s is normal (typos). "
             "Many 4625s for one account = brute force. A few 4625s across many accounts = "
             "password spraying. 4625 with Logon Type 10 from a public IP = internet-exposed RDP "
             "under attack. Always check whether a 4624 (successful logon) follows - that means "
             "they got in."},
    {"id": "event-4624", "title": "Windows Event ID 4624 explained",
     "tags": ["4624", "event", "windows", "logon", "success", "log"],
     "text": "Event ID 4624 = 'An account was successfully logged on'. Watch the Logon Type: 2 is "
             "interactive at the keyboard, 3 is network (file shares), 4 is batch/scheduled task, "
             "5 is a service, 7 is workstation unlock, 9 is RunAs with new credentials (used by "
             "attackers with stolen creds), 10 is RDP, 11 is cached credentials. Suspicious "
             "patterns: type 10 from an external IP, type 3 from a workstation to many hosts "
             "(lateral movement), logons outside business hours, service accounts logging on "
             "interactively, and 4624 immediately after a burst of 4625."},
    {"id": "social-engineering", "title": "Social engineering techniques",
     "tags": ["social engineering", "manipulation", "pretexting", "vishing", "baiting"],
     "text": "Social engineering exploits human psychology instead of software bugs. Main forms: "
             "phishing (email), smishing (SMS), vishing (voice call), pretexting (inventing a "
             "believable scenario, e.g. 'IT support needs your password'), baiting (a malicious "
             "USB drive labelled 'Salary 2024'), quid pro quo (offering help in exchange for "
             "access), tailgating (physically following someone through a secure door), and "
             "business email compromise (impersonating a CEO to authorise a payment). The levers "
             "are authority, urgency, fear, curiosity, greed and helpfulness. Defence: verify "
             "through an independent channel, slow down, and make it culturally acceptable to say "
             "'let me call you back on the official number'."},
    {"id": "password-security", "title": "Password best practices",
     "tags": ["password", "strong", "manager", "passphrase", "2fa", "mfa"],
     "text": "Length beats complexity. A 16+ character passphrase such as 'copper-violin-42-"
             "monsoon-Tide' is far stronger and more memorable than 'P@ssw0rd!'. Rules: unique "
             "password for every account (breaches cascade otherwise), never reuse across work "
             "and personal, use a free password manager (Bitwarden, KeePassXC), and enable "
             "two-factor authentication everywhere - prefer an authenticator app or hardware key "
             "over SMS, because SIM swapping defeats SMS. Never share OTPs; no legitimate support "
             "agent ever needs one. Change a password immediately if the service reports a breach."},
    {"id": "2fa", "title": "Two-factor authentication (2FA/MFA)",
     "tags": ["2fa", "mfa", "otp", "authenticator", "two factor"],
     "text": "2FA requires something you know (password) plus something you have (phone, key) or "
             "are (biometric). Strength ranking: hardware security key (FIDO2/YubiKey, "
             "phishing-resistant) > authenticator app TOTP (Google/Microsoft/Aegis) > push "
             "notification > SMS OTP (vulnerable to SIM swap and OTP-relay phishing). Attackers "
             "bypass 2FA with real-time phishing proxies (Evilginx), MFA-fatigue push bombing, and "
             "OTP social engineering. Mitigation: use number-matching push, hardware keys for "
             "high-value accounts, and never approve a prompt you did not initiate."},
    {"id": "safe-browsing", "title": "Safe browsing habits",
     "tags": ["browsing", "safe", "internet", "https", "extension", "web"],
     "text": "Keep the browser and OS updated - most drive-by attacks target known bugs. Check "
             "for HTTPS but remember that a padlock only means encryption, not honesty; most "
             "phishing sites now have valid certificates. Install as few extensions as possible "
             "and review their permissions - a malicious extension can read every page you visit. "
             "Use an ad/tracker blocker (uBlock Origin) since malvertising is a real infection "
             "vector. Never download cracked software or 'modded APKs'. Do not save passwords in "
             "the browser if you can use a password manager instead - infostealer malware targets "
             "the browser credential store first. Use a separate browser profile for banking."},
    {"id": "digital-forensics", "title": "Digital forensics fundamentals",
     "tags": ["forensics", "investigation", "evidence", "chain of custody", "acquisition"],
     "text": "Digital forensics follows four phases: Identification (what devices/data matter), "
             "Preservation (stop changes; write-blockers, imaging, hashing), Analysis (examine the "
             "copy, never the original), and Presentation (a clear, defensible report). Core "
             "principles: work on verified copies, hash everything at acquisition (MD5+SHA-256) "
             "and re-verify later, document every action with who/what/when/why, and follow the "
             "order of volatility - capture RAM and network state before shutting down, because "
             "memory is lost on power-off. A broken chain of custody can make otherwise solid "
             "evidence inadmissible in court."},
    {"id": "chain-of-custody", "title": "Chain of custody",
     "tags": ["chain of custody", "evidence", "legal", "documentation", "admissible"],
     "text": "The chain of custody is the chronological, documented history of a piece of "
             "evidence: who collected it, when, from where, who has held it since, what was done "
             "to it, and where it is stored. Each transfer is recorded and signed. It proves the "
             "evidence was not altered or substituted. Practical requirements: unique evidence IDs, "
             "acquisition hashes recorded at collection time, tamper-evident storage, "
             "access logging, and periodic integrity re-verification. If the SHA-256 of the "
             "evidence today differs from the acquisition hash, the evidence is compromised and "
             "you must document exactly when and how that happened."},
    {"id": "memory-forensics", "title": "Memory (RAM) forensics",
     "tags": ["memory", "ram", "volatility", "dump", "live"],
     "text": "RAM contains what disk does not: running processes, network connections, injected "
             "code, decrypted data, clipboard contents, encryption keys and cleartext credentials. "
             "It is the MOST volatile evidence, so capture it first with a tool such as WinPMEM, "
             "DumpIt, FTK Imager or LiME (Linux), writing the image to external media. Then "
             "analyse offline with Volatility 3 (pslist, pstree, netscan, malfind, cmdline, "
             "dlllist, handles, hashdump). Classic findings: a process whose parent is wrong "
             "(svchost.exe spawned by winword.exe), memory regions that are RWX and unbacked by a "
             "file (malfind), and hollowed processes."},
    {"id": "browser-forensics", "title": "Browser forensics",
     "tags": ["browser", "history", "chrome", "firefox", "cookies", "cache"],
     "text": "Browser artefacts reveal intent and activity. Chrome/Edge/Brave store SQLite files "
             "under 'User Data/Default': History (urls, visits, downloads, keyword_search_terms), "
             "Cookies, Login Data, Web Data (autofill), Top Sites and Favicons. Firefox uses "
             "places.sqlite (history + bookmarks), cookies.sqlite, formhistory.sqlite and "
             "logins.json. Chrome timestamps are microseconds since 1601-01-01 (WebKit epoch); "
             "Firefox uses microseconds since 1970. Always copy the files before opening - the "
             "browser locks them and opening a live DB modifies it. Also check the Cache folder, "
             "Session Restore files and the downloads list for evidence of what was fetched."},
    {"id": "incident-response", "title": "Incident response steps",
     "tags": ["incident", "response", "breach", "ir", "containment", "nist"],
     "text": "NIST's six phases: 1) Preparation - tooling, contacts, playbooks, backups. "
             "2) Identification - confirm something real happened, determine scope and severity. "
             "3) Containment - short term (isolate the host, block the IP, disable the account) "
             "then long term (patch, rebuild). 4) Eradication - remove malware, close the entry "
             "vector, reset credentials. 5) Recovery - restore from clean backups, monitor "
             "closely for reinfection. 6) Lessons learned - a blameless post-incident review with "
             "concrete improvements. Throughout: preserve evidence, keep a timeline, and "
             "communicate with legal/management. In India, CERT-In requires reporting certain "
             "incidents within 6 hours."},
    {"id": "report-cybercrime-india", "title": "How to report cybercrime in India",
     "tags": ["report", "cybercrime", "india", "police", "1930", "fir"],
     "text": "For financial fraud, call the national helpline 1930 IMMEDIATELY - within the "
             "'golden hour' the money can often be frozen before it is withdrawn. File a complaint "
             "at cybercrime.gov.in (works for financial fraud, women/child-related crimes and "
             "other cyber offences). Also inform your bank at once to block the card/account and "
             "raise a chargeback. Preserve everything: screenshots of the message and website, "
             "the sender's number/email, transaction IDs and reference numbers, and bank SMS "
             "alerts. You may also file an FIR at the nearest police station or cyber cell - they "
             "cannot refuse a cybercrime FIR. Report spam SMS to 1909 and report the UPI ID inside "
             "your payment app."},
    {"id": "sql-injection", "title": "SQL injection",
     "tags": ["sql injection", "sqli", "web", "database", "owasp"],
     "text": "SQL injection happens when user input is concatenated into a SQL query, letting an "
             "attacker change the query's meaning - for example entering ' OR '1'='1 to bypass a "
             "login, or UNION SELECT to read other tables. Impact: authentication bypass, mass "
             "data theft, and sometimes command execution on the database host. In logs you see "
             "URL parameters containing quotes, UNION SELECT, --, sleep(), or the sqlmap "
             "User-Agent. Defence: parameterised queries / prepared statements (the real fix), "
             "least-privilege DB accounts, input validation as defence in depth, and a WAF for "
             "virtual patching."},
    {"id": "xss", "title": "Cross-site scripting (XSS)",
     "tags": ["xss", "cross site scripting", "javascript", "web", "owasp"],
     "text": "XSS injects attacker JavaScript into a page that other users view. Stored XSS lives "
             "in the database (a comment field), reflected XSS bounces off a URL parameter, and "
             "DOM XSS occurs entirely client-side. Impact: session-cookie theft, keylogging inside "
             "the page, fake login overlays and full account takeover. Defence: context-aware "
             "output encoding, a strict Content-Security-Policy, HttpOnly and Secure cookie flags, "
             "and framework auto-escaping (never bypass it with innerHTML or |safe)."},
    {"id": "usb-safety", "title": "USB and removable media safety",
     "tags": ["usb", "pendrive", "removable", "autorun", "badusb"],
     "text": "Never plug in a found USB drive - 'lost' drives in car parks are a real attack. "
             "Threats: autorun malware, malicious LNK shortcuts, and BadUSB devices that pretend "
             "to be a keyboard and type commands in milliseconds. Controls: disable AutoPlay/"
             "AutoRun, scan any drive before opening it, show file extensions in Explorer so "
             "'invoice.pdf.exe' is visible, use write-blockers when the drive is evidence, and "
             "prefer cloud sharing over physical media in offices. On shared PCs, treat any drive "
             "that has been in another machine as untrusted."},
    {"id": "wifi-security", "title": "Public Wi-Fi and network security",
     "tags": ["wifi", "public", "network", "vpn", "evil twin", "router"],
     "text": "On public Wi-Fi assume someone is watching. Risks: evil-twin hotspots imitating "
             "'Airport_Free_WiFi', captive-portal phishing, ARP spoofing and SSL-stripping. Rules: "
             "avoid banking on public Wi-Fi, prefer your mobile hotspot, use a reputable VPN, "
             "verify HTTPS, turn off auto-connect and file sharing, and forget the network "
             "afterwards. At home: change the default router admin password, use WPA3 (or WPA2-AES), "
             "disable WPS, keep firmware updated, and put IoT devices on a guest network."},
    {"id": "data-breach", "title": "What to do after a data breach",
     "tags": ["breach", "leaked", "hacked", "compromised", "haveibeenpwned"],
     "text": "If a service you use is breached: change that password immediately, and change it "
             "anywhere you reused it (this is the real danger). Enable 2FA. Watch for targeted "
             "phishing that quotes real details from the breach to sound credible. Check bank and "
             "card statements, and consider freezing credit if identity documents leaked. If your "
             "Aadhaar/PAN leaked, monitor for loans opened in your name. Long term: stop reusing "
             "passwords and start using a password manager so a single breach cannot cascade."},
    {"id": "mobile-security", "title": "Mobile phone security",
     "tags": ["mobile", "android", "ios", "apk", "app", "phone"],
     "text": "Install apps only from the official store; sideloaded APKs from WhatsApp/Telegram "
             "links are a top infection route in India. Review permissions - a torch app does not "
             "need SMS and Accessibility access. Accessibility-service abuse lets malware read the "
             "screen and auto-approve transactions. Never install screen-sharing apps (AnyDesk, "
             "TeamViewer, QuickSupport) because 'bank support' asked you to - that is the single "
             "most common vishing scam. Keep the OS updated, use biometric lock, enable Find My "
             "Device, and back up. Beware fake loan apps that harvest contacts and blackmail."},
    {"id": "cyber-hygiene", "title": "Daily cyber hygiene checklist",
     "tags": ["hygiene", "checklist", "daily", "habits", "basics"],
     "text": "Daily: think before clicking links, ignore unexpected OTP requests, lock your screen "
             "when away. Weekly: install pending updates, review bank and UPI transactions, empty "
             "the downloads folder. Monthly: verify backups actually restore, review app "
             "permissions and browser extensions, check account login-activity pages, rotate any "
             "shared passwords. Quarterly: audit which accounts still need to exist, review 2FA "
             "recovery codes, and run a full malware scan. Always: unique passwords, 2FA, offline "
             "backups, and healthy suspicion of urgency."},
    {"id": "ai-scams", "title": "AI-powered scams: deepfakes and voice cloning",
     "tags": ["ai", "deepfake", "voice", "clone", "scam", "video call"],
     "text": "Attackers now clone a voice from a few seconds of social-media audio and call "
             "relatives claiming an emergency, or run deepfake video calls impersonating "
             "executives to authorise transfers. Digital-arrest scams use fake police video calls "
             "to terrify victims into paying. Defences: agree a family safe-word, always call back "
             "on a known number, be sceptical of urgency plus secrecy, require a second channel "
             "for any payment approval, and remember Indian police NEVER arrest or demand money "
             "over a video call. Look for deepfake artefacts: unnatural blinking, lip-sync drift, "
             "flat lighting and audio that never overlaps."},
    {"id": "insider-threat", "title": "Insider threats",
     "tags": ["insider", "employee", "exfiltration", "dlp", "leaver"],
     "text": "Insider threats are malicious (a departing employee stealing client lists), "
             "negligent (emailing data to a personal account), or compromised (a stolen account). "
             "Indicators: bulk downloads outside normal patterns, access to systems unrelated to "
             "the role, activity at unusual hours, large uploads to personal cloud storage or "
             "anonfiles/mega, USB usage spikes, and privilege requests before resignation. "
             "Controls: least privilege, joiner-mover-leaver processes with same-day revocation, "
             "DLP monitoring, logging of file-share access (Event 5145), and a culture where "
             "people report concerns."},
    {"id": "log-analysis-basics", "title": "Log analysis fundamentals",
     "tags": ["log", "siem", "analysis", "correlation", "baseline"],
     "text": "Start by knowing normal - you cannot spot an anomaly without a baseline. Key "
             "questions: who logged in, from where, when, and did anything change? Correlate "
             "across sources: firewall shows the connection, the web log shows the request, the "
             "OS log shows the process, the AV log shows the detection. Watch for gaps in log "
             "continuity (a deliberately cleared window), spikes in failures, first-time-seen IPs "
             "and user-agents, and any admin action outside change windows. Always normalise "
             "timestamps to one timezone (UTC) before building a timeline."},
    {"id": "upi-fraud", "title": "UPI and digital payment fraud",
     "tags": ["upi", "payment", "fraud", "money", "bank", "refund"],
     "text": "Common UPI scams: the 'collect request' trick (you never need to enter a PIN to "
             "RECEIVE money - entering it sends money), fake customer-care numbers found via "
             "Google, QR codes that actually debit you, screen-sharing app fraud, fake refund "
             "processing, and 'wrong transfer, please return it' mule schemes. Rules: a PIN is "
             "only ever needed to PAY; verify the payee name before confirming; find support "
             "numbers only on the official app; never install remote-access apps for support; and "
             "if defrauded, call 1930 within the golden hour and report at cybercrime.gov.in."},
    {"id": "vpn", "title": "VPNs: what they do and do not protect",
     "tags": ["vpn", "privacy", "encryption", "anonymity"],
     "text": "A VPN encrypts traffic between your device and the VPN server, hiding your browsing "
             "from the local network and your ISP, and masking your IP from websites. It does NOT "
             "make you anonymous, does not stop phishing, does not remove malware, and does not "
             "protect you once you log into an account. A free VPN often monetises by selling your "
             "traffic data. Use a VPN on untrusted Wi-Fi and when you need to hide your IP; do not "
             "treat it as a security product on its own."},
    {"id": "sim-swap", "title": "SIM swap fraud",
     "tags": ["sim", "swap", "otp", "mobile", "port"],
     "text": "In a SIM swap the attacker convinces your telecom operator to move your number to "
             "their SIM, using leaked personal data or an insider. Your phone loses signal, then "
             "every SMS OTP goes to them and they reset your bank and email accounts. Warning "
             "signs: sudden loss of network for no reason, unexpected 'SIM change' SMS, or being "
             "unable to make calls. Defences: move 2FA off SMS to an authenticator app, set a "
             "port-out PIN with your operator, limit the personal data you share publicly, and if "
             "your signal dies unexpectedly, contact your operator and bank immediately."},
]

STOP = set("a an the is are was were be been being of to in for on with as at by from and or "
           "if then than that this these those it its i you he she they we do does did how "
           "what why when where which who whom can could should would will shall may might my "
           "your our their about into over under again more most some such no nor not only own "
           "same so too very just also".split())


def _tokens(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if w not in STOP and len(w) > 1]


_IDF = None


def _idf():
    global _IDF
    if _IDF is None:
        df = Counter()
        for doc in KB:
            for t in set(_tokens(doc["title"] + " " + " ".join(doc["tags"]) + " " + doc["text"])):
                df[t] += 1
        n = len(KB)
        _IDF = {t: math.log((n + 1) / (c + 0.5)) for t, c in df.items()}
    return _IDF


def retrieve(question: str, k: int = 3) -> list[dict]:
    idf = _idf()
    q = _tokens(question)
    if not q:
        return []
    qc = Counter(q)
    scored = []
    for doc in KB:
        body = _tokens(doc["text"])
        title = _tokens(doc["title"])
        tags = _tokens(" ".join(doc["tags"]))
        bc, tc, gc = Counter(body), Counter(title), Counter(tags)
        s = 0.0
        for term, qn in qc.items():
            w = idf.get(term, 0.6)
            s += w * (2.5 * tc.get(term, 0) + 3.5 * gc.get(term, 0) +
                      1.0 * min(bc.get(term, 0), 4)) * (1 + 0.1 * qn)
        # phrase bonus
        for tag in doc["tags"]:
            if tag in question.lower():
                s += 6
        if s > 0:
            scored.append((s, doc))
    scored.sort(key=lambda x: -x[0])
    return [d for s, d in scored[:k] if s > 1.5]


SYSTEM = (
    "You are CyberSafe AI, the built-in assistant of a cyber safety and digital forensics "
    "platform used by students, small businesses and beginner investigators in India.\n"
    "Rules:\n"
    "- Be practical, specific and concise. Prefer short numbered steps over essays.\n"
    "- Ground your answer in the provided reference material when it is relevant.\n"
    "- You are a DEFENSIVE tool: never provide working malware, exploits, or instructions "
    "to attack systems you do not own. Explaining how an attack works conceptually, for "
    "defence and education, is fine and encouraged.\n"
    "- For Indian users mention cybercrime.gov.in and helpline 1930 when a crime has occurred.\n"
    "- If you are unsure, say so plainly rather than inventing details.\n"
    "- Use markdown: **bold** for key terms, numbered lists for steps."
)

QUICK_PROMPTS = [
    "Is this email suspicious? (paste it)",
    "How do I remove malware from my laptop?",
    "What does Event ID 4625 mean?",
    "Explain ransomware in simple terms",
    "How do I report a UPI fraud in India?",
    "How do I preserve evidence after a hack?",
    "What is chain of custody?",
    "How do I make a strong password I can remember?",
    "Someone got my OTP - what now?",
    "Explain phishing to a 10-year-old",
]


def build_prompt(question: str, docs: list[dict]) -> str:
    if docs:
        ctx = "\n\n".join(f"[{d['title']}]\n{d['text']}" for d in docs)
        return (f"REFERENCE MATERIAL FROM THE PLATFORM KNOWLEDGE BASE:\n{ctx}\n\n"
                f"---\nUSER QUESTION: {question}\n\n"
                f"Answer using the reference material where relevant, adding your own expertise. "
                f"Do not mention that you were given reference material.")
    return question


def ask(question: str, session_id: str | None = None, history: list[dict] | None = None) -> dict:
    session_id = session_id or str(uuid.uuid4())[:12]
    docs = retrieve(question, k=3)
    prompt = build_prompt(question, docs)

    msgs = list(history or [])[-10:]
    msgs.append({"role": "user", "content": prompt})
    res = ollama_client.chat(msgs, system=SYSTEM, temperature=0.35, max_tokens=900)

    if res["ok"] and res["text"]:
        answer, source = res["text"], "ollama"
    else:
        answer, source = fallback_answer(question, docs), "knowledge_base"

    execute("INSERT INTO chat(session_id,role,content,created_at) VALUES(?,?,?,?)",
            (session_id, "user", question[:4000], utcnow()))
    execute("INSERT INTO chat(session_id,role,content,created_at) VALUES(?,?,?,?)",
            (session_id, "assistant", answer[:8000], utcnow()))

    return {"answer": answer, "session_id": session_id, "source": source,
            "sources": [{"id": d["id"], "title": d["title"]} for d in docs],
            "model": res.get("model"), "ai_online": res["ok"]}


def fallback_answer(question: str, docs: list[dict]) -> str:
    if not docs:
        return (
            "**The local AI model is not reachable right now**, and I could not find a close "
            "match in my offline knowledge base.\n\n"
            "To enable full AI answers:\n"
            "1. Install Ollama from https://ollama.com\n"
            "2. Run `ollama serve`\n"
            "3. Run `ollama pull llama3.2`\n\n"
            "Meanwhile you can ask me about: phishing, ransomware, malware removal, passwords, "
            "2FA, Windows Event IDs, chain of custody, memory/browser forensics, incident "
            "response, UPI fraud, SIM swap, or how to report cybercrime in India."
        )
    parts = ["*(Answered from the offline knowledge base - the local AI model is not running.)*\n"]
    for d in docs:
        parts.append(f"### {d['title']}\n{d['text']}")
    parts.append("\n---\n**Tip:** start Ollama (`ollama serve` + `ollama pull llama3.2`) for "
                 "conversational, context-aware answers.")
    return "\n\n".join(parts)


def get_history(session_id: str, limit: int = 60) -> list[dict]:
    return query("SELECT role,content,created_at FROM chat WHERE session_id=? "
                 "ORDER BY id ASC LIMIT ?", (session_id, limit))


def list_sessions(limit: int = 20) -> list[dict]:
    return query(
        """SELECT session_id, MIN(created_at) AS started, COUNT(*) AS messages,
                  (SELECT content FROM chat c2 WHERE c2.session_id=c1.session_id
                   AND c2.role='user' ORDER BY c2.id ASC LIMIT 1) AS first_question
           FROM chat c1 GROUP BY session_id ORDER BY MAX(id) DESC LIMIT ?""", (limit,))


def clear_session(session_id: str):
    execute("DELETE FROM chat WHERE session_id=?", (session_id,))


def analyse_snippet(text: str) -> dict:
    """Quick 'is this suspicious?' helper used by the assistant UI."""
    from modules.phishing import analyze
    return analyze(text, kind="email" if len(text) > 200 else "sms", use_ai=True)
