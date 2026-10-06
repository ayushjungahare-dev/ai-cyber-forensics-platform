"""
Module 9 -- Cyber Learning Center.

Offline content: quizzes, hands-on labs, phishing simulator, learning paths.
AI (Ollama) optionally generates fresh questions and personalised explanations,
but every piece of content works with the AI switched off.
"""
from __future__ import annotations

import json
import random

from core import ollama_client
from core.database import execute, query, query_one, scalar, utcnow

# ---------------------------------------------------------------- quizzes
QUIZ_BANK = {
    "phishing": [
        {"q": "You get an SMS: 'Your SBI account is blocked. Update KYC now: http://sbi-kyc-verify.xyz'. What is the safest action?",
         "options": ["Click the link and update KYC quickly",
                     "Ignore the link and open the official bank app or call the number on your card",
                     "Reply STOP to unsubscribe",
                     "Forward it to friends as a warning first"],
         "answer": 1,
         "why": "Banks never send KYC links by SMS. The domain '.xyz' is not the bank's. Always use the official app or the number printed on your card/passbook."},
        {"q": "Which URL is most likely a phishing site imitating Amazon?",
         "options": ["https://www.amazon.in/orders", "https://amazon-security-login.xyz/verify",
                     "https://www.amazon.in/gp/css/homepage.html", "https://smile.amazon.com"],
         "answer": 1,
         "why": "The real registered domain is 'amazon-security-login.xyz' - Amazon only appears as a keyword. Brand name + hyphens + odd TLD is the classic pattern."},
        {"q": "An email from 'HR' has the attachment 'Salary_Revision_2026.pdf.exe'. What does this mean?",
         "options": ["It is a PDF that opens in Excel", "It is a compressed PDF",
                     "It is an EXECUTABLE disguised as a PDF", "It is a digitally signed PDF"],
         "answer": 2,
         "why": "The real extension is the LAST one: .exe. Double extensions are a classic disguise. Enable 'show file extensions' in Windows Explorer to see this."},
        {"q": "The email displays 'HDFC Bank' but the address is hdfc.support@gmail.com. What is this?",
         "options": ["Normal - banks use Gmail for support", "Display-name spoofing",
                     "A secure email gateway", "An encrypted mail relay"],
         "answer": 1,
         "why": "Legitimate organisations send from their own domain (@hdfcbank.com). A corporate claim from free webmail is a strong phishing indicator."},
        {"q": "Which of these does a genuine bank NEVER ask for?",
         "options": ["Your registered mobile number", "Your account number",
                     "Your OTP, CVV or UPI PIN", "Your branch name"],
         "answer": 2,
         "why": "OTP, CVV, PIN and passwords are secrets. No legitimate employee needs them - anyone asking is committing fraud."},
        {"q": "What is 'smishing'?",
         "options": ["Phishing over SMS", "Phishing over voice call",
                     "Phishing using QR codes", "Phishing via physical mail"],
         "answer": 0,
         "why": "SMS + phishing = smishing. Voice is 'vishing', QR codes are 'quishing'."},
        {"q": "A link shows 'www.icicibank.com' but the status bar reveals 'icici-secure.tk'. This is:",
         "options": ["A CDN redirect", "Anchor-text mismatch - a phishing technique",
                     "Normal load balancing", "A browser bug"],
         "answer": 1,
         "why": "The visible text and the real href differ. Always hover to preview the true destination before clicking."},
    ],
    "passwords": [
        {"q": "Which password is strongest?",
         "options": ["P@ssw0rd!", "Summer2026!", "copper-violin-42-monsoon-Tide", "Xk9#mQ2"],
         "answer": 2,
         "why": "Length dominates. A 28-character passphrase has far more entropy than a short 'complex' password, and it is easier to remember."},
        {"q": "Why is password reuse dangerous?",
         "options": ["It slows down login", "One breach compromises all your accounts",
                     "It uses more storage", "Browsers block it"],
         "answer": 1,
         "why": "Attackers take credentials from one breach and replay them everywhere - this is called credential stuffing."},
        {"q": "The most secure form of 2FA is:",
         "options": ["SMS OTP", "Email OTP", "Authenticator app (TOTP)", "Hardware security key (FIDO2)"],
         "answer": 3,
         "why": "Hardware keys are phishing-resistant: they cryptographically bind to the real domain, so a fake site cannot use the response."},
        {"q": "Roughly how long does a GPU rig take to crack an 8-character lowercase password?",
         "options": ["Centuries", "Several years", "A few months", "Seconds to minutes"],
         "answer": 3,
         "why": "26^8 is only ~209 billion combinations - trivial at billions of guesses per second."},
        {"q": "What does a password manager mainly protect you from?",
         "options": ["Viruses", "Password reuse and weak passwords",
                     "Network sniffing", "Phishing calls"],
         "answer": 1,
         "why": "It generates and stores a unique strong password per site, so you only remember one master passphrase."},
        {"q": "Your password appears in a public breach list. What do you do FIRST?",
         "options": ["Add a '1' to the end", "Change it everywhere it was used and enable 2FA",
                     "Wait and watch", "Delete the account"],
         "answer": 1,
         "why": "The exact string is now in attacker wordlists. Small tweaks are also guessed by cracking rules."},
    ],
    "malware": [
        {"q": "Ransomware most commonly enters an organisation through:",
         "options": ["Cosmic rays", "Phishing attachments and exposed RDP",
                     "The printer", "HTTPS websites"],
         "answer": 1,
         "why": "Phishing with malicious attachments/links and internet-exposed RDP with weak passwords remain the top two entry vectors."},
        {"q": "Your files are encrypted with a ransom note. What should you NOT do?",
         "options": ["Disconnect from the network", "Photograph the ransom note",
                     "Pay the ransom immediately", "Check nomoreransom.org for a free decryptor"],
         "answer": 2,
         "why": "Paying funds crime, marks you as a payer for future attacks, and often does not restore all files. Restore from offline backups instead."},
        {"q": "What is a 'trojan'?",
         "options": ["Malware that self-replicates across the network",
                     "Malware disguised as legitimate software",
                     "Malware that encrypts files", "Malware that shows adverts"],
         "answer": 1,
         "why": "A trojan tricks the user into running it by pretending to be something useful. Worms self-replicate; ransomware encrypts."},
        {"q": "'vssadmin delete shadows' in a log means:",
         "options": ["Routine disk cleanup", "Shadow copies are being deleted - a ransomware hallmark",
                     "A Windows update", "A user logged off"],
         "answer": 1,
         "why": "Ransomware deletes Volume Shadow Copies so you cannot restore previous versions. This is a high-fidelity detection."},
        {"q": "A file has entropy 7.9/8.0. This most likely means:",
         "options": ["It is plain text", "It is packed or encrypted",
                     "It is corrupted", "It is a small file"],
         "answer": 1,
         "why": "Near-maximum entropy means the bytes look random - typical of compression, encryption or packing used to evade AV signatures."},
        {"q": "Which is the safest way to analyse a suspicious file?",
         "options": ["Double-click it to see what happens",
                     "Run it on your main PC with AV enabled",
                     "Static analysis first, then detonate in an isolated VM/sandbox",
                     "Email it to colleagues"],
         "answer": 2,
         "why": "Never execute unknown samples on a production machine. Hash it, inspect it statically, then use an isolated, snapshot-able VM with no network."},
    ],
    "forensics": [
        {"q": "In the order of volatility, what should you collect FIRST?",
         "options": ["Hard disk image", "RAM (memory) contents",
                     "Printed documents", "Backup tapes"],
         "answer": 1,
         "why": "Memory is the most volatile - it vanishes on power-off. Capture RAM and network state before shutting anything down."},
        {"q": "Why hash evidence at the moment of acquisition?",
         "options": ["To compress it", "To prove later that it has not been altered",
                     "To encrypt it", "To speed up analysis"],
         "answer": 1,
         "why": "A matching SHA-256 later proves integrity. A mismatch proves tampering. This underpins admissibility."},
        {"q": "Chain of custody documents:",
         "options": ["Only who found the evidence",
                     "Who handled the evidence, when, and what they did, from collection onward",
                     "The cost of the investigation", "The suspect's history"],
         "answer": 1,
         "why": "It is an unbroken, documented record of possession and handling. Gaps can render evidence inadmissible."},
        {"q": "Chrome's History file stores timestamps as:",
         "options": ["Unix seconds since 1970", "Microseconds since 1601 (WebKit epoch)",
                     "ISO-8601 text", "Milliseconds since 2000"],
         "answer": 1,
         "why": "Chromium uses the WebKit epoch: microseconds since 1601-01-01 UTC. Firefox uses microseconds since 1970."},
        {"q": "Why must you work on a COPY of the evidence?",
         "options": ["Copies are faster", "To preserve the original in an unaltered state",
                     "Copies compress better", "The original is encrypted"],
         "answer": 1,
         "why": "Analysis modifies data (timestamps, journals). The original must remain pristine and verifiable against its acquisition hash."},
        {"q": "A write-blocker is used to:",
         "options": ["Encrypt a drive", "Prevent any writes to the evidence drive while reading it",
                     "Delete free space", "Speed up imaging"],
         "answer": 1,
         "why": "It guarantees the acquisition process cannot alter the source media, preserving integrity."},
    ],
    "incident_response": [
        {"q": "Windows Event ID 1102 means:",
         "options": ["A user logged on", "The audit log was CLEARED",
                     "A service started", "A file was deleted"],
         "answer": 1,
         "why": "1102 records that the Security log was cleared - a strong anti-forensics indicator that almost always warrants investigation."},
        {"q": "50 failed logons for one account then a success. This is:",
         "options": ["Normal typing errors", "A likely successful brute-force attack",
                     "A printer problem", "A DNS issue"],
         "answer": 1,
         "why": "Sustained failures followed by success strongly suggests the attacker guessed the password. Treat the account as compromised."},
        {"q": "The FIRST containment step for a compromised laptop is usually:",
         "options": ["Reinstall Windows", "Isolate it from the network",
                     "Delete suspicious files", "Run Disk Cleanup"],
         "answer": 1,
         "why": "Isolation stops C2, lateral movement and exfiltration while preserving evidence. Wiping destroys evidence and may not be necessary yet."},
        {"q": "A few failed logons across MANY different accounts indicates:",
         "options": ["Brute force", "Password spraying", "A DDoS attack", "A backup job"],
         "answer": 1,
         "why": "Spraying tries one or two common passwords against many accounts to stay under lockout thresholds."},
        {"q": "In India, the cyber-fraud financial helpline number is:",
         "options": ["100", "112", "1930", "1800-111-222"],
         "answer": 2,
         "why": "1930 is the national cyber financial fraud helpline. Call within the 'golden hour' to maximise the chance of freezing the money."},
    ],
    "web_security": [
        {"q": "The real fix for SQL injection is:",
         "options": ["Hiding error messages", "Parameterised queries / prepared statements",
                     "Renaming the database", "Using HTTPS"],
         "answer": 1,
         "why": "Parameterisation separates code from data so input can never change the query's structure. Everything else is defence in depth."},
        {"q": "A padlock icon in the browser guarantees:",
         "options": ["The site is legitimate and safe",
                     "The connection is encrypted - nothing about the owner's honesty",
                     "The site is virus-free", "The site is government approved"],
         "answer": 1,
         "why": "Certificates are free and instant. Most phishing sites today use HTTPS. Check the DOMAIN, not the padlock."},
        {"q": "HttpOnly on a cookie prevents:",
         "options": ["Cookie theft via JavaScript (XSS)", "Cookies being sent over HTTP",
                     "Cookie expiry", "Cross-site request forgery"],
         "answer": 0,
         "why": "HttpOnly hides the cookie from document.cookie, blocking the classic XSS session-theft payload. 'Secure' is the flag that forces HTTPS."},
        {"q": "Repeated 404 errors from one IP across many paths suggests:",
         "options": ["A slow network", "Directory/file enumeration scanning",
                     "A browser cache issue", "Normal user browsing"],
         "answer": 1,
         "why": "Tools like dirbuster/gobuster brute-force paths, producing bursts of 404s from a single source."},
    ],
}

# ---------------------------------------------------------------- labs
LABS = [
    {"id": "lab-phish-url", "title": "Lab 1: Dissect a Phishing URL", "level": "Beginner",
     "duration": "10 min", "module": "Phishing Detector", "icon": "🎣",
     "objective": "Learn to read a URL like an analyst and identify the real destination.",
     "scenario": "You receive: 'Your Amazon order could not be delivered. Update your address: "
                 "http://amazon.in.delivery-update.secure-login.xyz/track?id=99213'",
     "steps": [
         "Open the Phishing Detector module and paste the URL.",
         "Identify the REGISTERED domain. Read a domain right-to-left: the registered domain is "
         "the last two labels - here 'secure-login.xyz', NOT amazon.in.",
         "Note the '.xyz' TLD - heavily abused for phishing.",
         "Count the subdomain levels used to bury the real owner.",
         "Check the detector's risk score and read every indicator it raises.",
     ],
     "questions": [
         {"q": "What is the registered domain?", "a": "secure-login.xyz",
          "hint": "The last two labels before the path."},
         {"q": "Why does 'amazon.in' appear at the start?", "a": "To deceive the reader - it is only a subdomain label controlled by the attacker.",
          "hint": "Anyone can create any subdomain on a domain they own."},
     ],
     "takeaway": "Always read a domain from right to left. Everything before the registered domain "
                 "is attacker-controlled decoration."},

    {"id": "lab-email-headers", "title": "Lab 2: Analyse Email Headers", "level": "Beginner",
     "duration": "15 min", "module": "Phishing Detector", "icon": "📧",
     "objective": "Use headers to prove an email is spoofed.",
     "scenario": "From: \"HDFC Bank Security\" <alerts@hdfcbank.com>\nReply-To: recovery.desk909@gmail.com\n"
                 "Received-SPF: fail (domain of hdfcbank.com does not designate 203.0.113.44 as permitted sender)\n"
                 "Authentication-Results: dkim=fail; dmarc=fail\n"
                 "Subject: URGENT: Account suspended - verify within 24 hours",
     "steps": [
         "Paste the full header block into the Phishing Detector (Email mode).",
         "Compare the From domain with the Reply-To domain - a mismatch means replies go to the attacker.",
         "Read the SPF result: 'fail' means the sending server was not authorised by hdfcbank.com.",
         "Read DKIM and DMARC: both failing is conclusive proof of spoofing.",
         "Note the urgency in the subject line - a psychological lever.",
     ],
     "questions": [
         {"q": "Which single header field most conclusively proves spoofing?",
          "a": "Authentication-Results showing SPF/DKIM/DMARC all failing.",
          "hint": "Look for the cryptographic/authorisation verdicts."},
         {"q": "Where would a reply actually go?", "a": "recovery.desk909@gmail.com - the attacker's mailbox.",
          "hint": "Check Reply-To, not From."},
     ],
     "takeaway": "The From field is just text and can say anything. SPF, DKIM and DMARC are the "
                 "cryptographic truth."},

    {"id": "lab-password", "title": "Lab 3: Password Entropy Experiment", "level": "Beginner",
     "duration": "10 min", "module": "Password Analyzer", "icon": "🔐",
     "objective": "See mathematically why length beats complexity.",
     "scenario": "Compare four candidates and observe the crack-time curve.",
     "steps": [
         "Analyse 'P@ssw0rd!' - note the score and the pattern warnings.",
         "Analyse 'Summer2026!' - a very common corporate template.",
         "Analyse 'copper-violin-42-monsoon-Tide'.",
         "Analyse a 20-character random string from the built-in generator.",
         "Compare the entropy in bits and the GPU crack times side by side.",
     ],
     "questions": [
         {"q": "Which scored highest, and why?",
          "a": "The long passphrase/random string - entropy grows linearly with length but only logarithmically with charset size.",
          "hint": "Look at the bits of entropy, not how 'complex' it looks."},
         {"q": "Why is 'P@ssw0rd!' weak despite symbols and digits?",
          "a": "Leetspeak substitutions are in every cracking rule set; the base word is a dictionary word.",
          "hint": "Crackers apply transformation rules to dictionary words."},
     ],
     "takeaway": "A memorable 25-character passphrase beats an unmemorable 9-character 'complex' password."},

    {"id": "lab-file-triage", "title": "Lab 4: Suspicious File Triage", "level": "Intermediate",
     "duration": "20 min", "module": "Malware Analyzer", "icon": "🦠",
     "objective": "Triage an unknown file safely using static analysis only.",
     "scenario": "A colleague forwards 'Invoice_March.pdf' but Windows shows a strange icon.",
     "steps": [
         "Upload the file to the Malware Analyzer - it is never executed.",
         "Compare the declared extension against the TRUE TYPE from magic bytes.",
         "Record the MD5 and SHA-256 hashes for your case notes.",
         "Check entropy: above ~7.2 suggests packing or encryption.",
         "Review flagged signatures, PE sections and suspicious imports.",
         "Read the AI triage verdict and note the recommended containment steps.",
     ],
     "questions": [
         {"q": "Why is a hash more useful than a filename?",
          "a": "Filenames change freely; the hash uniquely identifies the exact bytes and can be shared with other analysts.",
          "hint": "Think about what stays constant."},
         {"q": "What does an entropy of 7.9 usually indicate?",
          "a": "The file is packed, compressed or encrypted - common for malware evading signatures.",
          "hint": "Maximum entropy is 8.0."},
     ],
     "takeaway": "Static analysis answers most triage questions with zero risk of infection."},

    {"id": "lab-evidence", "title": "Lab 5: Build a Defensible Case File", "level": "Intermediate",
     "duration": "25 min", "module": "Evidence Management", "icon": "📁",
     "objective": "Practise acquisition, hashing and chain of custody end to end.",
     "scenario": "A student reports their college email was hacked and money was requested from contacts.",
     "steps": [
         "Create a new case: 'Email Account Compromise - <student name>', priority High, "
         "incident type 'Account Takeover'.",
         "Upload evidence: screenshots of the fraudulent email, the email header text file, "
         "and any bank SMS screenshots. Tag each item.",
         "Observe that MD5/SHA-1/SHA-256 are computed automatically at acquisition.",
         "Open one item and click 'Verify Integrity' - confirm it matches the baseline.",
         "Add custody notes describing where each item came from.",
         "Review the Chain of Custody tab and then generate the case report.",
     ],
     "questions": [
         {"q": "What happens to the verification if a file is modified after acquisition?",
          "a": "The SHA-256 no longer matches the baseline, the item is marked as an integrity failure, and the custody log records the mismatch.",
          "hint": "Hashes are extremely sensitive - one changed bit changes everything."},
         {"q": "Why record who collected each item?",
          "a": "So the evidence can be traced to a responsible person and defended in proceedings.",
          "hint": "Think about court admissibility."},
     ],
     "takeaway": "Evidence is only as strong as its documentation. Hash early, log everything."},

    {"id": "lab-logs", "title": "Lab 6: Detect a Brute-Force Attack in Logs", "level": "Intermediate",
     "duration": "20 min", "module": "Log Analysis", "icon": "📜",
     "objective": "Spot the signature of a successful brute-force intrusion.",
     "scenario": "A Linux server is behaving oddly. You have its auth.log. Use the sample log "
                 "shipped with the platform (Sample Data → auth.log).",
     "steps": [
         "Load the sample auth.log into the Log Analysis module.",
         "Look at the count of 'Failed password' entries and group them by source IP.",
         "Find whether any 'Accepted password' event follows from the SAME IP.",
         "Check for post-login activity: useradd, usermod -G sudo, cron changes.",
         "Read the AI attack narrative and build your own timeline.",
     ],
     "questions": [
         {"q": "What single observation confirms the attack SUCCEEDED?",
          "a": "An 'Accepted password' from an IP that had many prior 'Failed password' entries.",
          "hint": "Failure followed by success from the same source."},
         {"q": "What did the attacker do for persistence?",
          "a": "Created a new user and added it to a privileged group (and/or modified cron).",
          "hint": "Look for account and scheduling changes after the login."},
     ],
     "takeaway": "Correlation across events - not any single line - reveals the attack story."},

    {"id": "lab-browser", "title": "Lab 7: Browser History Investigation", "level": "Intermediate",
     "duration": "20 min", "module": "Browser Forensics", "icon": "🌐",
     "objective": "Reconstruct user activity and find the infection moment.",
     "scenario": "A laptop is infected. You must find how the malware arrived.",
     "steps": [
         "Load the sample browser history export (Sample Data → browser_history.csv).",
         "Review the flagged URL categories and the phishing-pattern findings.",
         "Examine downloads: file type, source URL, and timestamp.",
         "Build a mini timeline: search → visit → download → execution.",
         "Note that saved-password VALUES are never extracted - only metadata.",
     ],
     "questions": [
         {"q": "Which visit immediately preceded the risky download?",
          "a": "The crack/keygen or fake-installer site identified in the flagged URLs.",
          "hint": "Sort by timestamp around the download event."},
         {"q": "Why is a download from a 'crack' site high risk?",
          "a": "Cracked software is a primary malware distribution channel - the payload is bundled with the crack.",
          "hint": "Think about the attacker's incentive."},
     ],
     "takeaway": "Browser artefacts usually contain the exact moment of compromise."},

    {"id": "lab-memory", "title": "Lab 8: Memory Dump Triage", "level": "Advanced",
     "duration": "30 min", "module": "Memory Forensics", "icon": "🧠",
     "objective": "Extract attacker activity from volatile memory.",
     "scenario": "You captured RAM from a suspected compromised workstation.",
     "steps": [
         "Load the sample memory image (Sample Data → sample_memory.raw).",
         "Review carved process names - look for masquerades like 'svch0st.exe'.",
         "Check network artefacts for connections on ports 4444, 1337 or 50050.",
         "Inspect recovered command lines for encoded PowerShell.",
         "Look at credential material and persistence artefacts.",
         "Read the AI assessment and map the findings to attacker techniques.",
     ],
     "questions": [
         {"q": "Why is 'svch0st.exe' immediately suspicious?",
          "a": "It masquerades as the legitimate svchost.exe using a zero instead of the letter o.",
          "hint": "Compare the characters carefully."},
         {"q": "Why capture RAM before shutting down?",
          "a": "Memory is volatile - processes, injected code, keys and connections are lost on power-off.",
          "hint": "Order of volatility."},
     ],
     "takeaway": "Memory reveals what disk cannot: what was actually RUNNING."},

    {"id": "lab-ir", "title": "Lab 9: Full Incident Response Simulation", "level": "Advanced",
     "duration": "45 min", "module": "All modules", "icon": "🚨",
     "objective": "Run a complete investigation from alert to report.",
     "scenario": "A small business reports: an employee opened an email attachment, and now files "
                 "are encrypted and ₹2,00,000 has left the company account.",
     "steps": [
         "Create a case with priority Critical, incident type 'Malware/Ransomware'.",
         "Analyse the phishing email in the Phishing Detector; attach the result to the case.",
         "Analyse the attachment in the Malware Analyzer; register its hashes as IOCs.",
         "Load the server logs into Log Analysis and identify the compromise timeline.",
         "Add every artefact as evidence with proper tags and custody notes.",
         "Ask the AI Assistant for a containment plan and immediate actions.",
         "Generate the final investigation report (HTML/Markdown) from the case page.",
     ],
     "questions": [
         {"q": "What is the very first containment action?",
          "a": "Isolate affected systems from the network, and call 1930 to attempt to freeze the transferred funds.",
          "hint": "Stop the bleeding, then preserve evidence."},
         {"q": "Which evidence is most time-critical?",
          "a": "Volatile memory and live network state - plus the bank transaction trail within the golden hour.",
          "hint": "What disappears fastest?"},
     ],
     "takeaway": "Real incidents need parallel tracks: containment, evidence preservation, "
                 "and financial reporting - all at once."},
]

# ---------------------------------------------------------------- phishing simulator
SIM_EMAILS = [
    {"id": "sim1", "phishing": True, "from_name": "Netflix Support",
     "from_addr": "no-reply@netflix-billing-update.com",
     "subject": "Your membership will be cancelled today",
     "body": "Dear Customer,\n\nWe were unable to process your last payment. Your Netflix "
             "membership will be CANCELLED within 24 hours unless you update your billing "
             "information immediately.\n\nUpdate now: http://netflix-billing-update.com/verify\n\n"
             "Failure to act will result in permanent loss of your account and viewing history.\n\n"
             "Netflix Billing Team",
     "clues": ["Sender domain is 'netflix-billing-update.com', not netflix.com",
               "Generic greeting 'Dear Customer'",
               "Artificial 24-hour deadline",
               "Threat of permanent loss",
               "Link goes to the attacker-controlled domain"]},
    {"id": "sim2", "phishing": False, "from_name": "GitHub",
     "from_addr": "noreply@github.com",
     "subject": "[GitHub] A third-party OAuth application has been added",
     "body": "Hey there,\n\nA third-party OAuth application (VS Code) with read:user scope was "
             "recently authorized to access your account.\n\nVisit https://github.com/settings/"
             "security-log for more information.\n\nIf you believe this was done in error, you "
             "can revoke access at any time from your settings page.\n\nThanks,\nThe GitHub Team",
     "clues": ["Legitimate github.com domain",
               "No urgency or threats",
               "Directs you to settings rather than asking for credentials",
               "Informational notification, matches a real action you took"]},
    {"id": "sim3", "phishing": True, "from_name": "HR Department",
     "from_addr": "hr.payroll@company-hr-portal.net",
     "subject": "Salary Revision 2026 - Action Required",
     "body": "Dear Employee,\n\nPlease find attached your revised salary structure effective this "
             "month. Kindly review and confirm within 2 days.\n\nAttachment: "
             "Salary_Revision_2026.pdf.exe\n\nNote: You must enable macros to view the document "
             "correctly.\n\nRegards,\nHR Team",
     "clues": ["External domain 'company-hr-portal.net' pretending to be internal HR",
               "Double extension: .pdf.exe means it is an EXECUTABLE",
               "'Enable macros' is a classic malware instruction",
               "Salary bait exploits curiosity",
               "Generic 'Dear Employee' with no name"]},
    {"id": "sim4", "phishing": True, "from_name": "SBI Bank",
     "from_addr": "sbi.alerts@gmail.com",
     "subject": "KYC Verification Pending - Account will be frozen",
     "body": "Dear SBI Customer,\n\nYour KYC is pending. As per RBI guidelines your account will "
             "be FROZEN today if KYC is not completed.\n\nComplete KYC: http://bit.ly/sbi-kyc-now\n\n"
             "You will need: Account number, Registered mobile, Debit card number, CVV and OTP.\n\n"
             "SBI Customer Care",
     "clues": ["A bank sending from a gmail.com address",
               "Shortened URL hides the real destination",
               "Asks for CVV and OTP - no bank ever does this",
               "Fake RBI authority and freezing threat",
               "Same-day deadline creates panic"]},
    {"id": "sim5", "phishing": False, "from_name": "Google",
     "from_addr": "no-reply@accounts.google.com",
     "subject": "Security alert: new sign-in on Windows",
     "body": "Your Google Account was just signed in to from a new Windows device.\n\n"
             "If this was you, you don't need to do anything.\n\nIf not, we'll help you secure "
             "your account: https://myaccount.google.com/notifications\n\nYou received this email "
             "to let you know about important changes to your Google Account.",
     "clues": ["Genuine accounts.google.com domain",
               "Link points to the real myaccount.google.com",
               "No credentials requested",
               "Calm, informational tone with no deadline"]},
    {"id": "sim6", "phishing": True, "from_name": "IT Helpdesk",
     "from_addr": "itsupport@0ffice365-support.com",
     "subject": "Mailbox storage full - messages will be deleted",
     "body": "Your mailbox has exceeded its storage quota (9.8 GB of 10 GB).\n\nIncoming messages "
             "will be REJECTED and existing mail deleted in 12 hours unless you increase your "
             "quota.\n\nClick here to keep your mailbox active: "
             "http://0ffice365-support.com/quota/login.php\n\nSign in with your work email and "
             "password to continue.\n\nIT Helpdesk",
     "clues": ["Domain uses a ZERO instead of the letter O: '0ffice365'",
               "12-hour deadline with threat of data loss",
               "Asks you to sign in with your work password on an external site",
               "IT departments do not manage quotas via public links"]},
]

# ---------------------------------------------------------------- paths
LEARNING_PATHS = [
    {"id": "path-beginner", "title": "Cyber Safety Essentials", "level": "Beginner",
     "icon": "🛡️", "duration": "2-3 hours",
     "description": "Everything a normal internet user needs to stay safe online.",
     "steps": ["Read: How phishing works", "Quiz: Phishing Awareness",
               "Lab 1: Dissect a Phishing URL", "Lab 3: Password Entropy Experiment",
               "Quiz: Password Security", "Phishing Simulator: score 5/6 or better",
               "Read: Daily cyber hygiene checklist"]},
    {"id": "path-responder", "title": "Incident Responder Track", "level": "Intermediate",
     "icon": "🚨", "duration": "6-8 hours",
     "description": "Learn to detect, analyse and contain security incidents.",
     "steps": ["Quiz: Malware Fundamentals", "Lab 4: Suspicious File Triage",
               "Lab 6: Detect a Brute-Force Attack", "Quiz: Incident Response",
               "Lab 7: Browser History Investigation", "Read: Incident response steps",
               "Lab 9: Full Incident Response Simulation"]},
    {"id": "path-forensics", "title": "Digital Forensics Investigator", "level": "Advanced",
     "icon": "🔍", "duration": "10-12 hours",
     "description": "Acquire, preserve and analyse digital evidence defensibly.",
     "steps": ["Read: Digital forensics fundamentals", "Read: Chain of custody",
               "Quiz: Digital Forensics", "Lab 5: Build a Defensible Case File",
               "Lab 7: Browser History Investigation", "Lab 8: Memory Dump Triage",
               "Lab 9: Full Incident Response Simulation", "Generate a full case report"]},
]

TOPIC_LABELS = {"phishing": "Phishing Awareness", "passwords": "Password Security",
                "malware": "Malware Fundamentals", "forensics": "Digital Forensics",
                "incident_response": "Incident Response", "web_security": "Web Security"}


# ---------------------------------------------------------------- API
def get_quiz(topic: str, n: int = 5) -> list[dict]:
    bank = QUIZ_BANK.get(topic, [])
    picks = random.sample(bank, min(n, len(bank))) if bank else []
    return [{"index": i, "q": q["q"], "options": q["options"]} for i, q in enumerate(picks)], picks


def grade_quiz(topic: str, picks: list[dict], answers: list[int], user="student") -> dict:
    correct, detail = 0, []
    for i, q in enumerate(picks):
        given = answers[i] if i < len(answers) else -1
        ok = (given == q["answer"])
        correct += ok
        detail.append({"q": q["q"], "your_answer": q["options"][given] if 0 <= given < len(q["options"]) else "(no answer)",
                       "correct_answer": q["options"][q["answer"]], "correct": ok, "why": q["why"]})
    total = len(picks)
    pct = round(correct / total * 100) if total else 0
    execute("INSERT INTO quiz_results(user,topic,score,total,detail,created_at) VALUES(?,?,?,?,?,?)",
            (user, topic, correct, total, json.dumps(detail), utcnow()))
    return {"score": correct, "total": total, "percent": pct, "detail": detail,
            "grade": "Excellent" if pct >= 85 else "Good" if pct >= 70 else
                     "Needs practice" if pct >= 50 else "Study more",
            "topic_label": TOPIC_LABELS.get(topic, topic)}


def get_lab(lab_id: str) -> dict | None:
    return next((l for l in LABS if l["id"] == lab_id), None)


def mark_lab(user: str, lab_id: str, status="completed", score=100):
    execute("""INSERT INTO lab_progress(user,lab_id,status,score,created_at) VALUES(?,?,?,?,?)
               ON CONFLICT(user,lab_id) DO UPDATE SET status=excluded.status,
               score=excluded.score, created_at=excluded.created_at""",
            (user, lab_id, status, score, utcnow()))


def progress(user="student") -> dict:
    quizzes = query("SELECT topic, MAX(score) AS best, MAX(total) AS total, COUNT(*) AS attempts "
                    "FROM quiz_results WHERE user=? GROUP BY topic", (user,))
    for q in quizzes:
        q["label"] = TOPIC_LABELS.get(q["topic"], q["topic"])
        q["percent"] = round(q["best"] / q["total"] * 100) if q["total"] else 0
    labs_done = query("SELECT lab_id,status,score,created_at FROM lab_progress "
                      "WHERE user=? AND status='completed'", (user,))
    done_ids = {l["lab_id"] for l in labs_done}
    total_items = len(LABS) + len(QUIZ_BANK)
    completed = len(done_ids) + len(quizzes)
    return {
        "quizzes": quizzes,
        "labs_completed": sorted(done_ids),
        "labs_total": len(LABS),
        "quizzes_total": len(QUIZ_BANK),
        "overall_percent": round(completed / total_items * 100) if total_items else 0,
        "attempts": scalar("SELECT COUNT(*) FROM quiz_results WHERE user=?", (user,)),
        "avg_score": round(scalar(
            "SELECT COALESCE(AVG(score*100.0/total),0) FROM quiz_results WHERE user=? AND total>0",
            (user,)) or 0),
        "badges": _badges(quizzes, done_ids),
    }


def _badges(quizzes, labs_done) -> list[dict]:
    b = []
    if quizzes:
        b.append({"icon": "🎓", "name": "First Steps", "desc": "Completed your first quiz"})
    if any(q["percent"] == 100 for q in quizzes):
        b.append({"icon": "💯", "name": "Perfect Score", "desc": "Scored 100% on a quiz"})
    if len(quizzes) >= 3:
        b.append({"icon": "📚", "name": "Well Read", "desc": "Attempted 3+ quiz topics"})
    if len(quizzes) >= len(QUIZ_BANK):
        b.append({"icon": "🏆", "name": "Quiz Master", "desc": "Attempted every quiz topic"})
    if labs_done:
        b.append({"icon": "🔬", "name": "Hands On", "desc": "Completed your first lab"})
    if len(labs_done) >= 5:
        b.append({"icon": "🕵️", "name": "Investigator", "desc": "Completed 5+ labs"})
    if len(labs_done) >= len(LABS):
        b.append({"icon": "🥇", "name": "Lab Champion", "desc": "Completed every lab"})
    return b


def ai_generate_quiz(topic: str, n: int = 5, difficulty: str = "beginner") -> dict:
    schema = ("""{"questions":[{"q":"question text","options":["a","b","c","d"],"""
              """"answer":0,"why":"explanation"}]}""")
    prompt = (f"Create {n} multiple-choice questions about {topic} for a {difficulty}-level "
              f"cybersecurity student in India. Exactly 4 options each. 'answer' is the 0-based "
              f"index of the correct option. Include a one-or-two sentence 'why' explanation. "
              f"Make them practical and scenario-based, not definition recall.")
    res = ollama_client.generate_json(prompt, schema,
                                      system="You are a cybersecurity instructor writing exam questions.",
                                      temperature=0.7, max_tokens=1200)
    if not res["ok"]:
        return {"available": False, "error": res.get("error")}
    qs = res["data"].get("questions", [])
    clean = []
    for q in qs[:n]:
        opts = q.get("options", [])
        if isinstance(opts, list) and len(opts) >= 2 and isinstance(q.get("q"), str):
            try:
                ans = int(q.get("answer", 0))
            except (TypeError, ValueError):
                ans = 0
            clean.append({"q": q["q"], "options": opts[:4],
                          "answer": max(0, min(ans, len(opts[:4]) - 1)),
                          "why": str(q.get("why", ""))[:400]})
    return {"available": bool(clean), "questions": clean, "model": res.get("model")}


def ai_explain(topic: str, level: str = "beginner") -> dict:
    res = ollama_client.generate(
        f"Explain '{topic}' to a {level} cybersecurity learner. Structure: what it is, how it "
        f"works, a real-world example (Indian context if relevant), and 3 practical defences. "
        f"Use markdown headings and keep it under 350 words.",
        system="You are a friendly cybersecurity teacher. Clear, concrete, no jargon without explanation.",
        temperature=0.4, max_tokens=650)
    return {"available": res["ok"], "text": res.get("text", ""), "model": res.get("model")}


def grade_sim(answers: dict) -> dict:
    """answers = {sim_id: 'phishing'|'legitimate'}"""
    correct, detail = 0, []
    for e in SIM_EMAILS:
        given = answers.get(e["id"])
        if not given:
            continue
        expected = "phishing" if e["phishing"] else "legitimate"
        ok = given == expected
        correct += ok
        detail.append({"id": e["id"], "subject": e["subject"], "your_answer": given,
                       "correct_answer": expected, "correct": ok, "clues": e["clues"]})
    total = len(detail)
    pct = round(correct / total * 100) if total else 0
    execute("INSERT INTO quiz_results(user,topic,score,total,detail,created_at) VALUES(?,?,?,?,?,?)",
            ("student", "phishing_simulator", correct, total, json.dumps(detail), utcnow()))
    return {"score": correct, "total": total, "percent": pct, "detail": detail,
            "grade": ("Excellent - you would not fall for these" if pct >= 85 else
                      "Good, but stay careful" if pct >= 70 else
                      "Risky - review the clues below" if pct >= 50 else
                      "High risk - please study the phishing module")}
