"""
Module 1 -- AI Phishing Detector.

Hybrid design:
  1. Deterministic heuristic engine (works offline, explainable, instant).
  2. Local Ollama LLM second opinion (semantic/social-engineering understanding).
Final score fuses both. Handles URLs, emails and SMS.
"""
from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import unquote, urlparse

from core import ollama_client
from core.utils import (URL_RE, clamp, extract_iocs, risk_label, shannon_entropy)

# ------------------------------------------------------------------ data
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "gq", "cf", "ml", "tk", "ga",
    "work", "loan", "review", "country", "stream", "download", "racing", "win",
    "bid", "date", "faith", "science", "party", "trade", "accountant", "cam",
    "rest", "buzz", "monster", "quest", "sbs", "cfd", "icu", "shop", "fit",
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "bit.do",
    "shorte.st", "adf.ly", "t.ly", "urlz.fr", "clck.ru", "s.id",
}
BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook", "instagram",
    "netflix", "whatsapp", "linkedin", "dropbox", "adobe", "chase", "hdfc",
    "icici", "sbi", "axis", "kotak", "paytm", "phonepe", "gpay", "flipkart",
    "myntra", "irctc", "aadhaar", "uidai", "incometax", "gst", "epfo", "dhl",
    "fedex", "usps", "bluedart", "coinbase", "binance", "metamask", "steam",
    "outlook", "office365", "icloud", "zoom", "telegram", "swiggy", "zomato",
]
LEGIT_DOMAINS = {
    "paypal.com", "amazon.com", "amazon.in", "apple.com", "microsoft.com",
    "google.com", "facebook.com", "instagram.com", "netflix.com", "whatsapp.com",
    "linkedin.com", "dropbox.com", "adobe.com", "hdfcbank.com", "icicibank.com",
    "onlinesbi.sbi", "axisbank.com", "paytm.com", "phonepe.com", "flipkart.com",
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in", "epfindia.gov.in",
    "dhl.com", "fedex.com", "coinbase.com", "binance.com", "outlook.com",
    "icloud.com", "zoom.us", "telegram.org", "github.com", "cybercrime.gov.in",
}
URGENCY = [
    "urgent", "immediately", "act now", "within 24 hours", "expire", "expiring",
    "suspended", "suspension", "blocked", "locked", "deactivat", "terminat",
    "final notice", "last warning", "limited time", "hurry", "asap", "right away",
    "failure to", "will be closed", "avoid closure", "immediate action",
]
CREDENTIAL_BAIT = [
    "verify your account", "confirm your identity", "update your payment",
    "re-enter your password", "validate your login", "confirm your password",
    "click here to login", "sign in to continue", "verify now", "update kyc",
    "kyc pending", "kyc expired", "re-verify", "unlock your account",
    "confirm your card", "update billing", "verify your upi",
]
REWARD_BAIT = [
    "you have won", "congratulations", "lottery", "prize", "lucky winner",
    "claim your", "free gift", "cash reward", "refund of", "you are selected",
    "job offer", "work from home", "earn daily", "part time job", "₹", "$",
    "crore", "lakh", "bonus", "cashback", "reward points expiring",
]
THREAT_WORDS = [
    "legal action", "police", "arrest", "court", "penalty", "fine", "lawsuit",
    "fir", "cyber cell", "your account will be", "unauthorized transaction",
    "suspicious login", "data breach detected", "virus detected", "warrant",
]
SENSITIVE_ASK = [
    "otp", "one time password", "cvv", "pin number", "atm pin", "net banking password",
    "aadhaar number", "pan card", "card number", "expiry date", "upi pin",
    "seed phrase", "recovery phrase", "private key", "wallet key", "mpin",
]
# ------------------------------------------------------------------
# Scam archetypes.
#
# The keyword lists above catch classic Western credential phishing, but most
# real-world losses in India come from a small set of highly repeatable social
# -engineering scripts. Each entry here is a near-conclusive pattern on its own,
# so they carry heavy weight. (pattern, severity, points, title, explanation)
# ------------------------------------------------------------------
SCAM_ARCHETYPES = [
    (r"(parcel|package|courier|shipment|consignment).{0,40}"
     r"(hold|held|stuck|pending|custom|clearance|detain|seiz|undeliver|fail)",
     "critical", 34, "Parcel / customs delivery scam",
     "A fake courier or customs notice asking for a small 'clearance' fee. The payment page "
     "harvests your card details. Real couriers do not collect duty by SMS link."),

    (r"(custom|customs)\s*(duty|charge|clearance|fee)|clearance\s*(fee|charge)",
     "critical", 32, "Customs fee demand",
     "Customs duty is never collected through an SMS link or a personal UPI ID."),

    (r"\b(kbc|kaun banega)\b|lucky\s*draw|lottery|jackpot|"
     r"you\s*(have\s*)?(won|win)\b|prize\s*money|bumper\s*(prize|draw)",
     "critical", 34, "Lottery / prize scam",
     "You cannot win a lottery you never entered. KBC and 'lucky draw' messages are the single "
     "most common prize fraud in India. Any 'processing fee' you pay is lost."),

    (r"(this is my |i have a |saved? my )?new (number|mobile|whatsapp)\b|"
     r"changed my number|using new sim",
     "high", 28, "'New number' impersonation",
     "Attackers pose as a family member or boss from an unknown number, then request money. "
     "Always call the person back on their ORIGINAL saved number before sending anything."),

    (r"\b(hi|hello|hey)\s*(mum|mom|mummy|dad|papa|beta|son|daughter|uncle|aunty)\b",
     "high", 26, "Family impersonation opener",
     "A classic opener for the 'relative in trouble' scam. Verify by calling the known number."),

    (r"(electricity|power|bill).{0,40}(disconnect|cut off|discontinu|suspend)|"
     r"(disconnect|cut).{0,25}(tonight|today|electricity|power supply)",
     "critical", 34, "Electricity disconnection scam",
     "A fake power-board warning that your supply is cut tonight unless you call or pay. "
     "Boards never threaten same-night disconnection by SMS. The callback number is the scammer."),

    (r"digital\s*arrest|under\s*arrest.{0,30}(video|call|online)|"
     r"(cbi|ed|ncb|narcotics|customs|police|cyber\s*cell|crime\s*branch)\b.{0,60}"
     r"(arrest|case|fir|warrant|investigation|video\s*call)",
     "critical", 40, "'Digital arrest' intimidation scam",
     "Indian police, CBI, ED and NCB NEVER arrest, interrogate or demand money over a video "
     "call. This script terrifies victims into transferring their savings. Disconnect and "
     "call 1930."),

    (r"(anydesk|teamviewer|quicksupport|ultraviewer|rustdesk|airdroid|screen\s*shar|"
     r"remote\s*(access|desktop|support)\s*app)",
     "critical", 38, "Remote-access / screen-sharing request",
     "Installing AnyDesk, TeamViewer or similar at someone's request hands them live control of "
     "your phone or PC. This is how accounts are emptied in minutes. No genuine support agent "
     "needs it."),

    (r"(send|share|upload|submit|provide).{0,30}"
     r"(aadhaar|aadhar|pan\s*card|passport|voter\s*id|driving\s*licen|cancelled\s*cheque|"
     r"bank\s*(detail|statement)|selfie\s*with)",
     "critical", 32, "Identity-document request",
     "Sharing Aadhaar, PAN or a selfie holding your ID enables loans and accounts opened in "
     "your name. No legitimate service collects these over chat."),

    (r"(refund|cashback|claim).{0,40}(pending|process|initiat|approv|credit)|"
     r"(pending|unclaimed).{0,20}(refund|cashback|amount)",
     "high", 26, "Fake refund scam",
     "A fake refund that requires you to 'verify' by entering card details or approving a "
     "collect request. A real refund arrives without any action from you."),

    (r"(pay|send|transfer|deposit).{0,25}(rs\.?|inr|₹)\s*\d{1,5}\b|"
     r"(rs\.?|inr|₹)\s*\d{1,4}\s*(only|processing|handling|registration|activation|refundable)",
     "high", 24, "Small advance-fee lure",
     "Scams ask for a small, believable amount (₹10–₹5,000) because victims pay without "
     "thinking. The fee is the fraud, or the payment page steals your card."),

    (r"(work|job|part[\s-]?time).{0,30}(from home|daily payment|no experience)|"
     r"earn.{0,20}(rs\.?|inr|₹)?\s*\d{3,}.{0,15}(per\s*day|daily|a\s*day)|"
     r"(like|rate|review).{0,20}(video|product|hotel).{0,20}(earn|task|paid)",
     "critical", 32, "Task-based job / 'like and earn' scam",
     "Victims are paid small amounts first to build trust, then asked to deposit larger sums "
     "for 'premium tasks' which are never returned."),

    (r"(instant|quick|urgent)\s*loan|loan\s*(approv|sanction|disburs).{0,25}"
     r"(instant|minute|without)|no\s*(document|cibil)\s*loan",
     "high", 26, "Instant-loan app scam",
     "Predatory loan apps harvest your contacts and photos, then blackmail you. Only borrow "
     "from RBI-registered lenders."),

    (r"(verify|update|complete|re-?submit).{0,20}(kyc|k\.y\.c)|kyc\s*(pending|expir|"
     r"incomplete|suspend|fail|update)",
     "high", 28, "KYC update scam",
     "Banks and wallets never collect KYC through an SMS link. This is the most common Indian "
     "banking phishing pretext."),

    (r"(call|contact|dial|whatsapp)\s*(us\s*)?(on|at|to)?\s*(\+?91[\s-]?)?[6-9]\d{9}",
     "medium", 18, "Callback number in message",
     "A mobile number as 'customer care' is a hallmark of fraud. Official helplines are "
     "landlines or toll-free numbers published on the company's own website."),

    # Matches either word order: "account will be blocked" and "block your account".
    (r"((block|freez|suspend|deactivat|clos|disabl)\w*\b.{0,30}\b(account|card|sim|service)|"
     r"\b(account|card|sim|service)\b.{0,40}(block|freez|suspend|deactivat|clos|disabl)\w*)"
     r".{0,40}(today|tonight|within|24\s*hour|48\s*hour|immediate|at once|soon)",
     "high", 26, "Account-blocking threat",
     "A same-day deadline is engineered panic. Log in through the official app to check."),

    (r"((otp|one\s*time\s*password|verification\s*code)\b.{0,30}"
     r"\b(share|send|tell|forward|provide|give|read\s*out)\b|"
     r"\b(share|send|tell|forward|provide|give|read\s*out)\b.{0,25}"
     r"(otp|one\s*time\s*password|verification\s*code))",
     "critical", 38, "OTP handover request",
     "An OTP is the last line of defence on your account. Anyone asking you to share it — in "
     "any wording, for any reason — is committing fraud."),

    (r"\b(army|military|defence|defense|soldier|jawan|crpf|bsf|"
     r"major|colonel|captain|lieutenant|brigadier|subedar|havildar)\b"
     r".{0,60}(posting|transfer|deploy|unit|urgent|buy|sell|advance|payment|cantonment)",
     "high", 26, "Fake armed-forces buyer scam",
     "Fraudsters pose as army personnel on marketplace apps (OLX, Quikr), claim an urgent "
     "posting, and send a fake payment screenshot or a QR code that debits you instead."),

    (r"scan.{0,20}qr.{0,25}(receive|get|claim|refund)|"
     r"qr\s*code.{0,25}(receive|credit|refund|cashback)",
     "critical", 34, "QR-to-receive-money scam",
     "You NEVER scan a QR code or enter a PIN to RECEIVE money. Scanning and approving always "
     "SENDS money out of your account."),
]

# Whole-message exemptions. If one of these matches ANYWHERE in the text, the
# named archetype is suppressed. This is what separates a genuine bank OTP alert
# ("never share this OTP") from a fraudster asking you to hand it over.
ARCHETYPE_EXEMPTIONS = {
    "OTP handover request": re.compile(
        r"\b(do\s*not|do\s?n'?t|never|no\s*one|nobody|not)\s+"
        r"(share|disclose|reveal|give|tell|forward|provide)\b"
        r"|\bsharing\s+(it|this|otp)\s+is\s+(unsafe|risky|prohibited)\b"
        r"|\bbank\s+never\s+asks\b", re.I),
    "Callback number in message": re.compile(
        r"\b1800[\s-]?\d{3,}|\b1930\b|\b1909\b|toll[\s-]?free", re.I),
    # A refund already completed is normal. A refund that is "pending" and needs
    # you to click, verify or approve something is the scam.
    "Fake refund scam": re.compile(
        r"\b(has\s*been|was|is)\s+(credited|refunded|processed|transferred)\b"
        r"|\brefund(ed)?\s+(to|into)\s+your\s+(original|source|bank|account|card)\b"
        r"|\bcredited\s+to\s+your\b", re.I),
}

SUSPICIOUS_ATTACH = {
    ".exe", ".scr", ".vbs", ".js", ".jar", ".bat", ".cmd", ".ps1", ".hta",
    ".iso", ".img", ".lnk", ".apk", ".msi", ".pif", ".com", ".docm", ".xlsm",
    ".pptm", ".zip", ".rar", ".7z", ".ace", ".gz",
}
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ʟ": "l", "ᴏ": "o", "0": "o",
    "1": "l", "3": "e", "5": "s", "@": "a", "$": "s", "rn": "m", "vv": "w",
}


# ------------------------------------------------------------------ helpers
def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalize_homoglyphs(s: str) -> str:
    out = s.lower()
    for bad, good in HOMOGLYPHS.items():
        out = out.replace(bad, good)
    return out


def _registered_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    two_level = {"co.in", "co.uk", "com.au", "gov.in", "ac.in", "net.in",
                 "org.in", "co.jp", "com.br", "co.za", "org.uk"}
    if ".".join(parts[-2:]) in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _hit(findings, sev, title, detail, points):
    findings.append({"severity": sev, "title": title, "detail": detail, "points": points})


# ------------------------------------------------------------------ URL engine
def analyze_url_rules(raw_url: str) -> dict:
    findings, score = [], 0
    url = (raw_url or "").strip()
    if not url:
        return {"score": 0, "findings": [], "parsed": {}}
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.I):
        url = "http://" + url
    try:
        p = urlparse(url)
    except ValueError:
        return {"score": 60, "findings": [{"severity": "high", "title": "Unparseable URL",
                "detail": "The URL structure is malformed.", "points": 60}], "parsed": {}}

    host = (p.hostname or "").lower()
    path = unquote(p.path or "")
    qs = unquote(p.query or "")
    full = url.lower()
    reg = _registered_domain(host)

    # 1. scheme
    if p.scheme == "http":
        _hit(findings, "medium", "No HTTPS encryption",
             "Traffic is unencrypted; credentials could be intercepted.", 12)
    elif p.scheme not in ("http", "https"):
        _hit(findings, "high", f"Unusual scheme '{p.scheme}'",
             "Non-web schemes are often used to launch local handlers.", 25)

    # 2. IP literal host
    try:
        ipaddress.ip_address(host)
        _hit(findings, "critical", "Raw IP address instead of domain",
             f"Host is the IP {host}. Legitimate brands use domain names.", 30)
    except ValueError:
        pass

    # 3. userinfo trick  http://apple.com@evil.tld
    if "@" in (p.netloc or ""):
        _hit(findings, "critical", "Credential/userinfo obfuscation (@)",
             "Text before '@' is ignored by browsers - the real host is after it.", 32)

    # 4. punycode / homoglyph
    if "xn--" in host:
        _hit(findings, "critical", "Punycode (IDN homograph) domain",
             "Non-Latin characters can perfectly imitate a real brand.", 30)
    norm = _normalize_homoglyphs(host)
    if norm != host:
        _hit(findings, "high", "Homoglyph characters in hostname",
             f"'{host}' normalizes to '{norm}' - look-alike character substitution.", 22)

    # 5. TLD reputation
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        _hit(findings, "high", f"High-abuse TLD '.{tld}'",
             "This TLD is disproportionately used for phishing and malware.", 18)

    # 6. shortener
    if reg in URL_SHORTENERS:
        _hit(findings, "medium", "URL shortener hides destination",
             f"'{reg}' masks where the link really goes. Expand before clicking.", 16)

    # 7. brand impersonation
    hostpath = host + path.lower()
    for brand in BRANDS:
        if brand in hostpath:
            if reg in LEGIT_DOMAINS or reg.endswith(f"{brand}.com"):
                continue
            where = "subdomain/path" if brand not in reg else "domain"
            _hit(findings, "critical", f"Brand impersonation: '{brand}'",
                 f"The brand name appears in the {where} but the real domain is '{reg}'.", 28)
            break

    # 8. typosquatting distance
    core = reg.split(".")[0]
    for legit in LEGIT_DOMAINS:
        lc = legit.split(".")[0]
        if len(core) > 3 and core != lc:
            d = _levenshtein(core, lc)
            if d == 1:
                _hit(findings, "critical", f"Typosquat of '{legit}'",
                     f"'{reg}' differs from '{legit}' by a single character.", 30)
                break
            if d == 2 and len(lc) > 5:
                _hit(findings, "high", f"Close look-alike of '{legit}'",
                     f"'{reg}' is 2 edits away from '{legit}'.", 20)
                break

    # 9. subdomain depth
    depth = host.count(".")
    if depth >= 4:
        _hit(findings, "high", "Excessive subdomain nesting",
             f"{depth} dots in hostname - used to bury the real domain off-screen.", 16)
    elif depth == 3:
        _hit(findings, "medium", "Deep subdomain structure",
             "Multiple subdomain levels can hide the true owner.", 8)

    # 10. hyphens / length / digits
    if host.count("-") >= 3:
        _hit(findings, "medium", "Many hyphens in hostname",
             "Phishing kits chain keywords with hyphens (e.g. secure-login-verify).", 12)
    if len(url) > 100:
        _hit(findings, "medium", "Very long URL",
             f"{len(url)} characters - length is used to obscure the destination.", 10)
    digits = sum(c.isdigit() for c in host)
    if digits >= 5:
        _hit(findings, "medium", "Digit-heavy hostname",
             "Auto-generated malicious hosts often contain long digit runs.", 10)

    # 11. sensitive keywords in URL
    kw = ["login", "signin", "verify", "secure", "account", "update", "confirm",
          "banking", "password", "webscr", "wallet", "kyc", "otp", "recover",
          "unlock", "billing", "invoice", "payment", "auth", "session"]
    found_kw = [k for k in kw if k in hostpath or k in qs.lower()]
    if len(found_kw) >= 3:
        _hit(findings, "high", "Credential-harvest keyword cluster",
             "Contains: " + ", ".join(found_kw[:6]), 18)
    elif found_kw:
        _hit(findings, "low", "Security-themed keywords in URL",
             "Contains: " + ", ".join(found_kw), 6)

    # 12. deceptive extension / double extension
    if re.search(r"\.(exe|apk|scr|zip|rar|msi|jar|bat|dmg)(\?|$)", full):
        _hit(findings, "critical", "Direct executable download link",
             "The URL points straight at an installable/executable payload.", 26)
    if re.search(r"\.(pdf|doc|jpg|png|xls)\.(exe|scr|js|vbs|zip)", full):
        _hit(findings, "critical", "Double file extension",
             "Disguises an executable as a harmless document.", 30)

    # 13. open redirect
    if re.search(r"[?&](url|redirect|next|return|continue|target|dest|goto|r)=https?", full):
        _hit(findings, "high", "Open-redirect parameter",
             "A trusted domain is being used to bounce victims to an attacker site.", 20)

    # 14. encoded payloads
    if full.count("%") >= 6:
        _hit(findings, "medium", "Heavy URL encoding",
             "Percent-encoding is used to hide keywords from filters.", 12)
    if re.search(r"(data:text/html|javascript:|base64,)", full):
        _hit(findings, "critical", "Inline script/data URI",
             "Executable content is embedded directly in the link.", 30)

    # 15. non-standard port
    if p.port and p.port not in (80, 443):
        _hit(findings, "medium", f"Non-standard port {p.port}",
             "Legitimate consumer sites rarely use custom ports.", 12)

    # 16. entropy of the domain label
    ent = shannon_entropy(core)
    if ent > 3.6 and len(core) > 8:
        _hit(findings, "medium", "High-entropy (random-looking) domain",
             f"Entropy {ent} - consistent with algorithmically generated domains.", 12)

    # 17. known-good allowlist relief
    if reg in LEGIT_DOMAINS and not any(f["severity"] == "critical" for f in findings):
        _hit(findings, "info", "Recognised legitimate domain",
             f"'{reg}' is on the known-good list.", -25)

    score = clamp(sum(f["points"] for f in findings))
    return {
        "score": score,
        "findings": sorted(findings, key=lambda f: -f["points"]),
        "parsed": {"scheme": p.scheme, "host": host, "registered_domain": reg,
                   "path": path[:200], "query": qs[:200], "port": p.port,
                   "tld": tld, "length": len(url), "entropy": ent},
    }


# ------------------------------------------------------------------ text engine
def analyze_text_rules(text: str, kind: str = "email") -> dict:
    findings = []
    t = (text or "")
    low = t.lower()
    if not t.strip():
        return {"score": 0, "findings": [], "urls": [], "stats": {}}

    def count_hits(words):
        return [w for w in words if w in low]

    # ---------- scam archetypes (highest-confidence signals, checked first)
    archetypes = []
    for pat, sev, pts, title, why in SCAM_ARCHETYPES:
        exempt = ARCHETYPE_EXEMPTIONS.get(title)
        if exempt and exempt.search(t):
            continue          # e.g. a real bank SMS saying "never share this OTP"
        m = re.search(pat, low, re.I)
        if m:
            archetypes.append(title)
            snippet = m.group(0).strip()[:70]
            _hit(findings, sev, title, f"{why} (matched: \"{snippet}\")", pts)

    urg = count_hits(URGENCY)
    if urg:
        _hit(findings, "high" if len(urg) > 1 else "medium", "Artificial urgency / time pressure",
             "Phrases: " + ", ".join(urg[:5]), min(10 + 6 * len(urg), 24))

    cred = count_hits(CREDENTIAL_BAIT)
    if cred:
        _hit(findings, "critical", "Credential-harvesting request",
             "Phrases: " + ", ".join(cred[:4]), min(18 + 6 * len(cred), 30))

    sens = count_hits(SENSITIVE_ASK)
    if sens:
        _hit(findings, "critical", "Asks for secret data (OTP/PIN/CVV/seed)",
             "No legitimate organisation ever asks for: " + ", ".join(sens[:5]), 32)

    rew = count_hits(REWARD_BAIT)
    if len(rew) >= 2:
        _hit(findings, "high", "Too-good-to-be-true reward bait",
             "Phrases: " + ", ".join(rew[:5]), 20)
    elif rew:
        _hit(findings, "low", "Reward/prize language", ", ".join(rew), 6)

    thr = count_hits(THREAT_WORDS)
    if thr:
        _hit(findings, "high", "Fear / legal-threat pressure",
             "Phrases: " + ", ".join(thr[:4]), 18)

    # generic greeting
    if re.search(r"\b(dear (customer|user|sir/madam|account holder|member|client))\b", low):
        _hit(findings, "medium", "Generic impersonal greeting",
             "Real providers normally address you by name.", 10)

    # sender / reply-to mismatch (email headers pasted in)
    m_from = re.search(r"^from:\s*(.+)$", t, re.I | re.M)
    m_reply = re.search(r"^reply-to:\s*(.+)$", t, re.I | re.M)
    if m_from and m_reply:
        d1 = (re.search(r"@([\w.\-]+)", m_from.group(1)) or [None, ""])[1]
        d2 = (re.search(r"@([\w.\-]+)", m_reply.group(1)) or [None, ""])[1]
        if d1 and d2 and d1.lower() != d2.lower():
            _hit(findings, "critical", "From / Reply-To domain mismatch",
                 f"Displayed sender '{d1}' but replies go to '{d2}'.", 28)
    if m_from:
        disp = m_from.group(1)
        dm = re.search(r'"?([^"<]+)"?\s*<[^@]+@([\w.\-]+)>', disp)
        if dm:
            name, dom = dm.group(1).lower(), dm.group(2).lower()
            for brand in BRANDS:
                if brand in name and brand not in dom:
                    _hit(findings, "critical", "Display-name spoofing",
                         f"Shows '{brand}' but sends from '{dom}'.", 30)
                    break
        if re.search(r"@(gmail|yahoo|outlook|hotmail|rediffmail|proton)\.", disp, re.I):
            for brand in BRANDS:
                if brand in low[:400]:
                    _hit(findings, "high", "Corporate claim from free webmail",
                         "A company claim sent from a free consumer mailbox.", 22)
                    break

    # SPF/DKIM/DMARC in pasted headers
    for mech, label in (("spf=fail", "SPF"), ("dkim=fail", "DKIM"), ("dmarc=fail", "DMARC")):
        if mech in low:
            _hit(findings, "critical", f"{label} authentication FAILED",
                 "The message was not authorised by the domain it claims to be from.", 26)

    # attachments
    atts = re.findall(r"[\w\-. ]+\.(?:exe|scr|vbs|js|jar|bat|cmd|ps1|hta|iso|img|lnk|apk|msi|docm|xlsm|zip|rar|7z)\b", low)
    if atts:
        _hit(findings, "critical", "Dangerous attachment type referenced",
             "Files: " + ", ".join(sorted(set(atts))[:5]), 26)

    # links
    urls = URL_RE.findall(t)
    url_scores = []
    for u in urls[:8]:
        r = analyze_url_rules(u)
        url_scores.append({"url": u, "score": r["score"],
                           "top": [f["title"] for f in r["findings"][:3]]})
    if url_scores:
        worst = max(url_scores, key=lambda x: x["score"])
        if worst["score"] >= 55:
            _hit(findings, "critical", "Malicious link embedded",
                 f"{worst['url'][:70]} scored {worst['score']}/100.", 26)
        elif worst["score"] >= 30:
            _hit(findings, "medium", "Questionable link embedded",
                 f"{worst['url'][:70]} scored {worst['score']}/100.", 12)

    # anchor-text mismatch  <a href="evil">bank.com</a>
    for href, label in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]{4,80})</a>', t, re.I):
        if re.match(r"https?://", label.strip(), re.I):
            h = urlparse(href).hostname or ""
            l = urlparse(label.strip()).hostname or ""
            if h and l and _registered_domain(h) != _registered_domain(l):
                _hit(findings, "critical", "Link text does not match destination",
                     f"Displays '{l}' but actually goes to '{h}'.", 30)
                break

    # SMS-specific
    if kind == "sms":
        if len(t) < 320 and urls:
            for u in urls:
                if _registered_domain(urlparse(u if "://" in u else "http://" + u).hostname or "") in URL_SHORTENERS:
                    _hit(findings, "high", "Shortened link in SMS (smishing)",
                         "Bank/telecom SMS never uses public shorteners.", 20)
                    break
        if re.search(r"\b(sms|reply)\s+(stop|yes|no)\b", low):
            _hit(findings, "low", "Reply-keyword harvesting",
                 "Replying confirms your number is active.", 6)
        if re.search(r"\b\d{4,8}\b", t) and any(w in low for w in ("otp", "code", "verification")):
            _hit(findings, "high", "OTP-relay social engineering",
                 "Message discusses an OTP - classic account-takeover step.", 20)

    # writing quality
    letters = sum(c.isalpha() for c in t) or 1
    caps = sum(c.isupper() for c in t)
    if caps / letters > 0.35 and letters > 40:
        _hit(findings, "medium", "Excessive capitalisation (shouting)",
             f"{caps / letters:.0%} uppercase.", 10)
    if t.count("!") >= 4:
        _hit(findings, "low", "Excessive exclamation marks", f"{t.count('!')} found.", 6)
    typos = ["recieve", "acount", "verifly", "informations", "kindly do the needful",
             "yours faithfuly", "immediatly", "sucessful", "confirmm", "detials",
             "pls", "plz", "ur account", "dear costumer"]
    ty = [x for x in typos if x in low]
    if ty:
        _hit(findings, "medium", "Spelling/grammar anomalies",
             "Found: " + ", ".join(ty[:4]), 12)

    # crypto / money mule
    iocs = extract_iocs(t)
    if iocs["bitcoin"]:
        _hit(findings, "critical", "Cryptocurrency wallet address present",
             "Untraceable payment demand - hallmark of extortion/fraud.", 28)
    if iocs["upi_ids"]:
        _hit(findings, "high", "UPI ID requested in message",
             "Payment redirection to a personal UPI handle: " + ", ".join(iocs["upi_ids"][:2]), 22)

    score = clamp(sum(f["points"] for f in findings))

    # A recognised scam script is near-conclusive on its own, and two of them
    # together is effectively certain. Don't let a short message score low just
    # because it lacks the trappings of corporate phishing.
    if len(archetypes) >= 2:
        score = max(score, 90)
    elif archetypes:
        worst = max((p for pat, s, p, ti, w in SCAM_ARCHETYPES if ti in archetypes),
                    default=0)
        score = max(score, 72 if worst >= 32 else 60)

    stats = {"length": len(t), "words": len(t.split()), "links": len(urls),
             "uppercase_ratio": round(caps / letters, 3),
             "scam_archetypes": archetypes}
    return {"score": score, "findings": sorted(findings, key=lambda f: -f["points"]),
            "urls": url_scores, "stats": stats, "iocs": iocs,
            "archetypes": archetypes}


# ------------------------------------------------------------------ AI layer
AI_SYSTEM = (
    "You are a phishing-analysis engine. You receive a URL, email or SMS and judge "
    "whether it is a phishing/scam attempt. Be decisive and concise. Focus on social "
    "engineering tactics a rule engine cannot see: tone, pretext, plausibility, "
    "psychological manipulation, and business-logic red flags."
)

SCHEMA = """{
  "verdict": "phishing" | "suspicious" | "legitimate",
  "confidence": 0-100,
  "ai_risk_score": 0-100,
  "tactics": ["short tactic names"],
  "reasoning": "2-4 sentence plain-English explanation",
  "red_flags": ["specific observations"],
  "recommended_actions": ["what the user should do now"],
  "victim_impact": "one line on what happens if the user complies"
}"""


def analyze_with_ai(content: str, kind: str, rule_summary: str) -> dict:
    prompt = (
        f"Artifact type: {kind.upper()}\n"
        f"--- CONTENT START ---\n{content[:4000]}\n--- CONTENT END ---\n\n"
        f"A deterministic rule engine already flagged:\n{rule_summary}\n\n"
        "Give your independent expert judgement. If the content is clearly a normal, "
        "benign message, say legitimate with a low score - do not over-flag."
    )
    res = ollama_client.generate_json(prompt, SCHEMA, system=AI_SYSTEM, temperature=0.1)
    if not res["ok"]:
        return {"available": False, "error": res.get("error")}
    d = res["data"]
    try:
        ai_score = int(float(d.get("ai_risk_score", d.get("confidence", 50))))
    except (TypeError, ValueError):
        ai_score = 50
    return {
        "available": True,
        "verdict": str(d.get("verdict", "suspicious")).lower(),
        "confidence": clamp(int(float(d.get("confidence", 60) or 60))),
        "ai_risk_score": clamp(ai_score),
        "tactics": d.get("tactics", [])[:8] if isinstance(d.get("tactics"), list) else [],
        "reasoning": str(d.get("reasoning", ""))[:1200],
        "red_flags": d.get("red_flags", [])[:8] if isinstance(d.get("red_flags"), list) else [],
        "recommended_actions": d.get("recommended_actions", [])[:8] if isinstance(d.get("recommended_actions"), list) else [],
        "victim_impact": str(d.get("victim_impact", ""))[:300],
        "model": res.get("model"),
    }


# ------------------------------------------------------------------ orchestrator
def analyze(content: str, kind: str = "url", use_ai: bool = True) -> dict:
    kind = (kind or "url").lower()
    content = (content or "").strip()
    if not content:
        return {"error": "empty input"}

    if kind == "url":
        rules = analyze_url_rules(content)
        rules.setdefault("iocs", extract_iocs(content))
    else:
        rules = analyze_text_rules(content, kind)

    rule_score = rules["score"]
    rule_summary = "; ".join(f"{f['title']} ({f['severity']})" for f in rules["findings"][:8]) or "no rule hits"

    ai = {"available": False}
    if use_ai:
        ai = analyze_with_ai(content, kind, rule_summary)

    # ---- fusion: rules are ground truth, AI adjusts within a band
    if ai.get("available"):
        final = int(round(0.62 * rule_score + 0.38 * ai["ai_risk_score"]))
        if ai["verdict"] == "phishing" and rule_score >= 20:
            final = max(final, 72)
        if ai["verdict"] == "legitimate" and rule_score < 25:
            final = min(final, 22)
        # never let AI talk us out of a critical rule hit
        if any(f["severity"] == "critical" for f in rules["findings"]):
            final = max(final, 70)
    else:
        final = rule_score
    final = clamp(final)

    verdict = risk_label(final)
    action = _action_for(final, kind)
    return {
        "kind": kind,
        "input": content[:1500],
        "risk_score": final,
        "rule_score": rule_score,
        "verdict": verdict,
        "band": ("critical" if final >= 80 else "high" if final >= 55
                 else "medium" if final >= 25 else "low"),
        "findings": rules["findings"],
        "parsed": rules.get("parsed", {}),
        "urls": rules.get("urls", []),
        "stats": rules.get("stats", {}),
        "iocs": rules.get("iocs", {}),
        "ai": ai,
        "recommended_action": action,
        "explanation": _explain(rules, ai, final, kind),
    }


def _action_for(score: int, kind: str) -> list[str]:
    if score >= 80:
        base = ["DO NOT click any link or open any attachment.",
                "Delete / block the sender immediately.",
                "If you already entered credentials, change that password NOW on the real site.",
                "Enable two-factor authentication on the affected account.",
                "Report at cybercrime.gov.in or call 1930 (India National Cyber Helpline)."]
    elif score >= 55:
        base = ["Treat as hostile until proven otherwise.",
                "Do not use links in the message - type the official address manually.",
                "Verify with the organisation using a number from their official website.",
                "Report as phishing in your mail client."]
    elif score >= 25:
        base = ["Proceed with caution and verify the sender independently.",
                "Hover over links to preview the real destination before clicking.",
                "Never share OTP, CVV, PIN or passwords, even if the request looks official."]
    else:
        base = ["No strong phishing indicators found.",
                "Stay alert: absence of indicators is not a guarantee of safety.",
                "Keep 2FA enabled and software updated."]
    if kind == "sms":
        base.append("Forward suspicious SMS to 1909 (India TRAI spam reporting).")
    return base


def _explain(rules, ai, final, kind) -> str:
    parts = []
    n = len(rules["findings"])
    crit = sum(1 for f in rules["findings"] if f["severity"] == "critical")
    parts.append(
        f"The rule engine examined this {kind} against 30+ phishing heuristics and raised "
        f"{n} indicator(s), {crit} of them critical, for a technical score of {rules['score']}/100."
    )
    if ai.get("available"):
        parts.append(f"The local AI model independently judged it '{ai['verdict']}' "
                     f"with {ai['confidence']}% confidence. {ai.get('reasoning','')}")
    else:
        parts.append("The AI layer was unavailable, so this verdict is based purely on "
                     "deterministic heuristics (still fully reliable, just less nuanced).")
    parts.append(f"Combined risk score: {final}/100 - {risk_label(final)}.")
    return " ".join(parts)
