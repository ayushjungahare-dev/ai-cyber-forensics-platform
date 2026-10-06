"""
BONUS Module -- Daily Security Toolkit.

Extra utilities that make the platform useful every day, all offline:
  * PII / sensitive-data scanner + redactor (before you share a screenshot or log)
  * Image EXIF metadata viewer & stripper (removes GPS before posting)
  * Encoder/decoder workbench (Base64, hex, URL, ROT13, binary, JWT decode)
  * Hash calculator & file comparison
  * Secure file shredder (multi-pass overwrite)
  * QR code payload safety checker
  * Fake job-offer / investment-scam detector
  * Personal security checkup (interactive hardening score)
  * Data-exposure self-check (offline)
"""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import json
import os
import re
import secrets
import struct
import urllib.parse
from pathlib import Path

from core import ollama_client
from core.utils import clamp, hash_file, human_size, shannon_entropy

# ================================================================= PII scanner
PII_PATTERNS = [
    ("Aadhaar number", r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b", "critical",
     "India's national ID. Never share publicly; enables identity theft and fake loans."),
    ("PAN card", r"\b[A-Z]{5}\d{4}[A-Z]\b", "critical",
     "India tax ID. Used for financial identity fraud."),
    ("Credit/Debit card", r"\b(?:4\d{3}|5[1-5]\d{2}|6011|65\d{2}|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{2,4}\b",
     "critical", "Full card number. Immediate financial risk."),
    ("CVV", r"\b(?:cvv|cvc|cid)\s*[:=#]?\s*\d{3,4}\b", "critical",
     "Card security code. Never store or share."),
    ("Indian mobile", r"(?:\+?91[\-\s]?)?\b[6-9]\d{4}[\s-]?\d{5}\b", "medium",
     "Phone number. Enables SIM-swap targeting, spam and OTP phishing."),
    ("Email address", r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "low",
     "Email address. Enables targeted phishing and credential stuffing."),
    ("IFSC code", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", "high",
     "Bank branch code. Combined with an account number it enables fraud."),
    ("Bank account", r"\b(?:a/c|acct|account)\s*(?:no\.?|number|#)?\s*[:=]?\s*\d{9,18}\b",
     "critical", "Bank account number."),
    ("UPI ID", r"\b[\w.\-]{2,}@(?:okaxis|oksbi|okhdfcbank|okicici|paytm|ybl|ibl|axl|upi|apl)\b",
     "high", "UPI handle. Enables targeted payment fraud."),
    ("Passport", r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b", "critical", "Passport number."),
    ("Vehicle number", r"\b[A-Z]{2}\s?\d{1,2}\s?[A-Z]{1,3}\s?\d{4}\b", "medium",
     "Vehicle registration - can reveal your location and identity."),
    ("IPv4 address", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
     "low", "IP address. Reveals approximate location and network."),
    ("MAC address", r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", "medium",
     "Hardware address - uniquely identifies a device."),
    ("Private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "critical",
     "Cryptographic private key. Full compromise if leaked."),
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b", "critical", "Cloud credential - rotate immediately."),
    ("Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "critical", "Cloud API key - rotate immediately."),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b", "critical", "Source-code access token."),
    ("Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "critical", "Workspace access token."),
    ("JWT token", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
     "high", "Session token - can be replayed to impersonate the user."),
    ("Password in text", r"(?:password|passwd|pwd|pass)\s*[:=]\s*\S{4,60}", "critical",
     "Plaintext credential."),
    ("Connection string", r"(?:mongodb|mysql|postgres(?:ql)?|redis)://[^\s'\"]+", "critical",
     "Database connection string, often containing credentials."),
    ("Date of birth", r"\b(?:0?[1-9]|[12]\d|3[01])[/\-](?:0?[1-9]|1[0-2])[/\-](?:19|20)\d{2}\b",
     "medium", "Date of birth - a key identity-verification answer."),
]


def _luhn(num: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", num)][::-1]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(digits):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def scan_pii(text: str) -> dict:
    text = text or ""
    findings = []
    for name, pat, sev, why in PII_PATTERNS:
        for m in re.finditer(pat, text, re.I if name not in ("PAN card", "IFSC code") else 0):
            val = m.group(0)
            if name == "Credit/Debit card":
                digits = re.sub(r"\D", "", val)
                # Accept a valid Luhn, OR a bare 16-digit run (test/masked data)
                if not (_luhn(val) or len(digits) == 16):
                    continue
            if name == "Indian mobile":
                if len(re.sub(r"\D", "", val)) not in (10, 12):
                    continue
                # reject matches embedded inside a longer digit run (e.g. a card number)
                before = text[max(0, m.start() - 1):m.start()]
                after = text[m.end():m.end() + 1]
                if before.isdigit() or after.isdigit():
                    continue
            findings.append({"type": name, "severity": sev, "value": val,
                             "masked": _mask(val), "why": why,
                             "start": m.start(), "end": m.end()})

    # de-duplicate overlaps: prefer the longest match, then the most severe
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (f["start"], -(f["end"] - f["start"]), order[f["severity"]]))
    kept, last_end = [], -1
    for f in findings:
        if f["start"] >= last_end:
            kept.append(f); last_end = f["end"]
    counts = {}
    for f in kept:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    score = clamp(counts.get("critical", 0) * 30 + counts.get("high", 0) * 18 +
                  counts.get("medium", 0) * 8 + counts.get("low", 0) * 3)
    return {"findings": kept, "count": len(kept), "counts": counts, "risk_score": score,
            "band": ("critical" if score >= 80 else "high" if score >= 55
                     else "medium" if score >= 25 else "low"),
            "redacted": redact(text, kept),
            "safe": len(kept) == 0}


def _mask(v: str) -> str:
    v = str(v)
    if len(v) <= 4:
        return "*" * len(v)
    keep = 2 if len(v) < 10 else 4
    return v[:keep] + "*" * (len(v) - keep - 2) + v[-2:]


def redact(text: str, findings: list) -> str:
    if not findings:
        return text
    out, last = [], 0
    for f in sorted(findings, key=lambda x: x["start"]):
        out.append(text[last:f["start"]])
        out.append(f"[REDACTED:{f['type'].upper().replace(' ', '_')}]")
        last = f["end"]
    out.append(text[last:])
    return "".join(out)


# ================================================================= EXIF
EXIF_TAGS = {
    0x010F: "Camera Make", 0x0110: "Camera Model", 0x0112: "Orientation",
    0x0132: "Date/Time", 0x013B: "Artist", 0x8298: "Copyright",
    0x9003: "Original Date/Time", 0x9004: "Digitized Date/Time",
    0x829A: "Exposure Time", 0x829D: "F-Number", 0x8827: "ISO",
    0xA002: "Image Width", 0xA003: "Image Height", 0x0131: "Software",
    0x8825: "GPS Info Offset", 0x927C: "Maker Note", 0x9286: "User Comment",
}
GPS_TAGS = {0x0001: "Lat Ref", 0x0002: "Latitude", 0x0003: "Lon Ref",
            0x0004: "Longitude", 0x0005: "Alt Ref", 0x0006: "Altitude",
            0x0007: "GPS Time", 0x001D: "GPS Date"}


def read_exif(path: str) -> dict:
    """Minimal JPEG EXIF reader (no Pillow dependency required)."""
    out = {"has_exif": False, "tags": {}, "gps": {}, "privacy_risk": [], "format": ""}
    try:
        with open(path, "rb") as fh:
            data = fh.read(2 * 1024 * 1024)
    except OSError as e:
        return {"error": str(e)}

    if data[:3] == b"\xff\xd8\xff":
        out["format"] = "JPEG"
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        out["format"] = "PNG"
        for kw in (b"tEXt", b"iTXt", b"zTXt"):
            if kw in data:
                out["has_exif"] = True
                out["tags"]["PNG text chunks"] = "present (may contain software/comments)"
        return out
    else:
        out["format"] = "Unknown/other"
        return out

    idx = data.find(b"Exif\x00\x00")
    if idx == -1:
        return out
    out["has_exif"] = True
    tiff = idx + 6
    try:
        endian = data[tiff:tiff + 2]
        fmt = "<" if endian == b"II" else ">"
        ifd_off = struct.unpack_from(fmt + "I", data, tiff + 4)[0]
        _read_ifd(data, tiff, tiff + ifd_off, fmt, out, EXIF_TAGS)
        gps_off = out.pop("_gps_offset", None)
        if gps_off:
            gout = {"tags": {}, "gps": {}}
            _read_ifd(data, tiff, tiff + gps_off, fmt, gout, GPS_TAGS)
            out["gps"] = gout["tags"]
    except (struct.error, IndexError, ValueError) as e:
        out["parse_note"] = f"partial parse: {str(e)[:80]}"

    if out["gps"]:
        out["privacy_risk"].append(
            "GPS COORDINATES EMBEDDED - this photo reveals exactly where it was taken.")
    if any("Date" in k for k in out["tags"]):
        out["privacy_risk"].append("Timestamp embedded - reveals when the photo was taken.")
    if "Camera Make" in out["tags"] or "Camera Model" in out["tags"]:
        out["privacy_risk"].append(
            "Device make/model embedded - links this photo to your specific device.")
    if "Artist" in out["tags"] or "Copyright" in out["tags"]:
        out["privacy_risk"].append("Author/owner name embedded.")
    if "Software" in out["tags"]:
        out["privacy_risk"].append("Editing software recorded.")
    return out


def _read_ifd(data, tiff, offset, fmt, out, tagmap):
    n = struct.unpack_from(fmt + "H", data, offset)[0]
    for i in range(min(n, 80)):
        e = offset + 2 + i * 12
        tag, typ, cnt = struct.unpack_from(fmt + "HHI", data, e)
        if tag == 0x8825:
            out["_gps_offset"] = struct.unpack_from(fmt + "I", data, e + 8)[0]
            continue
        name = tagmap.get(tag)
        if not name:
            continue
        sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
        sz = sizes.get(typ, 1) * cnt
        val_off = e + 8 if sz <= 4 else tiff + struct.unpack_from(fmt + "I", data, e + 8)[0]
        try:
            if typ == 2:
                v = data[val_off:val_off + cnt].split(b"\x00")[0].decode("utf-8", "ignore")
            elif typ in (3,):
                v = struct.unpack_from(fmt + "H", data, val_off)[0]
            elif typ in (4,):
                v = struct.unpack_from(fmt + "I", data, val_off)[0]
            elif typ in (5, 10):
                parts = []
                for j in range(min(cnt, 3)):
                    num, den = struct.unpack_from(fmt + "II", data, val_off + j * 8)
                    parts.append(round(num / den, 6) if den else 0)
                v = parts[0] if len(parts) == 1 else parts
            else:
                v = data[val_off:val_off + min(sz, 60)].decode("utf-8", "ignore").strip("\x00")
            if v not in ("", None):
                out["tags"][name] = v
        except (struct.error, IndexError, ZeroDivisionError, UnicodeDecodeError):
            continue


def strip_exif(src: str, dst: str) -> dict:
    """Rewrite a JPEG without APP1/APP2/COM metadata segments."""
    with open(src, "rb") as fh:
        data = fh.read()
    if data[:3] != b"\xff\xd8\xff":
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            out = _strip_png(data)
            Path(dst).write_bytes(out)
            return {"ok": True, "format": "PNG", "original": len(data), "cleaned": len(out),
                    "removed": len(data) - len(out)}
        return {"ok": False, "error": "Only JPEG and PNG are supported for stripping."}

    out = bytearray(b"\xff\xd8")
    i = 2
    removed = []
    while i < len(data) - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0xD9:                      # EOI
            out += data[i:]
            break
        if marker == 0xDA:                      # SOS - image data follows
            out += data[i:]
            break
        if i + 4 > len(data):
            break
        seg_len = struct.unpack_from(">H", data, i + 2)[0]
        seg = data[i:i + 2 + seg_len]
        if marker in (0xE1, 0xE2, 0xED, 0xEE, 0xFE) or (0xE3 <= marker <= 0xEF):
            removed.append(hex(marker))
        else:
            out += seg
        i += 2 + seg_len
    Path(dst).write_bytes(bytes(out))
    return {"ok": True, "format": "JPEG", "original": len(data), "cleaned": len(out),
            "removed": len(data) - len(out), "segments_removed": removed}


def _strip_png(data: bytes) -> bytes:
    out = bytearray(data[:8])
    i = 8
    keep = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"bKGD"}
    while i + 8 <= len(data):
        ln = struct.unpack_from(">I", data, i)[0]
        ctype = data[i + 4:i + 8]
        chunk = data[i:i + 12 + ln]
        if ctype in keep:
            out += chunk
        i += 12 + ln
        if ctype == b"IEND":
            break
    return bytes(out)


# ================================================================= encoders
def encode_decode(text: str, operation: str) -> dict:
    t = text or ""
    try:
        if operation == "base64_encode":
            return {"ok": True, "result": base64.b64encode(t.encode()).decode()}
        if operation == "base64_decode":
            pad = t.strip() + "=" * (-len(t.strip()) % 4)
            return {"ok": True, "result": base64.b64decode(pad).decode("utf-8", "replace")}
        if operation == "url_encode":
            return {"ok": True, "result": urllib.parse.quote(t, safe="")}
        if operation == "url_decode":
            return {"ok": True, "result": urllib.parse.unquote(t)}
        if operation == "hex_encode":
            return {"ok": True, "result": t.encode().hex()}
        if operation == "hex_decode":
            clean = re.sub(r"(0x|\\x|[\s:,-])", "", t)
            return {"ok": True, "result": bytes.fromhex(clean).decode("utf-8", "replace")}
        if operation == "rot13":
            return {"ok": True, "result": codecs.encode(t, "rot13")}
        if operation == "binary_encode":
            return {"ok": True, "result": " ".join(format(b, "08b") for b in t.encode())}
        if operation == "binary_decode":
            bits = re.sub(r"[^01]", "", t)
            chars = [bits[i:i + 8] for i in range(0, len(bits) - 7, 8)]
            return {"ok": True, "result": "".join(chr(int(c, 2)) for c in chars)}
        if operation == "html_encode":
            import html as _h
            return {"ok": True, "result": _h.escape(t)}
        if operation == "html_decode":
            import html as _h
            return {"ok": True, "result": _h.unescape(t)}
        if operation == "reverse":
            return {"ok": True, "result": t[::-1]}
        if operation == "jwt_decode":
            parts = t.strip().split(".")
            if len(parts) < 2:
                return {"ok": False, "error": "Not a JWT (needs header.payload.signature)"}
            def d(p):
                p += "=" * (-len(p) % 4)
                return json.loads(base64.urlsafe_b64decode(p).decode("utf-8", "replace"))
            header, payload = d(parts[0]), d(parts[1])
            return {"ok": True, "result": json.dumps({"header": header, "payload": payload},
                                                     indent=2),
                    "note": "Signature NOT verified - decoding only. Never trust unverified claims."}
        if operation.startswith("hash_"):
            algo = operation.split("_", 1)[1]
            if algo not in hashlib.algorithms_available:
                return {"ok": False, "error": f"unsupported algorithm {algo}"}
            return {"ok": True, "result": hashlib.new(algo, t.encode()).hexdigest()}
        return {"ok": False, "error": "unknown operation"}
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:120]}"}


ENCODE_OPS = [
    ("base64_encode", "Base64 Encode"), ("base64_decode", "Base64 Decode"),
    ("url_encode", "URL Encode"), ("url_decode", "URL Decode"),
    ("hex_encode", "Hex Encode"), ("hex_decode", "Hex Decode"),
    ("binary_encode", "Binary Encode"), ("binary_decode", "Binary Decode"),
    ("html_encode", "HTML Encode"), ("html_decode", "HTML Decode"),
    ("rot13", "ROT13"), ("reverse", "Reverse Text"), ("jwt_decode", "JWT Decode"),
    ("hash_md5", "MD5 Hash"), ("hash_sha1", "SHA-1 Hash"),
    ("hash_sha256", "SHA-256 Hash"), ("hash_sha512", "SHA-512 Hash"),
]


# ================================================================= shredder
def shred_file(path: str, passes: int = 3) -> dict:
    """DoD-style multi-pass overwrite then delete."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"ok": False, "error": "file not found"}
    size = p.stat().st_size
    try:
        with open(p, "r+b") as fh:
            for i in range(max(1, min(passes, 7))):
                fh.seek(0)
                pattern = (b"\x00" if i % 3 == 0 else b"\xff" if i % 3 == 1 else None)
                written = 0
                while written < size:
                    n = min(1024 * 1024, size - written)
                    fh.write(pattern * n if pattern else secrets.token_bytes(n))
                    written += n
                fh.flush()
                os.fsync(fh.fileno())
        # rename before unlink to destroy the filename in the directory entry
        tmp = p.with_name(secrets.token_hex(16))
        p.rename(tmp)
        tmp.unlink()
        return {"ok": True, "passes": passes, "size": size, "size_human": human_size(size),
                "message": f"Securely overwritten {passes} time(s) and deleted. "
                           f"Note: on SSDs and journaling filesystems, wear-levelling may retain "
                           f"copies - full-disk encryption is the reliable protection."}
    except OSError as e:
        return {"ok": False, "error": str(e)[:150]}


# ================================================================= QR / URL
def check_qr_payload(payload: str) -> dict:
    """Analyse the text decoded from a QR code."""
    from modules.phishing import analyze_url_rules, analyze_text_rules
    p = (payload or "").strip()
    kind, notes = "text", []
    if re.match(r"^(https?|ftp)://", p, re.I):
        kind = "url"
    elif p.lower().startswith("upi://"):
        kind = "upi_payment"
        notes.append("This is a UPI PAYMENT request. Verify the payee name and amount before "
                     "approving. Remember: you NEVER need to enter your PIN to RECEIVE money.")
        amt = re.search(r"am=([\d.]+)", p)
        pa = re.search(r"pa=([^&]+)", p)
        pn = re.search(r"pn=([^&]+)", p)
        if pa:
            notes.append(f"Payee VPA: {urllib.parse.unquote(pa.group(1))}")
        if pn:
            notes.append(f"Payee name: {urllib.parse.unquote(pn.group(1))}")
        if amt:
            notes.append(f"Amount pre-filled: ₹{amt.group(1)} - confirm this is what you expect.")
    elif p.upper().startswith("WIFI:"):
        kind = "wifi"
        notes.append("This QR joins a Wi-Fi network. Only scan Wi-Fi QR codes from a trusted source "
                     "- an evil-twin network can intercept your traffic.")
    elif p.lower().startswith(("tel:", "sms:", "smsto:")):
        kind = "phone_sms"
        notes.append("This will start a call or SMS. Premium-rate numbers can charge you heavily.")
    elif p.upper().startswith("BEGIN:VCARD"):
        kind = "contact"
    elif p.lower().startswith("mailto:"):
        kind = "email"

    if kind == "url" or re.search(r"https?://", p):
        m = re.search(r"https?://\S+", p)
        r = analyze_url_rules(m.group(0) if m else p)
        score, findings = r["score"], r["findings"]
    else:
        r = analyze_text_rules(p, "sms")
        score, findings = r["score"], r["findings"]
    if kind == "upi_payment":
        score = max(score, 35)
    return {"payload": p[:600], "kind": kind, "risk_score": clamp(score),
            "band": ("critical" if score >= 80 else "high" if score >= 55
                     else "medium" if score >= 25 else "low"),
            "findings": findings, "notes": notes,
            "advice": ["Never scan QR codes stuck over an existing one in a shop or parking meter.",
                       "Check the payee name on the confirmation screen, not the poster.",
                       "A PIN is required only to SEND money, never to receive it.",
                       "If the QR opens a login page, close it - scan-to-login phishing is common."]}


# ================================================================= scam detector
JOB_SCAM_SIGNS = [
    (r"registration fee|security deposit|refundable deposit|processing fee|training fee",
     "critical", 32, "Genuine employers NEVER charge you to get a job."),
    (r"earn (?:rs\.?|₹|inr)?\s?\d{3,}[\s,]*(?:per day|daily|/day)", "critical", 28,
     "Unrealistic daily earnings promise."),
    (r"work from home.*(?:no experience|any qualification|10th pass)", "high", 22,
     "No-skill, high-pay offers are almost always scams."),
    (r"(?:whatsapp|telegram).*(?:apply|contact|join)", "high", 22,
     "Real recruiters use company email, not WhatsApp/Telegram groups."),
    (r"part[\s-]?time job.*(?:like|review|rating|task)", "critical", 30,
     "Task-based 'like and earn' schemes are advance-fee frauds."),
    (r"selected (?:for|as).*without interview|direct joining", "high", 24,
     "Selection without any interview is not how hiring works."),
    (r"(?:limited|only) \d+ (?:seats|vacancies|positions) (?:left|remaining)", "medium", 14,
     "Artificial scarcity pressure."),
    (r"send.*(?:aadhaar|pan|passport|bank details|cancelled cheque)", "critical", 30,
     "Documents requested before any formal offer letter - identity-theft risk."),
    (r"invest.*(?:double|triple|guaranteed return|risk free|assured profit)", "critical", 34,
     "Guaranteed high returns are the definition of an investment scam."),
    (r"crypto.*(?:profit|double|guaranteed)|trading (?:tips|signals) group", "critical", 30,
     "Crypto 'profit group' scams are extremely common."),
    (r"lottery|lucky draw|you have won|kbc|jackpot", "critical", 32,
     "You cannot win a lottery you never entered."),
    (r"click (?:here|this link) to (?:claim|register|apply)", "medium", 14,
     "Link-driven urgency."),
    (r"gmail\.com|outlook\.com|yahoo\.com|rediffmail", "medium", 16,
     "Corporate offer sent from free webmail rather than a company domain."),
    (r"customs? (?:duty|clearance)|parcel (?:stuck|held)", "critical", 30,
     "Classic parcel/customs advance-fee scam."),
    (r"digital arrest|cbi|ed |narcotics.*parcel|money laundering case", "critical", 40,
     "'Digital arrest' scam - Indian police NEVER arrest or demand money over a video call."),
]


def detect_scam(text: str, use_ai: bool = True) -> dict:
    t = (text or "")
    low = t.lower()
    findings = []
    for pat, sev, pts, why in JOB_SCAM_SIGNS:
        if re.search(pat, low):
            findings.append({"severity": sev, "title": why,
                             "detail": f"Pattern matched: {pat[:60]}", "points": pts})
    from modules.phishing import analyze_text_rules
    phish = analyze_text_rules(t, "sms")
    findings += phish["findings"]
    pii = scan_pii(t)
    score = clamp(sum(f["points"] for f in findings))
    result = {
        "risk_score": score,
        "band": ("critical" if score >= 80 else "high" if score >= 55
                 else "medium" if score >= 25 else "low"),
        "findings": sorted(findings, key=lambda f: -f["points"]),
        "iocs": phish.get("iocs", {}),
        "pii_requested": [f["type"] for f in pii["findings"]],
        "advice": ["Never pay any fee to receive a job, prize, refund or loan.",
                   "Verify the company on its official website and LinkedIn - call the number "
                   "listed there, not the one in the message.",
                   "A real offer letter comes from a company domain with a physical address and GST/CIN.",
                   "Never share Aadhaar, PAN, bank details or OTP with an unverified 'recruiter'.",
                   "If you have already paid, call 1930 immediately and file at cybercrime.gov.in."],
    }
    if use_ai:
        r = ollama_client.generate(
            f"Analyse this message for scam indicators and explain to a non-technical Indian user "
            f"in under 140 words whether it is a scam and exactly what to do:\n\n{t[:2500]}",
            system="You are a consumer fraud-protection advisor in India. Be direct and protective.",
            temperature=0.25, max_tokens=380)
        result["ai"] = {"available": r["ok"], "text": r.get("text", ""), "model": r.get("model")}
    return result


# ================================================================= checkup
CHECKUP_ITEMS = [
    {"id": "unique_pw", "q": "Do you use a DIFFERENT password for every important account?",
     "weight": 15, "fix": "Install a free password manager (Bitwarden or KeePassXC) and change "
                          "reused passwords, starting with email and banking."},
    {"id": "pw_manager", "q": "Do you use a password manager?", "weight": 10,
     "fix": "Bitwarden (cloud sync, free) or KeePassXC (fully offline) both cost nothing."},
    {"id": "2fa_email", "q": "Is two-factor authentication enabled on your primary email?",
     "weight": 15, "fix": "Your email resets every other password - protect it first. Use an "
                          "authenticator app rather than SMS."},
    {"id": "2fa_bank", "q": "Is 2FA enabled on your banking and payment apps?", "weight": 12,
     "fix": "Enable app-based 2FA and transaction alerts in your bank's app."},
    {"id": "updates", "q": "Are automatic OS and app updates switched on?", "weight": 12,
     "fix": "Most successful attacks exploit bugs that were already patched. Turn on auto-update."},
    {"id": "backup", "q": "Do you have a backup that is NOT permanently connected to your PC?",
     "weight": 12, "fix": "Follow 3-2-1: three copies, two media types, one offline. This is the "
                          "only reliable defence against ransomware."},
    {"id": "antivirus", "q": "Is real-time antivirus protection active?", "weight": 8,
     "fix": "Windows Defender is free and good. Just make sure it is enabled and updating."},
    {"id": "screen_lock", "q": "Does your phone and laptop lock automatically?", "weight": 6,
     "fix": "Set auto-lock to 1-2 minutes with a PIN/biometric."},
    {"id": "no_cracks", "q": "Do you avoid cracked software and modded APKs?", "weight": 10,
     "fix": "Cracks are the #1 consumer malware vector. Use free/open-source alternatives instead."},
    {"id": "public_wifi", "q": "Do you avoid banking on public Wi-Fi?", "weight": 6,
     "fix": "Use your mobile hotspot for anything sensitive."},
    {"id": "app_perms", "q": "Have you reviewed app permissions in the last 3 months?", "weight": 6,
     "fix": "Revoke SMS, Accessibility, contacts and location from apps that do not need them."},
    {"id": "phish_aware", "q": "Do you verify links before clicking, even from known senders?",
     "weight": 10, "fix": "Hover to preview, and type important addresses manually."},
    {"id": "otp_never", "q": "Are you certain you would NEVER share an OTP, even with 'bank staff'?",
     "weight": 12, "fix": "No legitimate employee ever needs your OTP. Anyone asking is a fraudster."},
    {"id": "remote_apps", "q": "Do you refuse to install AnyDesk/TeamViewer when 'support' asks?",
     "weight": 10, "fix": "Screen-sharing fraud drains accounts in minutes. Never install these on request."},
    {"id": "disk_encrypt", "q": "Is disk encryption enabled (BitLocker/FileVault/LUKS)?",
     "weight": 8, "fix": "Protects your data if the device is lost or stolen."},
    {"id": "router_pw", "q": "Have you changed your Wi-Fi router's default admin password?",
     "weight": 6, "fix": "Default credentials let anyone on your network reconfigure it."},
]


def score_checkup(answers: dict) -> dict:
    total_w = sum(i["weight"] for i in CHECKUP_ITEMS)
    got, gaps, strengths = 0, [], []
    for item in CHECKUP_ITEMS:
        a = str(answers.get(item["id"], "")).lower()
        if a in ("yes", "true", "1", "on"):
            got += item["weight"]
            strengths.append(item["q"])
        else:
            gaps.append({"question": item["q"], "fix": item["fix"], "weight": item["weight"],
                         "priority": "high" if item["weight"] >= 12 else
                                     "medium" if item["weight"] >= 8 else "low"})
    pct = round(got / total_w * 100)
    if pct >= 90:
        grade, msg = "A+", "Excellent security posture. You are a hard target."
    elif pct >= 75:
        grade, msg = "B", "Good posture with a few gaps worth closing."
    elif pct >= 60:
        grade, msg = "C", "Average. Several important protections are missing."
    elif pct >= 40:
        grade, msg = "D", "Weak. You are at meaningful risk - act on the high-priority items."
    else:
        grade, msg = "F", "Critical. Please fix the high-priority items today."
    return {"percent": pct, "grade": grade, "message": msg,
            "gaps": sorted(gaps, key=lambda g: -g["weight"]),
            "strengths": strengths, "answered": len(answers), "total": len(CHECKUP_ITEMS)}


# ================================================================= hashing tools
def compare_files(path_a: str, path_b: str) -> dict:
    ha, hb = hash_file(path_a), hash_file(path_b)
    same = ha["sha256"] == hb["sha256"]
    return {"identical": same, "a": ha, "b": hb,
            "message": ("The files are byte-for-byte IDENTICAL (SHA-256 match)." if same else
                        "The files are DIFFERENT. At least one bit has changed.")}


def hash_text(text: str) -> dict:
    b = (text or "").encode()
    return {a: hashlib.new(a, b).hexdigest()
            for a in ("md5", "sha1", "sha256", "sha384", "sha512")}
