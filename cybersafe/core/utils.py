"""Shared helpers: hashing, entropy, formatting, defanging, safe IO."""
from __future__ import annotations

import hashlib
import math
import os
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------- time
def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def human_time(ts: str | None) -> str:
    if not ts:
        return "-"
    return str(ts).replace("T", " ")[:19]


def parse_any_time(value) -> datetime | None:
    """Best-effort timestamp parsing across forensic artifact formats."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    s = str(value).strip()
    if not s:
        return None
    # webkit / unix epochs
    if s.isdigit():
        n = int(s)
        try:
            if n > 11_000_000_000_000_000:          # webkit micro (Chrome)
                return datetime(1601, 1, 1, tzinfo=timezone.utc).fromtimestamp(0) if False else _webkit(n)
            if n > 1_000_000_000_000:               # ms epoch
                return datetime.fromtimestamp(n / 1000, tz=timezone.utc)
            if n > 1_000_000_000:                   # s epoch
                return datetime.fromtimestamp(n, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    fmts = (
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
        "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S %p", "%Y-%m-%d %H:%M", "%d-%m-%Y %H:%M:%S",
    )
    for f in fmts:
        try:
            dt = datetime.strptime(s[:32].strip(), f)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue
    return None


def _webkit(micros: int) -> datetime:
    """Chrome/WebKit epoch = microseconds since 1601-01-01."""
    from datetime import timedelta
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)


def webkit_to_dt(micros) -> datetime | None:
    try:
        micros = int(micros)
    except (TypeError, ValueError):
        return None
    if micros <= 0:
        return None
    try:
        return _webkit(micros)
    except (OverflowError, ValueError):
        return None


def firefox_to_dt(micros) -> datetime | None:
    """Firefox places.sqlite uses microseconds since unix epoch."""
    try:
        micros = int(micros)
    except (TypeError, ValueError):
        return None
    if micros <= 0:
        return None
    try:
        return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


# ---------------------------------------------------------------- hashing
def hash_file(path: str | Path, algos=("md5", "sha1", "sha256")) -> dict:
    hs = {a: hashlib.new(a) for a in algos}
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            size += len(chunk)
            for h in hs.values():
                h.update(chunk)
    out = {a: h.hexdigest() for a, h in hs.items()}
    out["size"] = size
    return out


def hash_bytes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------- entropy
def shannon_entropy(data) -> float:
    """Entropy in bits/byte (0-8). >7.2 usually means packed/encrypted."""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


# ---------------------------------------------------------------- formatting
def human_size(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"


def human_duration(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [("century", 3153600000), ("year", 31536000), ("month", 2592000),
             ("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)]
    for name, secs in units:
        if seconds >= secs:
            v = seconds / secs
            if v > 1e9:
                return f"{v:.2e} {name}s"
            return f"{v:.0f} {name}" + ("s" if round(v) != 1 else "")
    return "instantly"


def defang(text: str) -> str:
    """Make IOCs non-clickable for safe reporting."""
    if not text:
        return ""
    text = re.sub(r"https?://", lambda m: m.group(0).replace("http", "hxxp"), text, flags=re.I)
    text = text.replace(".", "[.]").replace("@", "[@]")
    return text


def safe_name(name: str, default="artifact") -> str:
    name = unicodedata.normalize("NFKD", str(name or default))
    name = re.sub(r"[^\w.\- ]+", "_", name).strip().strip(".")
    name = re.sub(r"\s+", "_", name)
    return (name or default)[:180]


def risk_band(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def risk_label(score: int) -> str:
    return {"critical": "Dangerous", "high": "Suspicious",
            "medium": "Caution", "low": "Likely Safe"}[risk_band(score)]


def clamp(v, lo=0, hi=100):
    return max(lo, min(hi, v))


def truncate(text, n=160):
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= n else text[: n - 1] + "…"


# ---------------------------------------------------------------- extraction
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'\)\]]+", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
UPI_RE = re.compile(
    r"\b[\w.\-]{1,64}@(?:okaxis|oksbi|okhdfcbank|okicici|paytm|ybl|ibl|axl|upi|apl|jio|"
    r"airtel|freecharge|fbl|idfcbank|indus|kotak|barodampay|sbi|hdfcbank|icici|axisbank)\b",
    re.I)
PHONE_IN_RE = re.compile(r"(?:\+?91[\-\s]?)?[6-9]\d{9}\b")
MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.I)
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")


def extract_iocs(text: str) -> dict:
    """Pull indicators of compromise out of arbitrary text."""
    text = text or ""
    out = {
        "urls": sorted(set(URL_RE.findall(text)))[:60],
        "emails": sorted(set(EMAIL_RE.findall(text)))[:40],
        "ips": sorted(set(i for i in IPV4_RE.findall(text) if not i.startswith("0.")))[:40],
        "bitcoin": sorted(set(BTC_RE.findall(text)))[:20],
        "upi_ids": sorted(set(UPI_RE.findall(text)))[:20],
        "phones": sorted(set(PHONE_IN_RE.findall(text)))[:20],
        "md5": sorted(set(MD5_RE.findall(text)))[:20],
        "sha256": sorted(set(SHA256_RE.findall(text)))[:20],
    }
    doms = set()
    for u in out["urls"]:
        m = DOMAIN_RE.search(u)
        if m:
            doms.add(m.group(0).lower())
    for e in out["emails"]:
        doms.add(e.split("@")[-1].lower())
    out["domains"] = sorted(doms)[:40]
    out["total"] = sum(len(v) for k, v in out.items() if isinstance(v, list))
    return out


def extract_strings(data: bytes, min_len: int = 5, limit: int = 200_000):
    """ASCII + UTF-16LE printable string extraction (the `strings` command)."""
    results = []
    # ASCII
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                results.append(cur.decode("ascii", "ignore"))
                if len(results) >= limit:
                    return results
            cur = bytearray()
    if len(cur) >= min_len:
        results.append(cur.decode("ascii", "ignore"))
    # UTF-16LE (very common in Windows memory)
    try:
        wide = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)
        for w in wide[: max(0, limit - len(results))]:
            results.append(w.decode("utf-16-le", "ignore"))
    except re.error:
        pass
    return results


def read_head(path, n=2 * 1024 * 1024) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def ensure_dir(p) -> Path:
    p = Path(p)
    p.mkdir(parents=True, exist_ok=True)
    return p


def file_type_guess(head: bytes, filename: str = "") -> str:
    """Magic-byte based file type detection (no external libs)."""
    sigs = [
        (b"MZ", "Windows Executable (PE/DLL/EXE)"),
        (b"\x7fELF", "Linux Executable (ELF)"),
        (b"\xca\xfe\xba\xbe", "Java Class / Mach-O FAT"),
        (b"%PDF", "PDF Document"),
        (b"PK\x03\x04", "ZIP archive (also DOCX/XLSX/PPTX/JAR/APK)"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"\x1f\x8b", "GZIP archive"),
        (b"\xd0\xcf\x11\xe0", "Legacy MS Office (OLE2: doc/xls/ppt)"),
        (b"\x89PNG", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF8", "GIF image"),
        (b"BM", "BMP image"),
        (b"SQLite format 3", "SQLite database"),
        (b"\x25\x21PS", "PostScript"),
        (b"ID3", "MP3 audio"),
        (b"\x00\x00\x01\xba", "MPEG video"),
        (b"OggS", "OGG media"),
        (b"fLaC", "FLAC audio"),
        (b"\xed\xab\xee\xdb", "RPM package"),
        (b"!<arch>", "Unix archive / DEB"),
        (b"EMiL", "Windows Event Log (EVT)"),
        (b"ElfFile", "Windows Event Log (EVTX)"),
    ]
    for sig, name in sigs:
        if head.startswith(sig):
            return name
    if b"<?xml" in head[:200]:
        return "XML document"
    if b"<html" in head[:400].lower():
        return "HTML document"
    if head[:4] == b"\x00\x00\x00\x0c":
        return "JPEG-2000 / MP4 family"
    ext = os.path.splitext(filename)[1].lower()
    known = {".txt": "Plain text", ".log": "Log file", ".csv": "CSV data",
             ".json": "JSON data", ".ps1": "PowerShell script", ".sh": "Shell script",
             ".py": "Python script", ".js": "JavaScript", ".bat": "Batch script",
             ".vbs": "VBScript", ".mem": "Memory image", ".raw": "Raw image",
             ".dmp": "Crash/Memory dump", ".vmem": "VMware memory image"}
    if ext in known:
        return known[ext]
    try:
        head.decode("utf-8")
        return "Text / unknown"
    except UnicodeDecodeError:
        return "Binary / unknown"


def is_printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return round(printable / len(data), 3)
