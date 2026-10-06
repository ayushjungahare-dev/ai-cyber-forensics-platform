"""
Live breach-lookup providers.

This is the part that actually answers "has THIS email been breached?" by
querying real breach databases over the network.

PROVIDERS
---------
  hibp_official   HaveIBeenPwned /api/v3/breachedaccount
                  THE authoritative source. Requires the user's own API key
                  (HIBP charges ~$3.95/month). Used automatically when a key is
                  configured in Settings.

  xposedornot     https://xposedornot.com  — FREE, no API key.
                  Returns the list of breaches an address appears in.

  leakcheck       https://leakcheck.io/api/public — FREE, no API key.
                  Returns the number of leaked records and their source names.

  hibp_catalogue  HaveIBeenPwned /api/v3/breaches — FREE, no API key.
                  The full breach encyclopaedia (1000+ breaches with metadata).
                  Not per-account, but used to enrich hits from the providers
                  above with authoritative descriptions and data classes.

All providers fail soft: if one is unreachable or rate-limited, the others
still answer, and the caller is told exactly which sources responded.
"""
from __future__ import annotations

import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

from config import Config

UA = "CyberSafe-Platform/1.1 (educational cyber-safety tool)"
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

HIBP_ACCOUNT = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_PASTE = "https://haveibeenpwned.com/api/v3/pasteaccount/"
XON_CHECK = "https://api.xposedornot.com/v1/check-email/"
XON_ANALYTICS = "https://api.xposedornot.com/v1/breach-analytics?email="
LEAKCHECK_PUBLIC = "https://leakcheck.io/api/public?check="

# --------------------------------------------------------------- rate limiting
_LOCK = threading.Lock()
_LAST_CALL: dict[str, float] = {}
_MIN_GAP = {"hibp": 1.7, "xon": 2.2, "leakcheck": 1.2}   # seconds between calls
_BACKOFF: dict[str, float] = {}                           # provider -> unix ts


def _throttle(provider: str):
    with _LOCK:
        gap = _MIN_GAP.get(provider, 1.0)
        last = _LAST_CALL.get(provider, 0.0)
        wait = gap - (time.time() - last)
        if wait > 0:
            time.sleep(min(wait, 5))
        _LAST_CALL[provider] = time.time()


def _blocked(provider: str) -> float:
    """Seconds remaining on a rate-limit backoff, 0 if clear."""
    until = _BACKOFF.get(provider, 0)
    return max(0.0, until - time.time())


def _set_backoff(provider: str, seconds: float):
    _BACKOFF[provider] = time.time() + min(seconds, 300)


def _fetch(url: str, headers: dict | None = None, timeout: int = 20,
           browser_ua: bool = False) -> tuple[int | None, str]:
    h = {"User-Agent": BROWSER_UA if browser_ua else UA,
         "Accept": "application/json"}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")[:600]
        except Exception:  # noqa: BLE001
            body = ""
        if e.code == 429:
            ra = e.headers.get("Retry-After") if e.headers else None
            try:
                secs = float(ra) if ra else 60
            except (TypeError, ValueError):
                secs = 60
            return 429, json.dumps({"retry_after": secs, "body": body[:200]})
        return e.code, body
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return None, f"network: {getattr(e, 'reason', e)}"
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:120]}"


# =============================================================== HIBP official
def hibp_official(email: str, api_key: str, timeout: int = 20) -> dict:
    """
    The authoritative per-account lookup. Requires the user's own HIBP API key.
    Returns the full breach objects HIBP holds for that address.
    """
    out = {"provider": "hibp_official", "label": "HaveIBeenPwned (official API)",
           "ok": False, "found": None, "breaches": [], "pastes": 0, "error": None,
           "authoritative": True}
    if not api_key:
        out["error"] = "no_api_key"
        return out
    wait = _blocked("hibp")
    if wait:
        out["error"] = f"rate limited, retry in {wait:.0f}s"
        return out

    _throttle("hibp")
    url = HIBP_ACCOUNT + urllib.parse.quote(email, safe="") + "?truncateResponse=false"
    status, body = _fetch(url, headers={"hibp-api-key": api_key}, timeout=timeout)

    if status == 200:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            out["error"] = "bad json from HIBP"
            return out
        out.update(ok=True, found=True)
        for b in data:
            out["breaches"].append({
                "name": b.get("Title") or b.get("Name"),
                "domain": b.get("Domain", ""),
                "date": b.get("BreachDate", ""),
                "year": int((b.get("BreachDate") or "0000")[:4] or 0),
                "accounts": b.get("PwnCount", 0),
                "data": b.get("DataClasses", []),
                "desc": _strip_html(b.get("Description", "")),
                "verified": b.get("IsVerified", True),
                "sensitive": b.get("IsSensitive", False),
                "fabricated": b.get("IsFabricated", False),
                "spam_list": b.get("IsSpamList", False),
                "malware": b.get("IsMalware", False),
                "stealer_log": b.get("IsStealerLog", False),
                "retired": b.get("IsRetired", False),
                "source": "HIBP",
            })
    elif status == 404:
        out.update(ok=True, found=False)       # HIBP: 404 means "not pwned"
    elif status == 401:
        out["error"] = "invalid or expired HIBP API key"
    elif status == 429:
        try:
            secs = json.loads(body).get("retry_after", 60)
        except Exception:  # noqa: BLE001
            secs = 60
        _set_backoff("hibp", secs)
        out["error"] = f"HIBP rate limit, retry in {secs:.0f}s"
    else:
        out["error"] = f"HTTP {status}"
    return out


def hibp_pastes(email: str, api_key: str, timeout: int = 15) -> int:
    if not api_key:
        return 0
    _throttle("hibp")
    status, body = _fetch(HIBP_PASTE + urllib.parse.quote(email, safe=""),
                          headers={"hibp-api-key": api_key}, timeout=timeout)
    if status == 200:
        try:
            return len(json.loads(body))
        except json.JSONDecodeError:
            return 0
    return 0


# =============================================================== XposedOrNot
def xposedornot(email: str, timeout: int = 20) -> dict:
    """FREE, keyless per-email breach lookup."""
    out = {"provider": "xposedornot", "label": "XposedOrNot (free)",
           "ok": False, "found": None, "breaches": [], "error": None,
           "authoritative": False}
    wait = _blocked("xon")
    if wait:
        out["error"] = f"rate limited, retry in {wait:.0f}s"
        return out

    _throttle("xon")
    status, body = _fetch(XON_CHECK + urllib.parse.quote(email, safe=""),
                          timeout=timeout, browser_ua=True)
    if status == 429:
        try:
            secs = json.loads(body).get("retry_after", 60)
        except Exception:  # noqa: BLE001
            secs = 60
        _set_backoff("xon", secs)
        out["error"] = f"rate limit, retry in {secs:.0f}s"
        return out
    if status == 404:
        out.update(ok=True, found=False)       # not found
        return out
    if status != 200:
        out["error"] = f"HTTP {status}"
        return out

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        out["error"] = "bad json"
        return out

    if isinstance(data, dict) and data.get("Error") == "Not found":
        out.update(ok=True, found=False)
        return out

    names = []
    raw = data.get("breaches")
    if isinstance(raw, list) and raw:
        first = raw[0]
        names = first if isinstance(first, list) else [x for x in raw if isinstance(x, str)]
    names = [n for n in names if isinstance(n, str) and n.strip()]
    out.update(ok=True, found=bool(names))
    out["breaches"] = [{"name": n, "source": "XposedOrNot"} for n in names]
    return out


def xposedornot_analytics(email: str, timeout: int = 20) -> dict:
    """Richer XposedOrNot data: exposed data classes, industry spread, risk."""
    out = {"ok": False, "data_classes": [], "industries": [], "risk": None,
           "yearly": [], "pastes": 0, "error": None}
    if _blocked("xon"):
        out["error"] = "rate limited"
        return out
    _throttle("xon")
    status, body = _fetch(XON_ANALYTICS + urllib.parse.quote(email, safe=""),
                          timeout=timeout, browser_ua=True)
    if status != 200:
        out["error"] = f"HTTP {status}"
        return out
    try:
        d = json.loads(body)
    except json.JSONDecodeError:
        out["error"] = "bad json"
        return out

    out["ok"] = True
    metrics = d.get("BreachMetrics") or {}
    risk = metrics.get("risk")
    if isinstance(risk, list) and risk:
        r0 = risk[0]
        if isinstance(r0, dict):
            out["risk"] = {"label": r0.get("risk_label"), "score": r0.get("risk_score")}
    xposed = metrics.get("xposed_data")
    if isinstance(xposed, list) and xposed:
        out["data_classes"] = _flatten_xposed(xposed)
    ind = metrics.get("industry")
    if isinstance(ind, list) and ind and isinstance(ind[0], list):
        out["industries"] = [{"industry": _INDUSTRY.get(k, k), "count": v}
                             for k, v in ind[0] if isinstance(v, int) and v > 0]
    yearly = metrics.get("yearwise_details")
    if isinstance(yearly, list) and yearly and isinstance(yearly[0], dict):
        out["yearly"] = [{"year": k.replace("y", "20"), "count": v}
                         for k, v in yearly[0].items() if isinstance(v, int) and v > 0]
    details = d.get("ExposedBreaches", {})
    if isinstance(details, dict):
        out["breach_details"] = details.get("breaches_details", [])
    return out


_INDUSTRY = {
    "misc": "Miscellaneous", "ente": "Entertainment", "heal": "Healthcare",
    "elec": "Electronics", "mini": "Mining", "musi": "Music", "manu": "Manufacturing",
    "ener": "Energy", "news": "News & Media", "hosp": "Hospitality", "food": "Food",
    "phar": "Pharmaceutical", "educ": "Education", "cons": "Construction",
    "agri": "Agriculture", "tele": "Telecom", "info": "Information Technology",
    "tran": "Transport", "aero": "Aerospace", "fina": "Finance", "reta": "Retail",
    "nonp": "Non-profit", "govt": "Government", "spor": "Sports", "envi": "Environment",
}


def _flatten_xposed(xposed) -> list[str]:
    """XposedOrNot nests data classes in children arrays."""
    out = []

    def walk(node):
        if isinstance(node, dict):
            name = node.get("name")
            if name and not node.get("children"):
                out.append(str(name).replace("_", " ").title())
            for c in node.get("children", []) or []:
                walk(c)
        elif isinstance(node, list):
            for c in node:
                walk(c)
    walk(xposed)
    return sorted(set(out))[:40]


# =============================================================== LeakCheck
def leakcheck(email: str, timeout: int = 20) -> dict:
    """FREE, keyless. Returns record count and the source names."""
    out = {"provider": "leakcheck", "label": "LeakCheck (free public API)",
           "ok": False, "found": None, "breaches": [], "records": 0,
           "fields": [], "error": None, "authoritative": False}
    if _blocked("leakcheck"):
        out["error"] = "rate limited"
        return out
    _throttle("leakcheck")
    status, body = _fetch(LEAKCHECK_PUBLIC + urllib.parse.quote(email, safe=""),
                          timeout=timeout, browser_ua=True)
    if status == 429:
        _set_backoff("leakcheck", 60)
        out["error"] = "rate limit"
        return out
    if status != 200:
        out["error"] = f"HTTP {status}"
        return out
    try:
        d = json.loads(body)
    except json.JSONDecodeError:
        out["error"] = "bad json"
        return out
    if not d.get("success"):
        out.update(ok=True, found=False)
        out["error"] = d.get("error")
        return out

    srcs = d.get("sources") or []
    out.update(ok=True, found=bool(srcs), records=int(d.get("found") or 0),
               fields=d.get("fields") or [])
    for s in srcs:
        nm = s.get("name", "") if isinstance(s, dict) else str(s)
        date = s.get("date", "") if isinstance(s, dict) else ""
        year = 0
        m = re.search(r"(19|20)\d{2}", f"{date} {nm}")
        if m:
            year = int(m.group(0))
        out["breaches"].append({"name": re.sub(r"\s*\(\d{4}\)$", "", nm).strip(),
                                "date": date, "year": year, "source": "LeakCheck"})
    return out


# =============================================================== HIBP catalogue
def fetch_hibp_catalogue(timeout: int = 45) -> dict:
    """
    Download the complete HIBP breach encyclopaedia. FREE, no API key.
    ~1000 breaches with authoritative descriptions and data classes.
    """
    status, body = _fetch(HIBP_BREACHES, timeout=timeout)
    if status != 200:
        return {"ok": False, "error": f"HTTP {status}", "breaches": []}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {"ok": False, "error": "bad json", "breaches": []}

    out = []
    for b in data:
        out.append({
            "name": b.get("Title") or b.get("Name"),
            "key": (b.get("Name") or "").lower(),
            "domain": b.get("Domain", ""),
            "year": int((b.get("BreachDate") or "0000")[:4] or 0),
            "date": b.get("BreachDate", ""),
            "accounts": b.get("PwnCount", 0),
            "data": b.get("DataClasses", []),
            "desc": _strip_html(b.get("Description", "")),
            "verified": b.get("IsVerified", True),
            "fabricated": b.get("IsFabricated", False),
            "sensitive": b.get("IsSensitive", False),
            "spam_list": b.get("IsSpamList", False),
            "malware": b.get("IsMalware", False),
            "stealer_log": b.get("IsStealerLog", False),
            "retired": b.get("IsRetired", False),
            "severity": _severity(b.get("DataClasses", []), b.get("PwnCount", 0)),
            "category": _category(b.get("DataClasses", []), b.get("Domain", "")),
        })
    return {"ok": True, "breaches": out, "count": len(out),
            "fetched_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}


def _strip_html(s: str) -> str:
    s = re.sub(r"<[^>]+>", "", s or "")
    for a, b in (("&quot;", '"'), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                 ("&#39;", "'"), ("&nbsp;", " ")):
        s = s.replace(a, b)
    return re.sub(r"\s+", " ", s).strip()


CRITICAL_CLASSES = {
    "passwords", "credit cards", "bank account numbers", "social security numbers",
    "government issued ids", "passport numbers", "health insurance information",
    "medical conditions", "biometric data", "security questions and answers",
    "partial credit card data", "credit card cvv", "tax records", "pins",
    "auth tokens", "encrypted keys", "private messages", "sexual orientation",
    "sexual fetishes", "bank statements", "mothers maiden names",
}
HIGH_CLASSES = {
    "phone numbers", "physical addresses", "dates of birth", "genders",
    "ip addresses", "geographic locations", "employers", "job titles",
    "driver's licenses", "income levels", "credit status information",
    "family members names", "relationship statuses", "browsing histories",
}


def _severity(classes: list[str], pwn: int) -> str:
    low = {str(c).lower() for c in (classes or [])}
    if low & CRITICAL_CLASSES:
        return "critical"
    if (low & HIGH_CLASSES) or pwn > 50_000_000:
        return "high"
    if pwn > 1_000_000:
        return "medium"
    return "low"


def _category(classes: list[str], domain: str) -> str:
    d = (domain or "").lower()
    low = {str(c).lower() for c in (classes or [])}
    pairs = [
        (("bank", "pay", "finance", "credit", "upstox", "zerodha", "mobikwik"), "finance"),
        (("health", "med", "pharma", "hospital", "aiims"), "health"),
        (("game", "gaming", "steam", "xbox", "zynga", "neopets"), "gaming"),
        (("shop", "store", "cart", "commerce", "bazaar", "flipkart", "amazon",
          "bigbasket", "myntra"), "ecommerce"),
        (("social", "facebook", "twitter", "linkedin", "insta", "tumblr", "myspace"), "social"),
        (("dating", "match", "tinder", "badoo", "zoosk", "adult"), "dating"),
        (("edu", "learn", "school", "academy", "chegg", "unacademy"), "education"),
        (("mail", "email"), "email"),
        (("tel", "mobile", "airtel", "jio", "vodafone"), "telecom"),
        (("travel", "air", "hotel", "booking", "ixigo", "irctc"), "travel"),
    ]
    for keys, cat in pairs:
        if any(k in d for k in keys):
            return cat
    if "credit cards" in low or "bank account numbers" in low:
        return "finance"
    if "medical conditions" in low:
        return "health"
    return "other"
