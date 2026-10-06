"""
Module 11 -- Data Breach Exposure Checker  (real per-email lookup)

HOW THE ANSWER IS PRODUCED
--------------------------
The question "has THIS email been breached?" is answered by querying real
breach databases live. Several providers are consulted and their results merged:

  * HIBP official API   -- authoritative. Used automatically when the user adds
                           their own HaveIBeenPwned API key in Settings.
  * XposedOrNot         -- FREE, no API key. Real per-email breach list.
  * LeakCheck public    -- FREE, no API key. Record count + source names.

Every hit is then enriched with authoritative breach metadata downloaded from
HIBP's free, keyless /api/v3/breaches encyclopaedia (1000+ breaches), which is
cached locally so it keeps working offline.

If NO provider can be reached, the module falls back to offline inference and
labels the result clearly as an estimate rather than a lookup.

Two further capabilities remain fully offline:
  * Pwned Passwords k-anonymity password check (free, keyless, opt-in)
  * Local corpus exact match for dumps the user lawfully imports
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from config import Config
from core import ollama_client
from core.database import execute, get_setting, query, query_one, scalar, set_setting
from core.utils import clamp, utcnow
from modules import breach_providers as bp

CATALOG_PATH = Path(Config.KNOWLEDGE_DIR) / "breach_catalog.json"
HIBP_CACHE_PATH = Path(Config.KNOWLEDGE_DIR) / "hibp_breaches.json"
_CATALOG = None
_HIBP = None
_HIBP_INDEX: dict | None = None

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "CyberSafe-Platform-Educational/1.0"


# ================================================================= catalogue
def catalog() -> dict:
    global _CATALOG
    if _CATALOG is None:
        try:
            with open(CATALOG_PATH, encoding="utf-8") as fh:
                _CATALOG = json.load(fh)
        except (OSError, json.JSONDecodeError):
            _CATALOG = {"breaches": [], "provider_notes": {}, "_meta": {}}
    return _CATALOG


def all_breaches() -> list[dict]:
    """The full reference catalogue: synced HIBP data when available, else curated."""
    h = hibp_catalogue()
    return h if h else catalog().get("breaches", [])


# ---------------------------------------------------------------- HIBP sync
def hibp_catalogue() -> list[dict]:
    """Locally cached copy of HIBP's free breach encyclopaedia."""
    global _HIBP
    if _HIBP is None:
        try:
            with open(HIBP_CACHE_PATH, encoding="utf-8") as fh:
                _HIBP = json.load(fh).get("breaches", [])
        except (OSError, json.JSONDecodeError):
            _HIBP = []
    return _HIBP


def hibp_index() -> dict:
    """name/key/domain -> breach record, for fast enrichment of provider hits."""
    global _HIBP_INDEX
    if _HIBP_INDEX is None:
        idx = {}
        for b in hibp_catalogue():
            for k in (b.get("key"), b.get("name"), b.get("domain")):
                if k:
                    idx.setdefault(_norm(k), b)
        _HIBP_INDEX = idx
    return _HIBP_INDEX


_TLD_RE = re.compile(
    r"\.(com|net|org|io|co|in|co\.in|co\.uk|me|ru|de|fr|br|jp|cn|xyz|info|biz|tv|us|"
    r"au|ca|nl|es|it|pl|se|no|dk|fi|gr|cz|ch|at|be|pt|tr|ir|id|my|sg|ph|vn|th|kr)$")


def _norm(s: str) -> str:
    """
    Normalise a breach name for cross-provider matching.

    Providers disagree on naming: XposedOrNot says "Paidwork", LeakCheck says
    "Paidwork.com", HIBP says "Paidwork". Stripping the TLD and all punctuation
    collapses these to one key so the same breach is never listed twice.
    """
    s = str(s or "").lower().strip()
    s = re.sub(r"\s*\(\d{4}\)\s*$", "", s)        # trailing "(2024)"
    s = _TLD_RE.sub("", s)                         # trailing TLD
    return re.sub(r"[^a-z0-9]", "", s)


def sync_hibp_catalogue(force: bool = False) -> dict:
    """Download HIBP's free breach encyclopaedia and cache it locally."""
    global _HIBP, _HIBP_INDEX
    if not force and HIBP_CACHE_PATH.exists():
        age_days = (time.time() - HIBP_CACHE_PATH.stat().st_mtime) / 86400
        if age_days < 7:
            return {"ok": True, "cached": True, "count": len(hibp_catalogue()),
                    "age_days": round(age_days, 1),
                    "message": "Using the cached copy (less than 7 days old)."}
    res = bp.fetch_hibp_catalogue()
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error"),
                "message": "Could not reach HaveIBeenPwned. The existing catalogue is unchanged."}
    HIBP_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(HIBP_CACHE_PATH, "w", encoding="utf-8") as fh:
        json.dump({"fetched_at": res["fetched_at"], "source": bp.HIBP_BREACHES,
                   "breaches": res["breaches"]}, fh)
    _HIBP = res["breaches"]
    _HIBP_INDEX = None
    set_setting("hibp_catalogue_synced", res["fetched_at"])
    return {"ok": True, "cached": False, "count": res["count"],
            "fetched_at": res["fetched_at"],
            "message": f"Downloaded {res['count']} breaches from HaveIBeenPwned "
                       f"(free endpoint, no API key)."}


def hibp_sync_status() -> dict:
    n = len(hibp_catalogue())
    synced = get_setting("hibp_catalogue_synced")
    age = None
    if HIBP_CACHE_PATH.exists():
        age = round((time.time() - HIBP_CACHE_PATH.stat().st_mtime) / 86400, 1)
    return {"synced": bool(n), "count": n, "fetched_at": synced, "age_days": age,
            "stale": (age is None or age > 14)}


# ---------------------------------------------------------------- settings
def hibp_api_key() -> str:
    return (get_setting("hibp_api_key", "") or Config.HIBP_API_KEY or "").strip()


def set_hibp_api_key(key: str):
    set_setting("hibp_api_key", (key or "").strip())


def online_enabled() -> bool:
    return get_setting("breach_online", "1") != "0"


def set_online_enabled(on: bool):
    set_setting("breach_online", "1" if on else "0")


INDIA_NAMES = {
    "bigbasket", "boat", "dominos", "dominosindia", "indiamart", "indianrailways",
    "ixigo", "upstox", "zomato", "unacademy", "mobikwik", "justdial", "airindia",
    "starhealth", "wazirx", "policybazaar", "rentomojo", "jio", "paytm", "phonepe",
    "swiggy", "myntra", "flipkart", "aadhaar", "uidai", "irctc", "cdsl", "aiims",
    "haldiram", "dunzo", "byjus", "oyo", "makemytrip", "cleartrip", "nykaa",
    "telecomregulatoryauthorityofindia", "trai", "razorpay", "cred", "zerodha",
}


def is_indian(b: dict) -> bool:
    if b.get("region") == "India":
        return True
    dom = str(b.get("domain", "")).lower()
    if dom.endswith(".in") or ".co.in" in dom or ".gov.in" in dom or ".org.in" in dom:
        return True
    return _norm(b.get("name", "")) in INDIA_NAMES or _norm(b.get("key", "")) in INDIA_NAMES


def catalog_stats() -> dict:
    b = all_breaches()
    total_accounts = sum(x.get("accounts", 0) for x in b)
    by_cat: dict[str, int] = {}
    for x in b:
        by_cat[x.get("category", "other")] = by_cat.get(x.get("category", "other"), 0) + 1
    years = [x["year"] for x in b if x.get("year")]
    synced = hibp_sync_status()
    return {
        "breach_count": len(b),
        "total_accounts": total_accounts,
        "total_accounts_human": _big(total_accounts),
        "critical": sum(1 for x in b if x.get("severity") == "critical"),
        "indian": sum(1 for x in b if is_indian(x)),
        "stealer_logs": sum(1 for x in b if x.get("stealer_log")),
        "sensitive": sum(1 for x in b if x.get("sensitive")),
        "categories": sorted(by_cat.items(), key=lambda kv: -kv[1]),
        "year_range": (min(years), max(years)) if years else (0, 0),
        "source": "HaveIBeenPwned (synced)" if synced["synced"] else "built-in curated catalogue",
        "last_updated": synced.get("fetched_at")
                        or catalog().get("_meta", {}).get("last_updated", "unknown"),
    }


def _big(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "0"
    if n >= 1e9:
        return f"{n/1e9:.1f} billion"
    if n >= 1e6:
        return f"{n/1e6:.0f} million"
    if n >= 1e3:
        return f"{n/1e3:.0f} thousand"
    return f"{n:.0f}"


def search_breaches(q: str, limit: int = 60) -> list[dict]:
    q = (q or "").strip().lower()
    src = all_breaches()
    if not q:
        return sorted(src, key=lambda b: -b.get("accounts", 0))[:limit]
    if q in ("india", "indian"):
        return sorted([b for b in src if is_indian(b)],
                      key=lambda b: -b.get("accounts", 0))[:limit]
    special = {"stealer log": "stealer_log", "sensitive": "sensitive",
               "unverified": "_unverified", "spam list": "spam_list",
               "fabricated": "fabricated"}
    if q in special:
        key = special[q]
        if key == "_unverified":
            hits = [b for b in src if not b.get("verified", True)]
        else:
            hits = [b for b in src if b.get(key)]
        return sorted(hits, key=lambda b: -b.get("accounts", 0))[:limit]
    out = []
    for b in src:
        hay = (f"{b.get('name','')} {b.get('domain','')} {b.get('category','')} "
               f"{b.get('desc','')} {' '.join(b.get('data', []))}").lower()
        if q in hay:
            out.append(b)
    return sorted(out, key=lambda b: -b.get("accounts", 0))[:limit]


# ================================================================= email check
EMAIL_RE = re.compile(r"^[\w.+\-]+@[\w\-]+\.[\w.\-]+$")

DISPOSABLE = {"temp-mail.org", "guerrillamail.com", "10minutemail.com", "mailinator.com",
              "throwawaymail.com", "yopmail.com", "trashmail.com", "sharklasers.com",
              "getnada.com", "tempmail.com", "fakeinbox.com", "dispostable.com"}

FREE_PROVIDERS = {"gmail.com", "yahoo.com", "ymail.com", "rocketmail.com", "hotmail.com",
                  "outlook.com", "live.com", "msn.com", "aol.com", "rediffmail.com",
                  "protonmail.com", "proton.me", "icloud.com", "me.com", "mac.com",
                  "zoho.com", "mail.com", "gmx.com", "yandex.com", "tutanota.com",
                  "hushmail.com", "fastmail.com", "inbox.com", "sify.com"}

# Services a user can tick to cross-reference against the catalogue.
COMMON_SERVICES = [
    ("linkedin.com", "LinkedIn"), ("facebook.com", "Facebook"), ("twitter.com", "Twitter / X"),
    ("adobe.com", "Adobe"), ("dropbox.com", "Dropbox"), ("canva.com", "Canva"),
    ("myfitnesspal.com", "MyFitnessPal"), ("quora.com", "Quora"), ("tumblr.com", "Tumblr"),
    ("myspace.com", "MySpace"), ("chegg.com", "Chegg"), ("zynga.com", "Zynga"),
    ("wattpad.com", "Wattpad"), ("deezer.com", "Deezer"), ("ebay.com", "eBay"),
    ("marriott.com", "Marriott"), ("uber.com", "Uber"), ("zomato.com", "Zomato"),
    ("bigbasket.com", "BigBasket"), ("unacademy.com", "Unacademy"),
    ("dominos.co.in", "Domino's India"), ("mobikwik.com", "MobiKwik"),
    ("justdial.com", "JustDial"), ("upstox.com", "Upstox"), ("airindia.in", "Air India"),
    ("starhealth.in", "Star Health"), ("boat-lifestyle.com", "boAt"),
    ("ixigo.com", "ixigo"), ("lastpass.com", "LastPass"), ("23andme.com", "23andMe"),
    ("t-mobile.com", "T-Mobile"), ("att.com", "AT&T"), ("neopets.com", "Neopets"),
    ("ticketmaster.com", "Ticketmaster"), ("archive.org", "Internet Archive"),
    ("disqus.com", "Disqus"), ("imgur.com", "Imgur"), ("last.fm", "Last.fm"),
    ("gravatar.com", "Gravatar"), ("houzz.com", "Houzz"), ("poshmark.com", "Poshmark"),
    ("dell.com", "Dell"), ("robinhood.com", "Robinhood"), ("capitalone.com", "Capital One"),
    ("equifax.com", "Equifax"), ("ashleymadison.com", "Ashley Madison"),
    ("adultfriendfinder.com", "FriendFinder"), ("zoosk.com", "Zoosk"),
    ("coffeemeetsbagel.com", "Coffee Meets Bagel"), ("badoo.com", "Badoo"),
]

AGGREGATE_CATEGORIES = {"aggregate", "data broker"}


def live_lookup(email: str, timeout: int = 20) -> dict:
    """
    Query every available live provider and merge the answers.

    Returns a dict describing, per provider, whether the address was found,
    plus a merged breach list and an overall verdict.
    """
    providers, errors = [], []
    key = hibp_api_key()

    # 1. HIBP official (authoritative) when a key is configured
    if key:
        r = bp.hibp_official(email, key, timeout=timeout)
        providers.append(r)
        if r.get("error"):
            errors.append(f"HIBP: {r['error']}")

    # 2. free keyless providers
    for fn, nm in ((bp.xposedornot, "XposedOrNot"), (bp.leakcheck, "LeakCheck")):
        try:
            r = fn(email, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            r = {"provider": nm.lower(), "label": nm, "ok": False, "found": None,
                 "breaches": [], "error": str(e)[:120], "authoritative": False}
        providers.append(r)
        if r.get("error"):
            errors.append(f"{nm}: {r['error']}")

    responded = [p for p in providers if p.get("ok")]
    hits = [p for p in responded if p.get("found")]

    # merge breach names across providers
    merged: dict[str, dict] = {}
    for p in responded:
        for b in p.get("breaches", []):
            nm = (b.get("name") or "").strip()
            if not nm:
                continue
            k = _norm(nm)
            if k not in merged:
                merged[k] = dict(b)
                merged[k]["seen_in"] = [p["label"]]
            else:
                if p["label"] not in merged[k]["seen_in"]:
                    merged[k]["seen_in"].append(p["label"])
                # prefer the cleaner display name (no trailing TLD)
                if "." in str(merged[k].get("name", "")) and "." not in nm:
                    merged[k]["name"] = nm
                for fld in ("year", "accounts", "data", "desc", "domain", "date"):
                    if not merged[k].get(fld) and b.get(fld):
                        merged[k][fld] = b[fld]

    # enrich from the HIBP encyclopaedia
    idx = hibp_index()
    enriched = []
    for k, b in merged.items():
        ref = idx.get(k) or idx.get(_norm(b.get("domain", "")))
        rec = {
            "name": b.get("name"),
            "domain": b.get("domain") or (ref or {}).get("domain", ""),
            "year": b.get("year") or (ref or {}).get("year", 0),
            "date": b.get("date") or (ref or {}).get("date", ""),
            "accounts": b.get("accounts") or (ref or {}).get("accounts", 0),
            "data": b.get("data") or (ref or {}).get("data", []),
            "desc": b.get("desc") or (ref or {}).get("desc", ""),
            "severity": (ref or {}).get("severity")
                        or bp._severity(b.get("data", []), b.get("accounts", 0)),
            "category": (ref or {}).get("category", "other"),
            "verified": b.get("verified", (ref or {}).get("verified", True)),
            "sensitive": b.get("sensitive", (ref or {}).get("sensitive", False)),
            "stealer_log": b.get("stealer_log", (ref or {}).get("stealer_log", False)),
            "spam_list": b.get("spam_list", (ref or {}).get("spam_list", False)),
            "malware": b.get("malware", (ref or {}).get("malware", False)),
            "seen_in": b.get("seen_in", []),
            "enriched": ref is not None,
        }
        enriched.append(rec)
    enriched.sort(key=lambda x: (-(x.get("year") or 0), -(x.get("accounts") or 0)))

    records = max([p.get("records", 0) for p in responded] or [0])
    authoritative = any(p.get("authoritative") and p.get("ok") for p in providers)

    # How much weight can a "not found" answer carry?
    if authoritative:
        confidence, conf_note = "high", (
            "HaveIBeenPwned's official API answered. This is the authoritative source.")
    elif len(responded) >= 2:
        confidence, conf_note = "medium", (
            f"{len(responded)} independent free databases answered and agreed. "
            f"Add a HaveIBeenPwned API key in Settings for authoritative coverage.")
    elif len(responded) == 1:
        confidence, conf_note = "low", (
            f"Only {responded[0]['label']} answered. A single free database has partial "
            f"coverage, so 'not found' here is weaker evidence than a HIBP result.")
    else:
        confidence, conf_note = "none", "No breach database could be reached."

    return {
        "attempted": True,
        "providers": providers,
        "responded": [p["label"] for p in responded],
        "responded_count": len(responded),
        "failed": errors,
        "any_response": bool(responded),
        "found": bool(hits),
        "conclusive_clean": bool(responded) and not hits,
        "authoritative": authoritative,
        "confidence": confidence,
        "confidence_note": conf_note,
        "breaches": enriched,
        "breach_count": len(enriched),
        "leaked_records": records,
        "hibp_key_used": bool(key),
    }


def check_email(email: str, services: list[str] | None = None,
                use_ai: bool = True, online: bool | None = None) -> dict:
    """
    Determine whether an email address appears in known data breaches.

    Primary path: live lookup against real breach databases (see live_lookup).
    Fallback path: offline inference, clearly labelled as an estimate.
    """
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        return {"error": "Please enter a valid email address."}

    local, domain = email.rsplit("@", 1)
    services = [s.lower() for s in (services or [])]
    if online is None:
        online = online_enabled()

    findings = []

    def add(sev, title, detail, pts):
        findings.append({"severity": sev, "title": title, "detail": detail, "points": pts})

    # ---------- 1. LIVE LOOKUP (the real answer)
    live = {"attempted": False, "any_response": False, "found": False,
            "breaches": [], "providers": [], "responded": [], "failed": [],
            "conclusive_clean": False, "authoritative": False, "breach_count": 0,
            "leaked_records": 0, "hibp_key_used": False}
    if online:
        live = live_lookup(email)

    live_breaches = live.get("breaches", [])
    for b in live_breaches:
        tags = []
        if b.get("stealer_log"):
            tags.append("stealer malware log")
        if b.get("sensitive"):
            tags.append("sensitive breach")
        if not b.get("verified", True):
            tags.append("unverified")
        if b.get("spam_list"):
            tags.append("spam list")
        detail = (f"{_big(b.get('accounts', 0))} accounts" if b.get("accounts")
                  else "account count undisclosed")
        if b.get("data"):
            detail += ". Exposed: " + ", ".join(b["data"][:6])
        if tags:
            detail += f". [{'; '.join(tags)}]"
        if b.get("seen_in"):
            detail += f" (confirmed by {', '.join(b['seen_in'])})"
        add(b.get("severity", "medium"),
            f"FOUND in breach: {b['name']}" + (f" ({b['year']})" if b.get("year") else ""),
            detail,
            {"critical": 30, "high": 20, "medium": 12, "low": 7}.get(b.get("severity"), 10))

    # ---------- 2. local imported corpus (exact match)
    corpus_hits = check_local_corpus(email)
    if corpus_hits:
        add("critical", "EXACT MATCH in your imported breach corpus",
            f"This address appears in {len(corpus_hits)} imported record(s): " +
            ", ".join(sorted({h['source'] for h in corpus_hits})[:4]) + ".", 40)

    # ---------- 3. offline inference (fallback / supplement)
    provider_breaches, service_breaches = [], []
    use_inference = not live.get("any_response")
    if use_inference:
        provider_breaches = [b for b in all_breaches()
                             if _norm(b.get("domain", "")) == _norm(domain)]
        for b in provider_breaches:
            add(b.get("severity", "medium"),
                f"Your email provider was breached: {b['name']} ({b.get('year')})",
                f"{_big(b.get('accounts', 0))} accounts affected. Exposed: "
                f"{', '.join(b.get('data', [])[:5])}.",
                {"critical": 22, "high": 15, "medium": 9, "low": 5}.get(b.get("severity"), 8))
        for svc in services:
            for b in all_breaches():
                if _norm(b.get("domain", "")) == _norm(svc) and b not in provider_breaches:
                    service_breaches.append(b)
        service_breaches = _dedupe(service_breaches)
        for b in service_breaches:
            add(b.get("severity", "medium"),
                f"Service you use was breached: {b['name']} ({b.get('year')})",
                f"{_big(b.get('accounts', 0))} accounts. Exposed: "
                f"{', '.join(b.get('data', [])[:5])}.",
                {"critical": 20, "high": 14, "medium": 9, "low": 4}.get(b.get("severity"), 7))

    provider_note = catalog().get("provider_notes", {}).get(domain)

    # ---------- 4. address-surface risk (always, but low weight)
    if domain in DISPOSABLE:
        add("low", "Disposable email domain",
            "Throwaway addresses limit long-term exposure, but any account tied to one "
            "cannot be recovered if you lose access.", 2)
    elif domain not in FREE_PROVIDERS:
        add("info", "Custom or corporate domain",
            f"'{domain}' is not a mainstream consumer provider. Corporate addresses are "
            f"prime targets for business email compromise and spear phishing.", 4)
    if re.fullmatch(r"[a-z]+[._][a-z]+\d{0,4}", local):
        add("info", "Predictable address format",
            f"'{local}' follows a guessable firstname.lastname pattern, so attackers can "
            f"enumerate it without any breach data.", 4)
    if re.search(r"(19[5-9]\d|20[0-2]\d)$", local):
        add("info", "Birth year likely embedded in the address",
            "A year in your email address helps attackers answer identity-verification "
            "questions and craft convincing phishing.", 4)
    if re.search(r"\b(admin|root|info|support|contact|billing|sales|hr|finance|security)\b", local):
        add("medium", "Role-based address",
            f"'{local}@' is a role account. These are published, heavily phished, and often "
            f"shared between staff, which makes attribution and MFA harder.", 8)

    # ---------- verdict
    breached = bool(live.get("found")) or bool(corpus_hits)
    if breached:
        n = live.get("breach_count", 0) + (1 if corpus_hits else 0)
        base = min(45 + 7 * live.get("breach_count", 0), 92)
        if corpus_hits:
            base = max(base, 85)
        if any(b.get("severity") == "critical" for b in live_breaches):
            base = max(base, 80)
        if any(b.get("stealer_log") for b in live_breaches):
            base = max(base, 88)
        score = clamp(max(base, sum(f["points"] for f in findings) // 2))
        verdict = "BREACHED"
        headline = (f"This address was found in {live.get('breach_count', 0)} known data "
                    f"breach(es)." if live.get("breach_count")
                    else "This address was found in your imported breach corpus.")
    elif live.get("conclusive_clean"):
        score = clamp(sum(f["points"] for f in findings if f["points"] <= 8))
        verdict = "NOT FOUND"
        headline = ("No breach records were found for this address by "
                    f"{', '.join(live['responded'])}. " + live.get("confidence_note", ""))
    else:
        score = clamp(sum(f["points"] for f in findings))
        verdict = ("Unknown — estimate only" if score < 55 else "Likely exposed — estimate only")
        headline = ("No breach database could be reached, so this is an OFFLINE ESTIMATE "
                    "based on your provider's history and the services you selected, not a "
                    "lookup of your actual address.")

    exposed_data = _aggregate_exposed(
        live_breaches if live_breaches else (provider_breaches + service_breaches))
    matched = live_breaches if live_breaches else _dedupe(provider_breaches + service_breaches)
    total_records = sum(b.get("accounts", 0) for b in matched)

    result = {
        "email": email,
        "local_part": local,
        "domain": domain,
        "breached": breached,
        "lookup_mode": ("live" if live.get("any_response") else "offline_estimate"),
        "verdict": verdict,
        "headline": headline,
        "risk_score": score,
        "band": ("critical" if score >= 80 else "high" if score >= 55
                 else "medium" if score >= 25 else "low"),
        "live": live,
        "findings": sorted(findings, key=lambda f: -f["points"]),
        "matched_breaches": matched,
        "provider_breaches": provider_breaches,
        "service_breaches": service_breaches,
        "corpus_hits": corpus_hits,
        "provider_note": provider_note,
        "exposed_data_types": exposed_data,
        "total_records": total_records,
        "total_records_human": _big(total_records),
        "leaked_records": live.get("leaked_records", 0),
        "timeline": sorted(
            [{"year": b.get("year") or 0, "name": b.get("name"),
              "accounts": b.get("accounts", 0), "severity": b.get("severity", "medium")}
             for b in matched if b.get("year")], key=lambda x: x["year"]),
        "action_plan": build_action_plan(score, exposed_data, matched, domain),
        "method_note": _method_note(live),
        "checked_at": utcnow(),
    }

    if use_ai:
        result["ai"] = ai_assessment(result)

    _log_check(email, score, len(matched))
    return result


def _method_note(live: dict) -> str:
    if not live.get("attempted"):
        return ("Online lookup is switched off, so this is an offline estimate based on the "
                "breach catalogue. Enable online lookup for a real per-address answer.")
    if not live.get("any_response"):
        return ("No breach database could be reached (check your internet connection). "
                "The result shown is an offline ESTIMATE based on your email provider's "
                "breach history and the services you selected — it is not a lookup of your "
                "actual address.")
    src = ", ".join(live["responded"])
    base = f"Live lookup performed against: {src}."
    if live.get("hibp_key_used") and live.get("authoritative"):
        base += " HaveIBeenPwned's official API answered, which is authoritative."
    elif not live.get("hibp_key_used"):
        base += (" Add your HaveIBeenPwned API key in Settings to also query HIBP's official "
                 "database, which is the most complete source available.")
    if live.get("failed"):
        base += " Providers that did not answer: " + "; ".join(live["failed"]) + "."
    return base


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for b in items:
        k = (b.get("name"), b.get("year"))
        if k not in seen:
            seen.add(k)
            out.append(b)
    return out


def _aggregate_exposed(breaches: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    for b in breaches:
        for d in b.get("data", []):
            counts[d] = counts.get(d, 0) + 1
    # Matched case-insensitively: HIBP, XposedOrNot and the curated catalogue all
    # use different capitalisation for the same data class.
    sev_map = {k.lower(): v for k, v in {
        "Passwords (plaintext)": "critical", "Passwords": "critical",
        "Social security numbers": "critical", "Government issued IDs": "critical",
        "Passport numbers": "critical", "Credit card numbers": "critical",
        "Credit cards": "critical", "Partial credit card data": "critical",
        "Credit card CVV": "critical", "Payment cards": "critical",
        "Bank account numbers": "critical", "Bank statements": "critical",
        "KYC documents": "critical", "Aadhaar numbers": "critical",
        "Aadhaar details": "critical", "PAN numbers": "critical", "PINs": "critical",
        "Medical records": "critical", "Health records": "critical",
        "Medical conditions": "critical", "Health insurance information": "critical",
        "Genetic ancestry results": "critical", "Encrypted password vaults": "critical",
        "Biometric data": "critical", "Auth tokens": "critical",
        "Encrypted keys": "critical", "Private messages": "critical",
        "Security questions and answers": "critical", "Tax records": "critical",
        "Sexual orientation": "critical", "Sexual fetishes": "critical",
        "Mothers maiden names": "critical", "Historical passwords": "critical",
        "Driver's licenses": "high", "Driver's licence numbers": "high",
        "Security questions": "high", "Dates of birth": "high", "Phone numbers": "high",
        "Partial phone numbers": "high", "Addresses": "high", "Home addresses": "high",
        "Physical addresses": "high", "Geographic locations": "high",
        "IP addresses": "high", "Credit scores": "high", "Income levels": "high",
        "Employers": "high", "Browsing histories": "high",
        "Credit status information": "high", "Family members names": "high",
    }.items()}
    out = []
    for d, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        low = d.lower().strip()
        sev = sev_map.get(low)
        if sev is None:
            if "password" in low:
                sev = "critical"
            elif any(k in low for k in ("ssn", "social security", "passport", "card",
                                        "bank", "medical", "health", "biometric",
                                        "token", "private key")):
                sev = "critical"
            elif any(k in low for k in ("number", "address", "birth", "document",
                                        "location", "licence", "license", "income")):
                sev = "high"
            else:
                sev = "medium"
        out.append({"type": d, "breach_count": n, "severity": sev})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(out, key=lambda x: (order[x["severity"]], -x["breach_count"]))


def build_action_plan(score: int, exposed: list[dict], breaches: list[dict],
                      domain: str) -> list[dict]:
    plan, types = [], {e["type"].lower() for e in exposed}

    if any("password" in t for t in types) or score >= 25:
        plan.append({"priority": "immediate", "icon": "🔑",
                     "action": "Change the password on every affected service",
                     "why": "Breached passwords are fed straight into credential-stuffing bots. "
                            "Change them on the real site, never via a link in an email."})
    plan.append({"priority": "immediate", "icon": "🛡️",
                 "action": "Turn on two-factor authentication everywhere",
                 "why": "2FA defeats a stolen password entirely. Prefer an authenticator app "
                        "or hardware key over SMS, which is vulnerable to SIM swapping."})
    plan.append({"priority": "immediate", "icon": "🔁",
                 "action": "Stop reusing this password anywhere else",
                 "why": "One breach only becomes a catastrophe when the password is reused. "
                        "Use a free manager such as Bitwarden or KeePassXC."})

    if any("security question" in t for t in types):
        plan.append({"priority": "high", "icon": "❓",
                     "action": "Reset your security questions and answers",
                     "why": "Your real answers are public now. Use random strings as answers "
                            "and store them in your password manager."})
    if any(k in t for t in types for k in ("phone", "sim")):
        plan.append({"priority": "high", "icon": "📱",
                     "action": "Set a port-out PIN with your mobile operator",
                     "why": "Your number is exposed, which enables SIM-swap attacks that "
                            "intercept SMS OTPs and drain bank accounts."})
    if any(k in t for t in types for k in ("aadhaar", "pan", "social security",
                                           "passport", "driver", "kyc")):
        plan.append({"priority": "high", "icon": "🆔",
                     "action": "Monitor for identity theft and fraudulent loans",
                     "why": "Government identity numbers were exposed. In India, check your "
                            "CIBIL report regularly and lock your Aadhaar biometrics at "
                            "uidai.gov.in."})
    if any(k in t for t in types for k in ("card", "bank", "payment")):
        plan.append({"priority": "immediate", "icon": "💳",
                     "action": "Review statements and consider reissuing your card",
                     "why": "Payment data was exposed. Enable transaction alerts and call 1930 "
                            "immediately if you spot an unauthorised debit."})
    if any(k in t for t in types for k in ("medical", "health", "genetic")):
        plan.append({"priority": "high", "icon": "🏥",
                     "action": "Be alert for medical and insurance fraud",
                     "why": "Health data cannot be reset. Watch for claims you did not make and "
                            "for extortion attempts referencing your conditions."})

    plan.append({"priority": "ongoing", "icon": "🎣",
                 "action": "Expect highly convincing phishing",
                 "why": "Attackers quote real breached details to sound legitimate. Treat any "
                        "message that already knows your data as more suspicious, not less."})
    plan.append({"priority": "ongoing", "icon": "📧",
                 "action": "Use email aliases for new signups",
                 "why": "A unique alias per service means a future breach is contained and you "
                        "can see exactly which company leaked your address."})
    plan.append({"priority": "ongoing", "icon": "🔍",
                 "action": "Re-check periodically",
                 "why": "Add this address to the watchlist below. New breaches surface "
                        "constantly, often years after the intrusion."})
    return plan


# ================================================================= local corpus
def check_local_corpus(email: str) -> list[dict]:
    rows = query("""SELECT source, note, added_at FROM breach_records
                    WHERE identifier=? AND record_type='email'""", (email.lower(),))
    return rows


def import_corpus(text: str, source_name: str, redact_passwords: bool = True) -> dict:
    """
    Import a credential dump you legitimately possess.

    Supported line formats:
        email:password        email;password        email,password
        email                 (address only)
        CSV with an 'email' column

    Passwords are NEVER stored in plaintext. We keep only a SHA-1 prefix so the
    password analyzer can flag reuse, exactly like the k-anonymity model.
    """
    source_name = (source_name or "imported corpus").strip()[:100]
    text = text or ""
    emails, pw_hashes, bad = set(), {}, 0

    # CSV path: only when the FIRST non-comment line is a real header naming an email column
    first = next((l for l in text.splitlines() if l.strip() and not l.startswith("#")), "")
    header_cells = [c.strip().lower() for c in first.split(",")]
    if len(header_cells) > 1 and any(
            c in ("email", "e-mail", "mail", "username", "login") for c in header_cells):
        try:
            body = "\n".join(l for l in text.splitlines() if not l.startswith("#"))
            rd = csv.DictReader(io.StringIO(body))
            for row in rd:
                low = {}
                for k, v in row.items():
                    if k is None:
                        continue
                    if isinstance(v, list):          # ragged row overflow
                        v = v[0] if v else ""
                    low[str(k).strip().lower()] = str(v or "").strip()
                em = (low.get("email") or low.get("e-mail") or low.get("mail")
                      or low.get("username") or low.get("login") or "").lower()
                if EMAIL_RE.match(em):
                    emails.add(em)
                    pw = low.get("password") or low.get("pass") or low.get("passwd") or ""
                    if pw:
                        pw_hashes[em] = hashlib.sha1(pw.encode()).hexdigest().upper()
            if emails:
                return _store_corpus(emails, pw_hashes, source_name, redact_passwords)
        except (csv.Error, ValueError, AttributeError):
            emails, pw_hashes = set(), {}   # fall through to line parsing

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[:;,\t|]", line, maxsplit=1)
        em = parts[0].strip().lower()
        if not EMAIL_RE.match(em):
            bad += 1
            continue
        emails.add(em)
        if len(parts) > 1 and parts[1].strip():
            pw_hashes[em] = hashlib.sha1(parts[1].strip().encode()).hexdigest().upper()

    return _store_corpus(emails, pw_hashes, source_name, redact_passwords, bad)


def _store_corpus(emails, pw_hashes, source, redact, skipped=0) -> dict:
    now = utcnow()
    added = 0
    for em in emails:
        try:
            execute("""INSERT INTO breach_records(identifier,record_type,source,note,
                       pw_sha1_prefix,added_at) VALUES(?,?,?,?,?,?)""",
                    (em, "email", source,
                     "Password hash retained (prefix only)" if em in pw_hashes
                     else "Address only",
                     pw_hashes.get(em, "")[:5] if redact else pw_hashes.get(em, ""),
                     now))
            added += 1
        except Exception:  # noqa: BLE001 - duplicates are fine
            continue
    return {"imported": added, "unique_emails": len(emails),
            "with_passwords": len(pw_hashes), "skipped": skipped, "source": source,
            "note": "Passwords were hashed and truncated on import. No plaintext credential "
                    "is stored by this platform."}


def corpus_stats() -> dict:
    return {
        "total": scalar("SELECT COUNT(*) FROM breach_records WHERE record_type='email'"),
        "sources": query("""SELECT source, COUNT(*) AS n, MIN(added_at) AS added
                            FROM breach_records WHERE record_type='email'
                            GROUP BY source ORDER BY n DESC"""),
    }


def clear_corpus(source: str | None = None):
    if source:
        execute("DELETE FROM breach_records WHERE record_type='email' AND source=?", (source,))
    else:
        execute("DELETE FROM breach_records WHERE record_type='email'")


# ================================================================= k-anonymity
def check_password_pwned(password: str, allow_network: bool = False) -> dict:
    """
    Check a password against HIBP's free, keyless Pwned Passwords range API
    using k-anonymity.

    Privacy model: we SHA-1 the password locally, send only the first 5 hex
    characters, and match the remaining 35 characters against the returned list
    offline. The server never learns the password, nor which of the ~800
    returned hashes you were interested in.

    With allow_network=False (the default) this runs purely offline against the
    local corpus and the built-in common-password list.
    """
    if not password:
        return {"error": "empty password"}

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    # ---- always: offline checks
    from modules.password import COMMON_PASSWORDS
    offline_common = password.lower() in COMMON_PASSWORDS

    # Built-in seed list and user-imported records are tracked separately so the
    # UI never claims a hit came from the user's own corpus when it did not.
    seeded = query_one("""SELECT source FROM breach_records
                          WHERE identifier=? AND record_type='password'
                            AND source='offline-common-list'""", (password.lower(),))
    imported = query_one("""SELECT source FROM breach_records
                            WHERE identifier=? AND record_type='password'
                              AND source!='offline-common-list'""", (password.lower(),))
    # k-anonymity style prefix match against passwords from imported email dumps
    corpus_prefix = scalar("""SELECT COUNT(*) FROM breach_records
                              WHERE pw_sha1_prefix=? AND pw_sha1_prefix!=''
                                AND record_type='email'""", (prefix,))

    found_offline = offline_common or bool(seeded) or bool(imported)
    result = {
        "sha1_prefix": prefix,
        "offline_common": offline_common or bool(seeded),
        "offline_corpus": bool(imported),
        "corpus_prefix_matches": corpus_prefix,
        "network_used": False,
        "found": found_offline,
        "count": 0,
        "source": ((imported or {}).get("source") if imported
                   else "built-in common-password list" if found_offline else None),
        "privacy": (f"Only the 5 characters '{prefix}' would ever be transmitted. The full hash "
                    f"and the password itself never leave this machine."),
    }

    if not allow_network:
        result["note"] = ("Checked offline only. Enable the online k-anonymity check to query "
                          "the free Pwned Passwords range API (no API key required).")
        return result

    # ---- opt-in: k-anonymity range query
    try:
        req = urllib.request.Request(
            HIBP_RANGE_URL + prefix,
            headers={"User-Agent": USER_AGENT, "Add-Padding": "true"})
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode("utf-8", "replace")
        result["network_used"] = True
        result["hashes_returned"] = body.count("\n")
        for line in body.splitlines():
            if ":" not in line:
                continue
            suf, cnt = line.split(":", 1)
            if suf.strip().upper() == suffix:
                try:
                    n = int(cnt.strip().replace(",", ""))
                except ValueError:
                    n = 1
                if n > 0:
                    result["found"] = True
                    result["count"] = n
                    result["source"] = "HaveIBeenPwned Pwned Passwords"
                break
        result["note"] = (
            f"Queried the free Pwned Passwords range API with prefix '{prefix}'. "
            f"{result.get('hashes_returned', 0)} candidate hashes were returned and compared "
            f"locally. No API key was used and the password was never transmitted.")
    except urllib.error.URLError as e:
        result["network_error"] = f"Could not reach the Pwned Passwords API: {e.reason}"
        result["note"] = "Online check failed. The offline result above still applies."
    except Exception as e:  # noqa: BLE001
        result["network_error"] = str(e)[:160]
        result["note"] = "Online check failed. The offline result above still applies."

    if result["found"] and result["count"]:
        result["severity"] = ("critical" if result["count"] > 100000
                              else "high" if result["count"] > 1000 else "medium")
        result["advice"] = (
            f"This password has appeared {result['count']:,} times in known breaches. It is in "
            f"every cracking dictionary. Change it immediately anywhere it is used.")
    elif result["found"]:
        result["severity"] = "critical"
        result["advice"] = "This password is in a known-bad list. Change it immediately."
    else:
        result["severity"] = "low"
        result["advice"] = ("Not found in the checked sources. That is a good sign, but it is "
                            "not proof of safety — keep it unique and enable 2FA.")
    return result


# ================================================================= watchlist
def add_to_watchlist(email: str, label: str = "") -> dict:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        return {"error": "invalid email"}
    existing = query_one("SELECT id FROM breach_watchlist WHERE email=?", (email,))
    if existing:
        return {"ok": True, "already": True, "id": existing["id"]}
    r = check_email(email, use_ai=False)
    wid = execute("""INSERT INTO breach_watchlist(email,label,last_score,last_breaches,
                     last_checked,created_at) VALUES(?,?,?,?,?,?)""",
                  (email, label[:80], r["risk_score"], len(r["matched_breaches"]),
                   utcnow(), utcnow()))
    return {"ok": True, "id": wid, "score": r["risk_score"]}


def watchlist() -> list[dict]:
    rows = query("SELECT * FROM breach_watchlist ORDER BY last_score DESC, id DESC")
    for r in rows:
        r["band"] = ("critical" if r["last_score"] >= 80 else "high" if r["last_score"] >= 55
                     else "medium" if r["last_score"] >= 25 else "low")
    return rows


def recheck_watchlist() -> dict:
    rows = query("SELECT id,email FROM breach_watchlist")
    changed = []
    for r in rows:
        res = check_email(r["email"], use_ai=False)
        prev = query_one("SELECT last_score,last_breaches FROM breach_watchlist WHERE id=?",
                         (r["id"],))
        execute("""UPDATE breach_watchlist SET last_score=?,last_breaches=?,last_checked=?
                   WHERE id=?""",
                (res["risk_score"], len(res["matched_breaches"]), utcnow(), r["id"]))
        if prev and res["risk_score"] != prev["last_score"]:
            changed.append({"email": r["email"], "old": prev["last_score"],
                            "new": res["risk_score"]})
    return {"checked": len(rows), "changed": changed}


def remove_from_watchlist(wid: int):
    execute("DELETE FROM breach_watchlist WHERE id=?", (wid,))


def _log_check(email, score, n):
    masked = _mask_email(email)
    execute("""INSERT INTO breach_checks(identifier,risk_score,breach_count,created_at)
               VALUES(?,?,?,?)""", (masked, score, n, utcnow()))


def _mask_email(email: str) -> str:
    try:
        local, dom = email.split("@", 1)
    except ValueError:
        return "***"
    if len(local) <= 2:
        return "*" * len(local) + "@" + dom
    return local[0] + "*" * (len(local) - 2) + local[-1] + "@" + dom


def recent_checks(limit=20) -> list[dict]:
    return query("SELECT * FROM breach_checks ORDER BY id DESC LIMIT ?", (limit,))


# ================================================================= AI
AI_SYSTEM = (
    "You are a data-breach exposure advisor. The user has discovered their email address is "
    "linked to known breaches. Explain the real-world consequences in plain language and give "
    "a prioritised, practical recovery plan. Be calm and constructive, not alarmist. The user "
    "is likely in India, so reference helpline 1930 and cybercrime.gov.in when money or "
    "identity documents are involved."
)

SCHEMA = """{
  "summary": "3-5 sentences explaining what this exposure actually means for the user",
  "biggest_risk": "the single most dangerous consequence, in one sentence",
  "likely_attacks": ["specific attacks this user should now expect"],
  "do_today": ["concrete actions for the next hour"],
  "do_this_week": ["follow-up actions"],
  "long_term": ["habits that prevent recurrence"]
}"""


def ai_assessment(result: dict) -> dict:
    breaches = "\n".join(
        f"- {b['name']} ({b['year']}): {_big(b.get('accounts', 0))} accounts, exposed "
        f"{', '.join(b.get('data', [])[:5])}"
        for b in result["matched_breaches"][:12]) or "- none matched in the catalogue"
    exposed = ", ".join(f"{e['type']} [{e['severity']}]"
                        for e in result["exposed_data_types"][:12]) or "none"
    flags = "\n".join(f"- [{f['severity']}] {f['title']}" for f in result["findings"][:10])
    prompt = (
        f"EMAIL UNDER REVIEW: {_mask_email(result['email'])} (domain: {result['domain']})\n"
        f"Exposure risk score: {result['risk_score']}/100 ({result['verdict']})\n"
        f"Confirmed corpus matches: {len(result['corpus_hits'])}\n\n"
        f"BREACHES LINKED TO THIS ADDRESS:\n{breaches}\n\n"
        f"DATA TYPES EXPOSED ACROSS THOSE BREACHES: {exposed}\n\n"
        f"RISK FACTORS:\n{flags}\n\n"
        "Give your exposure assessment and recovery plan."
    )
    res = ollama_client.generate_json(prompt, SCHEMA, system=AI_SYSTEM,
                                      temperature=0.25, max_tokens=900)
    if not res["ok"]:
        return {"available": False, "error": res.get("error")}
    d = res["data"]

    def lst(k, n=8):
        v = d.get(k)
        return v[:n] if isinstance(v, list) else []

    return {"available": True,
            "summary": str(d.get("summary", ""))[:1500],
            "biggest_risk": str(d.get("biggest_risk", ""))[:400],
            "likely_attacks": lst("likely_attacks"),
            "do_today": lst("do_today"),
            "do_this_week": lst("do_this_week"),
            "long_term": lst("long_term"),
            "model": res.get("model")}


def explain_breach(name: str, use_ai: bool = True) -> dict:
    b = next((x for x in all_breaches() if x["name"].lower() == (name or "").lower()), None)
    if not b:
        return {"error": "not found in catalogue"}
    out = dict(b)
    out["accounts_human"] = _big(b.get("accounts", 0))
    if use_ai:
        r = ollama_client.generate(
            f"Explain the {b['name']} data breach of {b['year']} to a beginner. It affected "
            f"about {_big(b.get('accounts', 0))} accounts and exposed: "
            f"{', '.join(b.get('data', []))}. Cover: how it likely happened, why it mattered, "
            f"what victims should have done, and the lesson for everyone else. Under 220 words.",
            system="You are a security educator explaining real breaches to students.",
            temperature=0.3, max_tokens=420)
        out["ai_explanation"] = r["text"] if r["ok"] else None
    return out
