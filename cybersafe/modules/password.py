"""
Module 2 -- Password Security Analyzer.

Offline-only maths (entropy, crack-time, pattern detection) + optional AI coaching.
Passwords are NEVER stored, logged, or transmitted anywhere.
"""
from __future__ import annotations

import hashlib
import math
import re
import secrets
import string

from core import ollama_client
from core.database import query_one
from core.utils import clamp, human_duration, shannon_entropy

# Attacker capability assumptions (hashes/second)
ATTACK_SPEEDS = {
    "Online throttled (100/s)": 1e2,
    "Online unthrottled (10k/s)": 1e4,
    "Offline bcrypt (20k/s)": 2e4,
    "Offline SHA-256 GPU (10B/s)": 1e10,
    "Offline MD5 GPU rig (200B/s)": 2e11,
}

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "shadow", "master", "696969", "mustang", "666666",
    "qwertyuiop", "123321", "1234567890", "superman", "asdfghjkl", "trustno1",
    "iloveyou", "sunshine", "princess", "admin", "welcome", "login", "passw0rd",
    "starwars", "whatever", "hello", "freedom", "computer", "internet", "samsung",
    "admin123", "root", "toor", "pass", "test", "guest", "india123", "sachin",
    "krishna", "ganesh", "bharat", "delhi123", "mumbai123", "chennai", "password1",
    "password123", "qwerty123", "1q2w3e4r", "zaq12wsx", "asdf1234", "p@ssw0rd",
}

LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o",
                      "$": "s", "5": "s", "7": "t", "+": "t", "8": "b", "9": "g"})

DICT_WORDS = {
    "love", "money", "secret", "god", "sex", "hello", "summer", "winter", "spring",
    "autumn", "january", "february", "march", "april", "june", "july", "august",
    "september", "october", "november", "december", "monday", "friday", "sunday",
    "india", "delhi", "mumbai", "chennai", "kolkata", "bangalore", "hyderabad",
    "pune", "jaipur", "school", "college", "office", "family", "mother", "father",
    "brother", "sister", "friend", "cricket", "football", "hockey", "tennis",
    "music", "movie", "google", "facebook", "instagram", "youtube", "amazon",
    "apple", "samsung", "nokia", "honda", "toyota", "ferrari", "batman", "superman",
    "spiderman", "ironman", "avengers", "pokemon", "naruto", "dragon", "tiger",
    "lion", "eagle", "shark", "panther", "phoenix", "ninja", "warrior", "hunter",
    "gamer", "player", "master", "legend", "king", "queen", "prince", "princess",
    "angel", "devil", "ghost", "shadow", "storm", "thunder", "lightning", "fire",
    "water", "earth", "wind", "star", "moon", "sun", "sky", "ocean", "river",
    "mountain", "forest", "flower", "rose", "lily", "orchid", "jasmine",
    "rahul", "amit", "priya", "neha", "raj", "kumar", "singh", "sharma", "patel",
    "welcome", "computer", "keyboard", "internet", "network", "system", "server",
    "password", "passwd", "admin", "administrator", "letmein", "qwerty", "login",
    "root", "user", "guest", "test", "default", "secret", "access", "changeme",
    "trustno", "iloveyou", "sunshine", "shadow", "michael", "jennifer", "hunter",
}

KEYBOARD_ROWS = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./",
                 "~!@#$%^&*()_+", "QWERTYUIOP{}|", "ASDFGHJKL:\"", "ZXCVBNM<>?"]

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789",
             "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def _charset_size(pw: str) -> tuple[int, list[str]]:
    size, sets = 0, []
    if re.search(r"[a-z]", pw):
        size += 26; sets.append("lowercase")
    if re.search(r"[A-Z]", pw):
        size += 26; sets.append("uppercase")
    if re.search(r"\d", pw):
        size += 10; sets.append("digits")
    specials = set(re.findall(r"[^\w]", pw))
    if specials:
        size += 33; sets.append("symbols")
    if re.search(r"_", pw) and "symbols" not in sets:
        size += 1; sets.append("underscore")
    if any(ord(c) > 127 for c in pw):
        size += 100; sets.append("unicode")
    return max(size, 1), sets


def _has_sequence(pw: str, minlen=3) -> list[str]:
    hits, low = [], pw.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - minlen + 1):
            frag = seq[i:i + minlen]
            if frag in low:
                hits.append(frag)
            if frag[::-1] in low:
                hits.append(frag[::-1])
    return sorted(set(hits))[:6]


def _keyboard_walk(pw: str) -> list[str]:
    hits, low = [], pw.lower()
    for row in KEYBOARD_ROWS:
        r = row.lower()
        for i in range(len(r) - 2):
            frag = r[i:i + 3]
            if frag in low:
                hits.append(frag)
    return sorted(set(hits))[:6]


def _repeats(pw: str) -> list[str]:
    out = [m.group(0) for m in re.finditer(r"(.)\1{2,}", pw)]
    for m in re.finditer(r"(.{2,4})\1{1,}", pw):
        out.append(m.group(0))
    return sorted(set(out))[:6]


def _dictionary_hits(pw: str) -> list[str]:
    base = pw.lower().translate(LEET)
    hits = [w for w in DICT_WORDS if len(w) >= 4 and w in base]
    return sorted(hits, key=len, reverse=True)[:6]


def _dates(pw: str) -> list[str]:
    out = []
    out += re.findall(r"\b(19[5-9]\d|20[0-4]\d)\b", pw)
    out += re.findall(r"\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(\d{2,4})\b", pw)
    flat = []
    for o in out:
        flat.append("".join(o) if isinstance(o, tuple) else o)
    return sorted(set(flat))[:4]


PASSPHRASE_RE = re.compile(r"^[A-Za-z]{2,}(?:[-_. +][A-Za-z0-9]{2,}){2,}$")


def is_passphrase(pw: str) -> tuple[bool, int]:
    """
    Detect a multi-word passphrase such as 'copper-violin-42-monsoon-Tide'.

    Passphrases are the single strongest memorable strategy, and their entropy
    comes from the NUMBER OF WORDS drawn from a large vocabulary -- not from the
    words being obscure. Penalising them for "containing dictionary words" is
    exactly backwards, so they are scored on a separate model.
    """
    if not PASSPHRASE_RE.match(pw or ""):
        return False, 0
    words = [w for w in re.split(r"[-_. +]", pw) if w]
    alpha = [w for w in words if w.isalpha() and len(w) >= 3]
    return (len(alpha) >= 3), len(words)


def passphrase_entropy(pw: str, n_words: int) -> float:
    """
    Diceware-style estimate: each word contributes log2(vocabulary).
    We assume a conservative 7,776-word attacker vocabulary (~12.9 bits/word),
    then add the keyspace contribution of digits, symbols and capitalisation.
    """
    words = [w for w in re.split(r"[-_. +]", pw) if w]
    bits = 0.0
    for w in words:
        if w.isalpha():
            bits += 12.9                      # one dictionary word
            if not w.islower():
                bits += 1.0                   # unpredictable capitalisation
        elif w.isdigit():
            bits += len(w) * 3.32             # digits
        else:
            bits += len(w) * 4.5              # mixed token
    seps = len(set(re.findall(r"[-_. +]", pw)))
    bits += max(0, seps - 1) * 2
    return round(bits, 2)


def entropy_bits(pw: str) -> float:
    """
    Effective entropy in bits.

    Starts from the theoretical keyspace entropy (length x log2(charset)) and
    discounts it for observed structure: repeated characters, dictionary words,
    sequences and keyboard walks. We deliberately do NOT clamp to the string's
    own Shannon self-entropy, because that measure is bounded by log2(length)
    and therefore badly under-rates short random passwords.
    """
    if not pw:
        return 0.0
    size, _ = _charset_size(pw)
    theoretical = len(pw) * math.log2(size)

    # 1. character-diversity discount (repeats reduce real randomness)
    uniq = len(set(pw)) / len(pw)
    effective = theoretical * (0.70 + 0.30 * uniq)

    # 2. structural discounts - each predictable chunk costs real bits
    penalty_bits = 0.0
    for word in _dictionary_hits(pw):
        # a dictionary word of length n costs ~log2(size^n) but is worth ~11 bits
        penalty_bits += max(0.0, len(word) * math.log2(size) - 11)
    for frag in _has_sequence(pw) + _keyboard_walk(pw):
        penalty_bits += max(0.0, len(frag) * math.log2(size) - 5)
    for rep in _repeats(pw):
        penalty_bits += max(0.0, (len(rep) - 1) * math.log2(size) - 2)
    for d in _dates(pw):
        penalty_bits += max(0.0, len(d) * math.log2(size) - 9)

    effective = max(effective - penalty_bits, math.log2(max(len(set(pw)), 2)))
    return round(min(effective, theoretical), 2)


def crack_times(bits: float) -> dict:
    guesses = 2 ** min(bits, 200) / 2
    return {name: human_duration(guesses / speed) for name, speed in ATTACK_SPEEDS.items()}


def breach_check(pw: str) -> dict:
    """
    Fully OFFLINE breach check. We never send the password anywhere.
    We hash it locally and compare against a local corpus of known-bad values.
    """
    low = pw.lower()
    row = query_one("""SELECT source, note FROM breach_records
                       WHERE identifier=? AND record_type='password'""", (low,))
    in_common = low in COMMON_PASSWORDS
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    return {
        "found": bool(row) or in_common,
        "source": (row or {}).get("source", "built-in common list" if in_common else None),
        "sha1_prefix": sha1[:5],
        "note": "Checked entirely offline against a local corpus. Your password never left this machine.",
    }


def analyze(pw: str, use_ai: bool = True, context: str = "") -> dict:
    if pw is None:
        pw = ""
    issues, bonuses = [], []
    L = len(pw)

    if L == 0:
        return {"error": "empty"}

    # ---------- structural findings
    if L < 8:
        issues.append(("critical", f"Only {L} characters",
                       "Under 8 characters can be brute-forced almost instantly.", 35))
    elif L < 12:
        issues.append(("high", f"{L} characters is short",
                       "12+ characters is the modern minimum; 16+ is recommended.", 18))
    elif L < 16:
        bonuses.append(("info", f"{L} characters - decent length", "16+ would be stronger.", 0))
    else:
        bonuses.append(("good", f"{L} characters - excellent length",
                        "Length is the single biggest factor in resisting cracking.", 0))

    size, sets = _charset_size(pw)
    missing = {"lowercase", "uppercase", "digits", "symbols"} - set(sets)
    if len(sets) <= 1:
        issues.append(("critical", "Single character type only",
                       f"Uses only {', '.join(sets) or 'one set'} - drastically shrinks the keyspace.", 25))
    elif missing:
        issues.append(("medium", "Limited character variety",
                       "Missing: " + ", ".join(sorted(missing)), 8 * len(missing)))
    else:
        bonuses.append(("good", "All four character classes present", "Maximises keyspace.", 0))

    low = pw.lower()
    if low in COMMON_PASSWORDS:
        issues.append(("critical", "Found in the top-common password list",
                       "This is tried in the first second of any attack.", 60))

    b = breach_check(pw)
    if b["found"] and low not in COMMON_PASSWORDS:
        issues.append(("critical", "Matches a known-breached value",
                       f"Source: {b['source']}. Credential-stuffing bots already have it.", 50))

    is_phrase, word_count = is_passphrase(pw)

    dic = _dictionary_hits(pw)
    if dic and not is_phrase:
        issues.append(("high", "Contains dictionary word(s)",
                       "Found: " + ", ".join(dic) + " (leetspeak is also decoded by crackers).", 20))
    elif is_phrase:
        bonuses.append(("good", f"Passphrase with {word_count} components",
                        "Multi-word passphrases are the strongest memorable strategy. Their "
                        "entropy comes from word count, so dictionary words are not a weakness "
                        "here.", 0))

    seq = _has_sequence(pw)
    if seq:
        issues.append(("high", "Sequential characters", "Found: " + ", ".join(seq), 16))

    kb = _keyboard_walk(pw)
    if kb:
        issues.append(("high", "Keyboard pattern", "Found: " + ", ".join(kb), 16))

    rep = _repeats(pw)
    if rep:
        issues.append(("medium", "Repeated characters/blocks", "Found: " + ", ".join(rep), 12))

    dts = _dates(pw)
    if dts:
        issues.append(("high", "Looks like a date/year",
                       "Found: " + ", ".join(dts) + " - birth years are guessed early.", 15))

    if re.match(r"^[A-Z][a-z]+\d{1,4}[!@#]?$", pw):
        issues.append(("high", "Classic 'Word + numbers + symbol' template",
                       "Capital-word-digits is the most predictable human pattern.", 20))

    if re.match(r"^\d+$", pw):
        issues.append(("critical", "Digits only",
                       "A 10-digit numeric PIN falls in seconds on a GPU.", 30))
    if re.match(r"^[a-z]+$", pw):
        issues.append(("high", "Lowercase letters only", "No case variation or symbols.", 18))

    if context:
        for token in re.split(r"[\s@._\-]+", context.lower()):
            if len(token) >= 3 and token in low:
                issues.append(("critical", "Contains personal information",
                               f"'{token}' appears in your password and is publicly guessable.", 30))
                break

    uniq_ratio = len(set(pw)) / L
    if uniq_ratio < 0.5 and not is_phrase:
        issues.append(("medium", "Low character diversity",
                       f"Only {len(set(pw))} unique characters out of {L}.", 10))

    # ---------- scoring
    # Entropy maps to a base score on a curve: 28 bits -> ~25, 60 bits -> ~68,
    # 80 bits -> ~88, 100+ bits -> 100. This matches real cracking economics.
    bits = passphrase_entropy(pw, word_count) if is_phrase else entropy_bits(pw)
    if bits >= 100:
        base = 100
    elif bits >= 75:
        base = 85 + (bits - 75) * 0.6
    elif bits >= 60:
        base = 68 + (bits - 60) * 1.13
    elif bits >= 40:
        base = 45 + (bits - 40) * 1.15
    elif bits >= 28:
        base = 25 + (bits - 28) * 1.67
    else:
        base = bits * 0.89
    base = clamp(int(base))

    penalty = sum(i[3] for i in issues)
    score = clamp(base - penalty + (6 if len(sets) == 4 else 0) + (8 if L >= 16 else 0))

    if score >= 85:
        rating, color = "Excellent", "excellent"
    elif score >= 70:
        rating, color = "Strong", "strong"
    elif score >= 50:
        rating, color = "Moderate", "moderate"
    elif score >= 30:
        rating, color = "Weak", "weak"
    else:
        rating, color = "Very Weak", "critical"

    times = crack_times(bits)
    all_findings = [{"severity": s, "title": t, "detail": d, "points": p}
                    for s, t, d, p in issues] + \
                   [{"severity": s, "title": t, "detail": d, "points": p}
                    for s, t, d, p in bonuses]

    result = {
        "length": L,
        "score": score,
        "rating": rating,
        "color": color,
        "entropy_bits": bits,
        "charset_size": size,
        "charsets": sets,
        "unique_chars": len(set(pw)),
        "findings": sorted(all_findings, key=lambda f: -f["points"]),
        "crack_times": times,
        "headline_crack_time": times["Offline SHA-256 GPU (10B/s)"],
        "breach": b,
        "suggestions": build_suggestions(pw, score),
        "masked": pw[0] + "•" * max(L - 2, 0) + pw[-1] if L > 2 else "•" * L,
    }

    if use_ai and score < 85:
        result["ai_advice"] = ai_coach(result)
    return result


def build_suggestions(pw: str, score: int) -> list[str]:
    s = []
    if len(pw) < 16:
        s.append(f"Extend to at least 16 characters - going from {len(pw)} to 16 multiplies "
                 "the attacker's work by billions.")
    if not re.search(r"[A-Z]", pw):
        s.append("Add uppercase letters in unpredictable positions (not just the first).")
    if not re.search(r"\d", pw):
        s.append("Add digits, but never as a trailing '123' or a birth year.")
    if not re.search(r"[^\w]", pw):
        s.append("Add symbols such as ~ ^ % & to expand the keyspace.")
    s.append("Best practice: use a 4-6 word passphrase, e.g. 'copper-violin-42-monsoon-Tide'. "
             "Easy to remember, brutal to crack.")
    s.append("Use a password manager (Bitwarden / KeePassXC are free and open-source) so every "
             "site gets a unique random password.")
    s.append("Turn on two-factor authentication - it defeats stolen passwords entirely.")
    s.append("Never reuse this password on another site; one breach then compromises everything.")
    return s


def generate_password(length=20, use_symbols=True, use_digits=True,
                      exclude_ambiguous=True) -> str:
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.?~"
    if exclude_ambiguous:
        for ch in "il1Lo0O":
            lower = lower.replace(ch, ""); upper = upper.replace(ch, "")
            digits = digits.replace(ch, "")
    pool = lower + upper
    required = [secrets.choice(lower), secrets.choice(upper)]
    if use_digits:
        pool += digits; required.append(secrets.choice(digits))
    if use_symbols:
        pool += symbols; required.append(secrets.choice(symbols))
    length = max(length, len(required) + 4)
    rest = [secrets.choice(pool) for _ in range(length - len(required))]
    chars = required + rest
    # Fisher-Yates with CSPRNG
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


WORDLIST = """apple amber anchor arrow autumn basil beacon birch bison blossom bronze
canyon cedar cinder clover cobalt copper coral cosmos crimson crystal dahlia delta
denim dust ember falcon fern flint forest garnet ginger glacier granite harbor hazel
heron indigo ivory jasper jungle kernel lantern lagoon lichen lotus lunar maple marble
meadow monsoon nectar nimbus oasis obsidian onyx opal orbit otter pepper phoenix pine
prairie quartz quiver raven reef ripple river rustic saffron sage sapphire scarlet
shadow silver slate solar spruce summit tandem tempest thistle thunder tidal timber
topaz tundra umber valley velvet violet walnut willow winter zephyr zenith""".split()


def generate_passphrase(words=5, separator="-", capitalize=True, add_number=True) -> str:
    picks = [secrets.choice(WORDLIST) for _ in range(max(3, words))]
    if capitalize:
        idx = secrets.randbelow(len(picks))
        picks[idx] = picks[idx].capitalize()
    phrase = separator.join(picks)
    if add_number:
        phrase += separator + str(secrets.randbelow(90) + 10)
    return phrase


AI_SYSTEM = ("You are a password-security coach. Give short, practical, encouraging advice. "
             "Never ask for or repeat the actual password. Focus on habits and memorable techniques.")


def ai_coach(result: dict) -> dict:
    """AI never sees the password itself - only its statistical profile."""
    profile = (
        f"Length: {result['length']}\n"
        f"Entropy: {result['entropy_bits']} bits\n"
        f"Score: {result['score']}/100 ({result['rating']})\n"
        f"Character sets used: {', '.join(result['charsets'])}\n"
        f"Weaknesses detected: " +
        ("; ".join(f['title'] for f in result['findings'] if f['points'] > 0) or "none") + "\n"
        f"Cracks in (GPU offline): {result['headline_crack_time']}"
    )
    prompt = (
        "A user's password has this profile (the password itself is withheld for privacy):\n\n"
        f"{profile}\n\n"
        "Write: (1) a one-sentence verdict, (2) the single most impactful fix, "
        "(3) a memorable technique to build a stronger password they will actually remember. "
        "Keep it under 130 words, friendly and non-technical."
    )
    res = ollama_client.generate(prompt, system=AI_SYSTEM, temperature=0.4, max_tokens=320)
    if not res["ok"]:
        return {"available": False}
    return {"available": True, "text": res["text"], "model": res.get("model")}


def compare_passwords(pw_list: list[str]) -> list[dict]:
    out = []
    for p in pw_list[:10]:
        if not p:
            continue
        r = analyze(p, use_ai=False)
        out.append({"masked": r["masked"], "score": r["score"], "rating": r["rating"],
                    "bits": r["entropy_bits"], "crack": r["headline_crack_time"]})
    return sorted(out, key=lambda x: -x["score"])
