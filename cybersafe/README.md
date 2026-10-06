# 🛡️ AI Cyber Safety & Digital Forensics Platform

### *"Protect. Detect. Investigate."*

A complete cybersecurity **and** digital-forensics platform that runs entirely on your own
machine. All AI is served locally by [Ollama](https://ollama.com).

> **No API keys are required anywhere in this project.** No OpenAI, no VirusTotal, no
> subscriptions, no rate limits. Search the source — there is nothing to sign up for.
> The one optional key (HaveIBeenPwned) buys *authoritative* breach data; the platform
> gives real answers without it.

**Stack:** Python (Flask) · HTML/Jinja2 · vanilla JS · SQLite · Ollama
**Size:** ~11,000 lines of Python · 27 templates · 68 routes · **207 self-tests passing**

---

## Contents

1. [Why this exists](#why-this-exists)
2. [Quick start](#quick-start)
3. [The 10 core modules](#the-10-core-modules)
4. [Breach Checker](#-breach-checker)
5. [Daily Toolkit](#-daily-toolkit)
6. [How the AI works](#how-the-ai-works)
7. [Sample data](#sample-data)
8. [Project structure](#project-structure)
9. [Configuration](#configuration)
10. [Testing](#testing)
11. [Troubleshooting](#troubleshooting)
12. [Legal & ethics](#legal--ethics)

---

## Why this exists

| Problem | How this platform answers it |
|---|---|
| People cannot tell real messages from phishing | AI Phishing Detector — 30+ heuristics **plus 19 India-specific scam archetypes** |
| Weak and reused passwords | Entropy analyzer with realistic crack times and proper passphrase scoring |
| Risky files opened blindly | 9-engine offline static malware analyzer |
| Nobody knows their data is already leaked | Breach Checker with **live lookup** against real breach databases |
| Low cyber awareness | Learning Center — 6 quizzes, 9 labs, phishing simulator |
| Forensic tools cost lakhs (EnCase/FTK) | Free, beginner-friendly forensic modules |
| Evidence gets scattered and spoiled | Case management with hashing and chain of custody |
| Reports take hours to write | One-click professional investigation reports |

**Built for:** students, colleges, police trainees, small businesses, individuals and
cybersecurity beginners — with particular attention to the scams that actually dominate
in India.

---

## Quick start

### 1. Install Ollama (optional but recommended)

```bash
# Linux / macOS
curl -fsSL https://ollama.com/install.sh | sh
# Windows: download the installer from https://ollama.com
```

```bash
ollama serve            # leave running in its own terminal
ollama pull llama3.2    # ~2 GB, fine on an 8 GB laptop
```

### 2. Run the platform

```bash
cd cybersafe
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**

### 3. Generate the sample data

```bash
python make_samples.py     # 13 realistic, harmless artefacts in data/samples/
```

> ### ⚡ Ollama is optional
> With Ollama off, **every rule engine still works at full strength** — phishing
> heuristics, password maths, malware signatures, log detections, all forensic parsers.
> Only the AI commentary layer is disabled, and the UI says so instead of breaking.

---

## The 10 core modules

### 🛡️ 1. AI Phishing Detector

Analyses **URLs, emails and SMS/WhatsApp**.

**19 scam archetypes** — the scripts that cause most real-world losses in India. Each is
near-conclusive on its own:

| | |
|---|---|
| Parcel / customs fee | Lottery & KBC prize |
| "This is my new number" | Family impersonation opener |
| Electricity disconnection | **Digital arrest** intimidation |
| AnyDesk / screen-share request | QR-code-to-receive-money |
| Identity-document request | Task-based "like and earn" job |
| Instant-loan app | Fake armed-forces buyer |
| KYC update | OTP handover |
| Account-blocking threat | Small advance-fee lure |
| Fake pending refund | Callback-number bait |

**30+ URL heuristics** — typosquatting (Levenshtein), IDN/punycode homographs, `@`
userinfo obfuscation, brand impersonation, high-abuse TLDs, shorteners, open redirects,
double extensions, subdomain burial, domain entropy.

**Email intelligence** — From/Reply-To mismatch, display-name spoofing, SPF/DKIM/DMARC
failure parsing, anchor-text vs href mismatch, dangerous attachments.

**Precision matters as much as recall.** Whole-message exemptions mean a genuine bank SMS
saying *"never share this OTP"* is **not** flagged, and a *completed* refund is
distinguished from a *pending* one demanding action.

> Benchmarked at **14/14 scams detected, 0 false positives** on 12 legitimate messages.

### 🔐 2. Password Security Analyzer

* True **entropy in bits**, discounted for dictionary words, sequences, keyboard walks and dates
* **Correct passphrase model** — multi-word passphrases are scored on diceware maths
  (~12.9 bits/word) instead of being penalised for "containing dictionary words".
  `correct-horse-battery-staple` reports a realistic 51.6 bits.
* **Crack times** across 5 attack scenarios (throttled online → 200 billion hashes/sec GPU)
* Offline breach check, personal-info detection, live strength meter
* CSPRNG password **and passphrase** generator; compare up to 5 side by side
* **Your password is never stored, logged or transmitted.** The AI coach sees only a
  statistical profile.

### 🦠 3. Malware File Analyzer

Nine local engines. **The file is never executed.**

1. MD5/SHA-1/SHA-256 hashing + local known-bad corpus
2. Magic-byte true-type detection (catches `invoice.pdf` that is really an `.exe`)
3. Shannon entropy — packing and encryption detection
4. **31 YARA-style signatures** — ransomware, injection, C2, miners, LOLBins, UAC bypass
5. Dependency-free **PE parser** — headers, sections, RWX permissions, compile timestamps
6. **26 suspicious Windows APIs** — VirtualAllocEx, CreateRemoteThread, etc.
7. Container inspection — ZIP/Office macros, APK, Zip-Slip, zip bombs
8. Script deobfuscation — Base64 payload decoding, IEX/eval chains, hex blobs
9. Embedded IOC extraction

### 📁 4. Digital Evidence Management

* Auto-numbered cases (`CASE-2026-0001`)
* Evidence hashed **at the moment of acquisition** — the legal baseline
* Full **chain of custody**: who, what, when, integrity status for every action
* On-demand re-verification — a modified file is instantly flagged `MISMATCH`
* Tagging, search, IOC registry, investigation timeline
* Write-once vault at `data/evidence/<case-number>/`

### 🌐 5. Browser Forensics

* **Chrome/Edge/Brave** — `History`, `Cookies`, `Login Data`
* **Firefox** — `places.sqlite`, `cookies.sqlite`, bookmarks
* Generic CSV/JSON exports including Google Takeout
* Correct epoch handling (WebKit 1601 µs vs Firefox 1970 µs)
* 10 risk categories, phishing scoring of visited URLs, risky-download correlation,
  hour-of-day activity chart
* 🔒 **Saved passwords and cookie values are never decrypted** — metadata only

### 🧠 6. Memory Forensics

Works on **any** RAM dump with zero setup — no symbol profiles needed.

* Process carving with **masquerade detection** (`svch0st.exe`, `lsasss.exe`)
* Network artefacts with C2 port intelligence (4444, 1337, 50050, 6667, 9050…)
* Command-line and PowerShell reconstruction
* Credential material — NTLM pairs, bcrypt, JWTs, private keys, cloud tokens (redacted)
* Injection chains (VirtualAllocEx → WriteProcessMemory → CreateRemoteThread)
* Persistence — Run keys, WMI, scheduled tasks, cron, systemd, LD_PRELOAD
* Family signatures — Cobalt Strike, Meterpreter, Mimikatz, ransomware, miners

### 📜 7. Log Analysis

**Auto-detects** the format, then hunts for intrusions.

| Format | Detections |
|---|---|
| Windows Event Log (EVTX + text/CSV) | Brute force, password spraying, 1102 log clearing, new admins, service installs, RDP from public IPs |
| Linux auth.log / syslog | SSH brute force → success correlation, user enumeration, sudo abuse, persistence, anti-forensics |
| Apache / Nginx | SQLi, XSS, LFI, RCE, Log4Shell, web shells, scanners, exfiltration, "attack returned HTTP 200" |
| Firewall (iptables/UFW/pfSense) | Port scans, sustained blocks, risky-service probing |

Includes a **51-entry Windows Event ID reference** with AI explanations on demand.

### 🤖 8. AI Cyber Assistant

* **RAG-lite** — a **29-article** offline knowledge base retrieved with TF-IDF and injected
  into the prompt, so even a 3B model gives grounded answers
* **Live streaming** via Server-Sent Events, with source citations
* **Graceful degradation** — with Ollama off it answers from the knowledge base directly

### 📚 9. Cyber Learning Center

* **6 quizzes / 34 questions** with a full explanation for every answer
* **9 hands-on labs**, beginner → advanced, using the platform's own tools
* **Phishing simulator** — 6 realistic messages to classify, every clue revealed
* **3 guided learning paths**, progress tracking and badges
* **AI study buddy** — generates fresh quizzes and explains any topic

### 📊 10. Dashboard

Threats detected, active investigations, evidence count, integrity failures, overall risk
gauge, module activity, learning progress and prioritised security recommendations.

---

## 💧 Breach Checker

Answers the real question: **has THIS email address been breached?**

### How the answer is produced

Live queries against real breach databases, merged:

| Source | API key | What it gives |
|---|---|---|
| **HaveIBeenPwned** official API | Your own (~$3.95/mo) | Authoritative per-email breach list |
| **XposedOrNot** | ✅ None | Real per-email breach list |
| **LeakCheck** public API | ✅ None | Leaked record count + source names |
| **HIBP breach encyclopaedia** | ✅ None | **1,039 breaches / 17.8B accounts**, cached locally |

**You get real per-email answers with no API key at all.** Add your own HIBP key in
*Breach Checker → Settings* and it is used automatically.

### Decisive verdicts

* **🚨 BREACHED** — found in N specific breaches, each with year, account count, exact data
  classes and the authoritative HIBP description
* **✅ NOT FOUND** — no responding database has a record, shown with a **confidence level**
  (high / medium / low) based on how many sources answered
* **❓ COULD NOT VERIFY** — nothing reachable, so the offline estimate is shown and
  explicitly labelled an estimate, never a verdict

A positive hit is conclusive. A *negative* is only as strong as the coverage behind it, so
the UI states plainly whether one free database answered or HIBP's authoritative one did.

### Also included

* **Pwned Passwords k-anonymity** — HIBP's free keyless endpoint. Only 5 of the 40 SHA-1
  hash characters leave your machine. Verified: `123456` → 210,461,208 real hits.
* **Local corpus import** — exact matching against dumps you lawfully possess. Passwords
  are SHA-1 hashed and truncated to 5 chars on import; no plaintext is ever stored.
* **Watchlist** — monitor several addresses and re-check over time
* **Catalogue browser** — search all 1,039 breaches by company, data class
  (`Passwords`, `Social security numbers`) or flag (`stealer log`, `sensitive`)
* **AI recovery plan** — tailored to what actually leaked

### Privacy

The address goes only to the breach databases you enabled, and is stored locally **masked**
(`r***l@gmail.com`). Untick *Live lookup* to stay fully offline. Every other module remains
100% offline regardless.

---

## 🧰 Daily Toolkit

Seven practical utilities beyond the core modules.

| Tool | What it does |
|---|---|
| **🔏 PII Scanner & Redactor** | **22 patterns** — Aadhaar, PAN, Luhn-validated cards, UPI, IFSC, phones, API keys, passwords, JWTs. Produces a **safe redacted version** to share. |
| **🚩 Scam Detector** | Tuned for Indian fraud: fake jobs, "like & earn", investment schemes, lottery, parcel/customs, **digital arrest**. |
| **📷 EXIF Cleaner** | Shows GPS, timestamps and device model hidden in photos — and **strips them**. |
| **📱 QR Safety Checker** | Decodes UPI payment requests, Wi-Fi joins and URLs *before* you act. Warns on pre-filled amounts. |
| **🔤 Encoder/Decoder** | **17 operations** — Base64, hex, URL, binary, HTML, ROT13, JWT decode, 4 hash algorithms. |
| **#️⃣ Hash Tools** | Text hashing and byte-for-byte file comparison. |
| **✅ Security Checkup** | **16 weighted questions** → graded score with a prioritised fix list. |

Plus 🇮🇳 India-specific incident guidance throughout — helpline **1930**,
cybercrime.gov.in, TRAI 1909.

---

## How the AI works

```
Your input
    │
    ├─→ Deterministic rule engine  ──→ explainable score + findings   (always runs)
    │
    └─→ Local Ollama LLM           ──→ semantic judgement + narrative (optional)
                 │
                 └─→ Fused score, with rule findings taking precedence
```

* **Rules are ground truth.** The AI adjusts within a band; it can never override a
  critical deterministic finding.
* **Strict JSON mode** with a defensive parser that repairs trailing commas and fence
  artifacts from small models.
* **Never fails closed.** Every AI call has a rule-based fallback.
* **Nothing leaves your machine** — the only AI traffic is to `localhost:11434`.

---

## Sample data

`python make_samples.py` generates 13 harmless artefacts:

| File | Module | Demonstrates |
|---|---|---|
| `auth.log` | Log Analysis | SSH brute force → success → backdoor account → history wiped |
| `access.log` | Log Analysis | SQLi, scanning, `.env` leak, web shell, 46 MB exfiltration |
| `security_events.txt` | Log Analysis | Windows RDP brute force, new admin, Defender off, log cleared |
| `firewall.log` | Log Analysis | 60-port scan, RDP and SMB probing |
| `browser_history.db` | Browser Forensics | Crack-site search → keygen download (the infection moment) |
| `places.sqlite` | Browser Forensics | Firefox format with a typosquat and .onion visit |
| `sample_memory.raw` | Memory Forensics | Masqueraded processes, C2 on :4444, Mimikatz, ransom note |
| `eicar.txt` | Malware Analyzer | Standard harmless AV test file → known-hash detection |
| `suspicious.ps1` | Malware Analyzer | Obfuscated PowerShell (**inert** — dangerous lines commented out) |
| `phishing_email.txt` | Phishing Detector | Spoofed bank email, SPF/DKIM/DMARC all failing |
| `pii_document.txt` | Daily Toolkit | 20 kinds of PII for the redaction tool |
| `scam_message.txt` | Daily Toolkit | Fake job offer with advance-fee fraud |
| `breach_corpus_sample.txt` | Breach Checker | Synthetic credential dump for corpus import |

---

## Project structure

```
cybersafe/
├── app.py                     Flask app — 68 routes
├── config.py                  Central config (no secrets)
├── make_samples.py            Sample artefact generator
├── selftest.py                207 self-tests
├── requirements.txt
│
├── core/
│   ├── database.py            SQLite schema + helpers (auto-initialising, migrating)
│   ├── ollama_client.py       Local AI client (generate / chat / stream / JSON mode)
│   └── utils.py               Hashing, entropy, IOC extraction, magic bytes, time
│
├── modules/
│   ├── phishing.py            Module 1  — URL/email/SMS + 19 scam archetypes
│   ├── password.py            Module 2  — entropy, crack time, passphrase model
│   ├── malware.py             Module 3  — 9 static engines, PE parser
│   ├── evidence.py            Module 4  — cases + chain of custody
│   ├── browser_forensics.py   Module 5
│   ├── memory_forensics.py    Module 6
│   ├── log_analysis.py        Module 7
│   ├── assistant.py           Module 8  — RAG knowledge base
│   ├── learning.py            Module 9  — quizzes, labs, simulator
│   ├── breach.py              Module 11 — breach checker orchestration
│   ├── breach_providers.py              — live lookup: HIBP / XposedOrNot / LeakCheck
│   ├── reports.py             Report generator (HTML + Markdown)
│   └── toolkit.py             Daily Toolkit
│
├── templates/                 27 Jinja2 templates + shared macros
├── static/css/style.css       Dark cybersecurity design system
├── static/js/app.js           Tabs, markdown renderer, SSE streaming, mobile nav
└── data/
    ├── knowledge/             Breach catalogues (curated + synced HIBP)
    ├── evidence/              Case evidence vault
    ├── reports/               Generated reports
    └── samples/               Demo artefacts
```

---

## Configuration

Everything is optional — defaults work out of the box.

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `llama3.2` | Model to use |
| `MAX_UPLOAD_MB` | `512` | Upload size limit |
| `INVESTIGATOR` | `analyst` | Default chain-of-custody actor |
| `HIBP_API_KEY` | *(empty)* | Optional HaveIBeenPwned key for authoritative lookup |
| `BREACH_TIMEOUT` | `20` | Seconds to wait for each breach database |
| `PORT` / `HOST` | `5000` / `127.0.0.1` | Web server binding |
| `DEBUG` | `0` | Flask debug mode |

```bash
# Example: bigger uploads with a stronger model
MAX_UPLOAD_MB=2048 OLLAMA_MODEL=llama3.1:8b python app.py
```

Model and host can also be changed live from the **Settings** page.

| Model | RAM | Notes |
|---|---|---|
| `llama3.2` (3B) | ~8 GB | Default. Fast, runs on most laptops. |
| `llama3.1:8b` | ~16 GB | Better reasoning and JSON reliability. |
| `qwen2.5:7b` | ~16 GB | Excellent structured output. |

---

## Testing

```bash
python selftest.py
```

Runs **207 checks** offline, with no Ollama required:

| Area | Checks |
|---|---|
| Core utilities & AI client | 20 |
| Phishing Detector | 15 |
| Password Analyzer | 16 |
| Malware Analyzer | 12 |
| Evidence & Chain of Custody | 12 |
| Browser Forensics | 7 |
| Memory Forensics | 8 |
| Log Analysis | 15 |
| AI Assistant | 6 |
| Learning Center | 17 |
| Breach Checker | 52 |
| Daily Toolkit | 21 |
| Template form integrity | 6 |

Every engine is tested against known-good **and** known-bad inputs, so false-positive rates
are verified too — not just detection. The suite includes regression tests for bugs already
fixed (duplicate form field names, passphrase scoring, breach-name deduplication).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Pill shows "AI Offline" | Run `ollama serve`, confirm `ollama list` shows a model, check the host in Settings |
| AI responses are slow | Normal for a 3B model on CPU (10–40 s). Untick "Use local AI" for instant rule-only results |
| "File too large" | `MAX_UPLOAD_MB=2048 python app.py` |
| Browser artefact will not parse | Close the browser completely, then **copy** the file — browsers lock their SQLite DBs |
| "unparseable_json" from AI | Small models occasionally emit malformed JSON. Re-run, or switch to `llama3.1:8b` |
| Breach lookup says "could not verify" | Check your internet connection, or untick *Live lookup* to use the offline catalogue |
| Breach catalogue empty | Breach Checker → Settings → **Sync from HaveIBeenPwned** (free, no key) |
| Start completely fresh | Stop the app, delete `data/cybersafe.db`, restart |
| Port 5000 in use | `PORT=8080 python app.py` |

---

## Legal & ethics

> ⚠️ **Only examine systems and data you own or are formally authorised to examine.**
> Unauthorised access to a computer or its data is a criminal offence under the
> Information Technology Act, 2000 (India) and equivalent laws elsewhere.

This platform is **deliberately defensive**:

* No exploit code, no attack tooling, no malware generation
* Malware analysis is **static only** — samples are never executed
* Saved passwords and cookie values are never decrypted
* The AI system prompt refuses to produce offensive tooling

For evidence intended for court, findings should be reproduced and corroborated by a
certified forensic examiner using validated tooling.

### 🇮🇳 Emergency contacts (India)

| Purpose | Contact |
|---|---|
| **Cyber financial fraud — call immediately** | **1930** |
| National Cyber Crime Reporting Portal | cybercrime.gov.in |
| Spam SMS / calls (TRAI) | 1909 |
| Police emergency | 112 |
| Free ransomware decryptors | nomoreransom.org |

---

## Privacy guarantee

| | |
|---|---|
| 🚫 | **Zero required API keys** — the one optional key (HIBP) only upgrades breach results |
| 🏠 | AI runs locally via Ollama; files, passwords and evidence never leave your machine |
| 📡 | No telemetry, no analytics, no phone-home |
| 🌐 | The only outbound traffic is breach-database lookups you explicitly enable |
| 💰 | Free — no subscriptions, trials or rate limits |
| 🔓 | Your data lives in `data/` — copy it, move it, delete it |

---

*Built with Python and HTML. Powered entirely by local AI.*
**Protect. Detect. Investigate.**
