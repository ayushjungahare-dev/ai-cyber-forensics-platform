"""SQLite persistence layer. Zero-config, single file, WAL mode."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager

from config import Config
from core.utils import utcnow

_local = threading.local()

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    investigator TEXT,
    status TEXT DEFAULT 'open',           -- open | in_progress | closed
    priority TEXT DEFAULT 'medium',       -- low | medium | high | critical
    incident_type TEXT,
    created_at TEXT, updated_at TEXT, closed_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    original_filename TEXT,
    stored_path TEXT,
    evidence_type TEXT,                   -- image|document|video|log|browser|memory|other
    description TEXT,
    source TEXT,
    collected_by TEXT,
    collected_at TEXT,
    size INTEGER,
    md5 TEXT, sha1 TEXT, sha256 TEXT,
    verified INTEGER DEFAULT 1,
    last_verified_at TEXT,
    tags TEXT,
    meta TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
    action TEXT,                          -- acquired|accessed|analyzed|transferred|verified|exported
    actor TEXT,
    notes TEXT,
    integrity TEXT,                       -- intact|mismatch|unknown
    ts TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    module TEXT NOT NULL,                 -- phishing|password|malware|browser|memory|logs|assistant
    target TEXT,
    verdict TEXT,
    risk_score INTEGER DEFAULT 0,
    summary TEXT,
    details TEXT,                         -- JSON blob
    ai_used INTEGER DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    role TEXT,
    content TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS quiz_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    topic TEXT,
    score INTEGER, total INTEGER,
    detail TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS lab_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    lab_id TEXT,
    status TEXT,                          -- started|completed
    score INTEGER DEFAULT 0,
    created_at TEXT,
    UNIQUE(user, lab_id)
);

CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    ts TEXT,
    source TEXT,
    event TEXT,
    severity TEXT DEFAULT 'info',
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    ioc_type TEXT,
    value TEXT,
    source_module TEXT,
    confidence INTEGER DEFAULT 50,
    first_seen TEXT,
    UNIQUE(case_id, ioc_type, value)
);

CREATE TABLE IF NOT EXISTS breach_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT,
    record_type TEXT DEFAULT 'password',   -- password | email
    source TEXT, note TEXT,
    pw_sha1_prefix TEXT DEFAULT '',
    added_at TEXT,
    UNIQUE(identifier, record_type, source)
);

CREATE TABLE IF NOT EXISTS breach_watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    label TEXT,
    last_score INTEGER DEFAULT 0,
    last_breaches INTEGER DEFAULT 0,
    last_checked TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS breach_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT,                       -- masked, never the full address
    risk_score INTEGER DEFAULT 0,
    breach_count INTEGER DEFAULT 0,
    created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_breach_id ON breach_records(identifier, record_type);
CREATE INDEX IF NOT EXISTS idx_breach_pfx ON breach_records(pw_sha1_prefix);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    title TEXT, path TEXT, kind TEXT, created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_ev_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_scan_mod ON scans(module, created_at);
CREATE INDEX IF NOT EXISTS idx_cust_ev ON custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_tl_case ON timeline(case_id, ts);
"""


_INITIALIZED = False


def get_conn() -> sqlite3.Connection:
    global _INITIALIZED
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(Config.DB_PATH, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
        # Auto-create the schema on first use so any module works standalone.
        if not _INITIALIZED:
            _INITIALIZED = True
            try:
                conn.executescript(SCHEMA)
                conn.commit()
                seed_defaults()
            except sqlite3.Error:
                pass
    return conn


@contextmanager
def tx():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db():
    global _INITIALIZED
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    _INITIALIZED = True
    seed_defaults()


def migrate():
    """Add columns introduced after the first release, for existing databases."""
    conn = get_conn()
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(breach_records)")}
    except sqlite3.Error:
        return
    for col, ddl in (("record_type", "TEXT DEFAULT 'password'"),
                     ("pw_sha1_prefix", "TEXT DEFAULT ''")):
        if col not in cols:
            try:
                conn.execute(f"ALTER TABLE breach_records ADD COLUMN {col} {ddl}")
                conn.commit()
            except sqlite3.Error:
                pass


def seed_defaults():
    migrate()
    if not query_one("SELECT 1 FROM settings WHERE key='initialized'"):
        execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
                ("initialized", utcnow()))
        # A tiny offline "breach" corpus so the credential checker works with no API.
        common = ["123456", "password", "admin123", "qwerty", "111111", "letmein",
                  "iloveyou", "welcome", "monkey", "dragon", "abc123", "football",
                  "india123", "sachin123", "password123", "qwerty123", "1q2w3e4r",
                  "p@ssw0rd", "welcome123", "admin@123"]
        import hashlib as _h
        for c in common:
            execute("""INSERT OR IGNORE INTO breach_records(identifier,record_type,source,note,
                       pw_sha1_prefix,added_at) VALUES(?,?,?,?,?,?)""",
                    (c, "password", "offline-common-list",
                     "Frequently seen in public breach corpora",
                     _h.sha1(c.encode()).hexdigest().upper()[:5], utcnow()))


# ------------------------------------------------------------ helpers
def execute(sql, params=()):
    with tx() as conn:
        cur = conn.execute(sql, params)
        return cur.lastrowid


def executemany(sql, seq):
    with tx() as conn:
        conn.executemany(sql, seq)


def query(sql, params=()) -> list[dict]:
    cur = get_conn().execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def query_one(sql, params=()) -> dict | None:
    cur = get_conn().execute(sql, params)
    row = cur.fetchone()
    return dict(row) if row else None


def scalar(sql, params=(), default=0):
    row = get_conn().execute(sql, params).fetchone()
    if not row or row[0] is None:
        return default
    return row[0]


# ------------------------------------------------------------ domain writes
def log_scan(module, target, verdict, risk_score, summary, details=None,
             case_id=None, ai_used=False, duration_ms=0) -> int:
    return execute(
        """INSERT INTO scans(case_id,module,target,verdict,risk_score,summary,details,
                             ai_used,duration_ms,created_at)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (case_id, module, (target or "")[:500], verdict, int(risk_score or 0),
         (summary or "")[:2000], json.dumps(details or {}, default=str),
         1 if ai_used else 0, duration_ms, utcnow()))


def add_custody(evidence_id, action, actor, notes="", integrity="intact"):
    execute("""INSERT INTO custody(evidence_id,action,actor,notes,integrity,ts)
               VALUES(?,?,?,?,?,?)""",
            (evidence_id, action, actor, notes, integrity, utcnow()))


def add_timeline(case_id, ts, source, event, severity="info"):
    if not case_id:
        return
    execute("""INSERT INTO timeline(case_id,ts,source,event,severity,created_at)
               VALUES(?,?,?,?,?,?)""",
            (case_id, ts, source, (event or "")[:800], severity, utcnow()))


def add_ioc(case_id, ioc_type, value, source_module, confidence=60):
    try:
        execute("""INSERT OR IGNORE INTO iocs(case_id,ioc_type,value,source_module,
                   confidence,first_seen) VALUES(?,?,?,?,?,?)""",
                (case_id, ioc_type, str(value)[:400], source_module, confidence, utcnow()))
    except sqlite3.Error:
        pass


def get_setting(key, default=None):
    row = query_one("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default


def set_setting(key, value):
    execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, str(value)))
