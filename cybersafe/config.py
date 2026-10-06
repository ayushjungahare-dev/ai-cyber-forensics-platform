"""
Central configuration for the AI Cyber Safety & Digital Forensics Platform.

Everything here is local-first. There are NO third-party API keys anywhere in
this project. All AI capability is served by a local Ollama instance.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
UPLOAD_DIR = DATA_DIR / "uploads"
KNOWLEDGE_DIR = DATA_DIR / "knowledge"
REPORT_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "cybersafe.db"

for _d in (DATA_DIR, EVIDENCE_DIR, UPLOAD_DIR, KNOWLEDGE_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)


class Config:
    # --- Flask ---
    SECRET_KEY = os.environ.get("CYBERSAFE_SECRET", "cybersafe-local-dev-key-change-me")
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", "512")) * 1024 * 1024
    TEMPLATES_AUTO_RELOAD = True
    JSON_SORT_KEYS = False

    # --- Ollama (100% local, no API key) ---
    OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
    OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "120"))
    OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "4096"))
    OLLAMA_TEMPERATURE = float(os.environ.get("OLLAMA_TEMPERATURE", "0.2"))

    # --- Breach lookup ---
    # OPTIONAL. The platform works with no key at all, using the free keyless
    # providers. Supply your own HaveIBeenPwned key for authoritative results.
    HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
    BREACH_TIMEOUT = int(os.environ.get("BREACH_TIMEOUT", "20"))

    # --- Paths ---
    DB_PATH = str(DB_PATH)
    EVIDENCE_DIR = str(EVIDENCE_DIR)
    UPLOAD_DIR = str(UPLOAD_DIR)
    KNOWLEDGE_DIR = str(KNOWLEDGE_DIR)
    REPORT_DIR = str(REPORT_DIR)

    # --- Platform ---
    APP_NAME = "AI Cyber Safety & Digital Forensics Platform"
    APP_TAGLINE = "Protect. Detect. Investigate."
    APP_VERSION = "1.0.0"
    DEFAULT_INVESTIGATOR = os.environ.get("INVESTIGATOR", "analyst")

    # Analysis tuning
    RISK_THRESHOLDS = {"safe": 25, "suspicious": 55, "dangerous": 80}
    MAX_STRINGS_EXTRACT = 400_000     # cap for memory-dump string extraction
    MAX_LOG_LINES = 250_000           # cap for log ingestion
