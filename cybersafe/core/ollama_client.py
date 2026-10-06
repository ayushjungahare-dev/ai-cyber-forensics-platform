"""
Local Ollama client -- the only "AI provider" in this project.

No API keys. No cloud calls. If Ollama is offline every caller degrades
gracefully to the deterministic rule-engines, so the platform never breaks.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from config import Config

_STATUS = {"checked_at": 0.0, "online": False, "models": [], "model": Config.OLLAMA_MODEL}
_CACHE_TTL = 20  # seconds


# ------------------------------------------------------------------ HTTP
def _post(path: str, payload: dict, timeout: int | None = None) -> dict:
    url = f"{Config.OLLAMA_HOST.rstrip('/')}{path}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout or Config.OLLAMA_TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _get(path: str, timeout: int = 4) -> dict:
    url = f"{Config.OLLAMA_HOST.rstrip('/')}{path}"
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# ------------------------------------------------------------------ status
def status(force: bool = False) -> dict:
    now = time.time()
    if not force and now - _STATUS["checked_at"] < _CACHE_TTL:
        return dict(_STATUS)
    try:
        tags = _get("/api/tags")
        models = [m.get("name", "") for m in tags.get("models", [])]
        _STATUS.update(online=True, models=models, checked_at=now)
        if models and not any(m.split(":")[0] == Config.OLLAMA_MODEL.split(":")[0] for m in models):
            _STATUS["model"] = models[0]           # fall back to whatever exists
        else:
            _STATUS["model"] = Config.OLLAMA_MODEL
    except Exception:
        _STATUS.update(online=False, models=[], checked_at=now)
    return dict(_STATUS)


def is_online() -> bool:
    return status()["online"]


def active_model() -> str:
    return status().get("model") or Config.OLLAMA_MODEL


# ------------------------------------------------------------------ generate
SYSTEM_DEFAULT = (
    "You are CyberSafe AI, a defensive cybersecurity and digital-forensics assistant "
    "for students, small businesses and beginner investigators. You explain threats "
    "clearly and give practical, lawful, defensive advice. You never write malware, "
    "exploits, or attack tooling. Keep answers concise and structured."
)


def generate(prompt: str, system: str = SYSTEM_DEFAULT, temperature: float | None = None,
             max_tokens: int = 900, model: str | None = None) -> dict:
    """Single-shot completion. Returns {ok, text, error, model, elapsed_ms}."""
    if not is_online():
        return {"ok": False, "text": "", "error": "ollama_offline",
                "model": None, "elapsed_ms": 0}
    t0 = time.time()
    payload = {
        "model": model or active_model(),
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {
            "temperature": Config.OLLAMA_TEMPERATURE if temperature is None else temperature,
            "num_ctx": Config.OLLAMA_NUM_CTX,
            "num_predict": max_tokens,
        },
    }
    try:
        resp = _post("/api/generate", payload)
        return {"ok": True, "text": (resp.get("response") or "").strip(),
                "error": None, "model": payload["model"],
                "elapsed_ms": int((time.time() - t0) * 1000)}
    except urllib.error.URLError as e:
        return {"ok": False, "text": "", "error": f"connection: {e.reason}",
                "model": payload["model"], "elapsed_ms": int((time.time() - t0) * 1000)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "text": "", "error": str(e)[:200],
                "model": payload["model"], "elapsed_ms": int((time.time() - t0) * 1000)}


def chat(messages: list[dict], system: str = SYSTEM_DEFAULT,
         temperature: float | None = None, max_tokens: int = 900) -> dict:
    """Multi-turn chat with history."""
    if not is_online():
        return {"ok": False, "text": "", "error": "ollama_offline", "model": None}
    msgs = [{"role": "system", "content": system}] + [
        {"role": m["role"], "content": m["content"]} for m in messages[-16:]
    ]
    payload = {
        "model": active_model(), "messages": msgs, "stream": False,
        "options": {
            "temperature": Config.OLLAMA_TEMPERATURE if temperature is None else temperature,
            "num_ctx": Config.OLLAMA_NUM_CTX, "num_predict": max_tokens,
        },
    }
    t0 = time.time()
    try:
        resp = _post("/api/chat", payload)
        return {"ok": True, "text": (resp.get("message", {}).get("content") or "").strip(),
                "error": None, "model": payload["model"],
                "elapsed_ms": int((time.time() - t0) * 1000)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "text": "", "error": str(e)[:200], "model": payload["model"]}


def stream_chat(messages: list[dict], system: str = SYSTEM_DEFAULT):
    """Yields text chunks for server-sent-events streaming in the UI."""
    if not is_online():
        yield "[Ollama is offline. Start it with `ollama serve` and pull a model: `ollama pull llama3.2`]"
        return
    msgs = [{"role": "system", "content": system}] + [
        {"role": m["role"], "content": m["content"]} for m in messages[-16:]
    ]
    payload = {"model": active_model(), "messages": msgs, "stream": True,
               "options": {"temperature": Config.OLLAMA_TEMPERATURE,
                           "num_ctx": Config.OLLAMA_NUM_CTX}}
    url = f"{Config.OLLAMA_HOST.rstrip('/')}/api/chat"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=Config.OLLAMA_TIMEOUT) as r:
            for raw in r:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                chunk = obj.get("message", {}).get("content", "")
                if chunk:
                    yield chunk
                if obj.get("done"):
                    break
    except Exception as e:  # noqa: BLE001
        yield f"\n\n[AI stream error: {str(e)[:160]}]"


# ------------------------------------------------------------------ JSON mode
def generate_json(prompt: str, schema_hint: str, system: str = SYSTEM_DEFAULT,
                  temperature: float = 0.1, max_tokens: int = 800) -> dict:
    """
    Ask the model for strict JSON and parse it defensively.
    Returns {ok, data, raw, error}.
    """
    full = (
        f"{prompt}\n\n"
        f"Respond with ONE valid JSON object only. No markdown fences, no commentary.\n"
        f"Required shape:\n{schema_hint}\n"
    )
    res = generate(full, system=system, temperature=temperature, max_tokens=max_tokens)
    if not res["ok"]:
        return {"ok": False, "data": {}, "raw": "", "error": res["error"]}
    parsed = _parse_json_loose(res["text"])
    if parsed is None:
        return {"ok": False, "data": {}, "raw": res["text"], "error": "unparseable_json"}
    return {"ok": True, "data": parsed, "raw": res["text"], "error": None,
            "model": res.get("model")}


def _parse_json_loose(text: str):
    if not text:
        return None
    text = text.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # grab the outermost {...}
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        candidate = text[start:end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            cleaned = re.sub(r",\s*([}\]])", r"\1", candidate)
            cleaned = cleaned.replace("'", '"')
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                return None
    return None


def pull_hint() -> str:
    return ("Ollama not reachable at " + Config.OLLAMA_HOST +
            ". Run:  ollama serve   then   ollama pull " + Config.OLLAMA_MODEL)
