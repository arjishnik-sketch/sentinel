"""Lean, stateless JSON-mode LLM client for the autonomous loop.

Distinct from app.ai.SentinelAI (a stateful chat used for long-form advisory
prose): here every call is independent, temperature 0, and Ollama's JSON mode is
forced so the caller always gets structured data back. The transport is an
injectable seam so the hypothesis engine is fully testable without Ollama.

The LLM only ever PROPOSES. Nothing it returns is a verdict — a deterministic
judge downstream disposes. So a failed / unparseable LLM call is non-fatal: the
caller falls back to deterministic rules.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from ..config import OLLAMA_URL, OLLAMA_MODEL, AI_ADVISORY_TIMEOUT, logger


@dataclass
class LLMResult:
    ok: bool
    data: object          # parsed dict/list, or None on failure
    raw: str = ""
    error: str = ""


def _ollama_json_chat(system, user, *, model, url, timeout, num_predict):
    import requests

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0, "num_predict": num_predict},
    }
    r = requests.post(url + "/api/chat", json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()["message"]["content"]


def _loads_lenient(raw):
    """Parse JSON, tolerating a model that wraps it in prose or fences."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        pass
    # Fall back to the first balanced {...} or [...] span.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = raw.find(opener)
        end = raw.rfind(closer)
        if 0 <= start < end:
            try:
                return json.loads(raw[start : end + 1])
            except ValueError:
                continue
    return None


def ask_json(
    system,
    user,
    *,
    model=None,
    url=None,
    timeout=None,
    num_predict=512,
    transport=None,
) -> LLMResult:
    """Call the LLM in JSON mode and return a parsed LLMResult. Never raises."""

    transport = transport or _ollama_json_chat
    try:
        raw = transport(
            system,
            user,
            model=model or OLLAMA_MODEL,
            url=url or OLLAMA_URL,
            timeout=timeout or AI_ADVISORY_TIMEOUT,
            num_predict=num_predict,
        )
    except Exception as exc:  # network down, model missing, timeout, ...
        logger.warning("LLM call failed: %s", exc)
        return LLMResult(ok=False, data=None, error=str(exc))

    data = _loads_lenient(raw)
    if data is None:
        return LLMResult(ok=False, data=None, raw=raw, error="unparseable JSON")
    return LLMResult(ok=True, data=data, raw=raw)
