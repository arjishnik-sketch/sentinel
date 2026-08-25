"""Lean, stateless JSON-mode LLM client for the autonomous loop.

Distinct from app.ai.SentinelAI (a stateful chat used for long-form advisory
prose): here every call is independent, temperature 0, and JSON mode is forced
so the caller always gets structured data back. The transport is an injectable
seam so the hypothesis engine is fully testable without any model.

The client is PROVIDER-PLUGGABLE. By default it talks to a local Ollama (no key,
fully offline — the safe default that keeps a pentest air-gapped). A user who
wants a cleverer model exports SENTINEL_LLM_PROVIDER=anthropic|openai|compatible
and the matching API key (ANTHROPIC_API_KEY / OPENAI_API_KEY); the key is read
from the environment (or prompted for once via getpass on an interactive TTY),
held only in memory for the process, and NEVER logged or persisted.

The LLM only ever PROPOSES. Nothing it returns is a verdict — a deterministic
judge downstream disposes. So the choice of provider cannot change a finding: a
smarter model proposes better hypotheses/payloads, but the pure judge remains
the sole arbiter. A failed / unparseable call is non-fatal: the caller falls
back to deterministic rules.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os

from ..config import OLLAMA_URL, OLLAMA_MODEL, AI_ADVISORY_TIMEOUT, logger


# Sensible, overridable defaults for the hosted providers. A user who wants a
# different model exports SENTINEL_LLM_MODEL. Quality is the priority, so the
# hosted defaults are strong general models rather than the cheapest tier.
_DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5"
_DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


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


def _openai_json_chat(system, user, *, model, url, timeout, num_predict, api_key):
    """OpenAI (and any OpenAI-compatible gateway) chat-completions, JSON mode."""
    import requests

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0,
        "max_tokens": num_predict,
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    r = requests.post(
        url.rstrip("/") + "/chat/completions",
        json=payload,
        headers=headers,
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _anthropic_json_chat(system, user, *, model, url, timeout, num_predict, api_key):
    """Anthropic Messages API. JSON is coaxed via the system prompt + a leading

    assistant '{' is NOT used (JSON mode is not a first-class flag here); the
    lenient parser recovers the object from the returned text blocks.
    """
    import requests

    payload = {
        "model": model,
        "system": system + "\n\nRespond with a single valid JSON value and nothing else.",
        "messages": [{"role": "user", "content": user}],
        "max_tokens": num_predict,
        "temperature": 0,
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    r = requests.post(
        url.rstrip("/") + "/v1/messages",
        json=payload,
        headers=headers,
        timeout=timeout,
    )
    r.raise_for_status()
    blocks = r.json().get("content", [])
    return "".join(
        b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"
    )


class LLMConfigError(RuntimeError):
    """A non-Ollama provider was selected but is misconfigured (missing key or
    base URL). :func:`ask_json` converts this into a non-fatal ``LLMResult`` so
    the caller falls back to deterministic rules rather than crashing a scan."""


@dataclass(frozen=True)
class LLMProvider:
    """A fully-resolved backend: the (already key-bound) transport plus the
    model and base URL to call it with. The transport's signature is uniform —
    ``(system, user, *, model, url, timeout, num_predict)`` — because any API
    key is bound in via a closure (see :func:`_bind`), so the key never travels
    through :func:`ask_json` and can never be logged from there."""

    name: str
    transport: object
    model: str
    url: str


def _resolve_api_key(env, primary, label, *, required=True):
    """Return the API key for a hosted provider, or prompt for it once on an
    interactive TTY. The key is read from the environment (or getpass) and held
    only in memory — it is NEVER logged or persisted. Error text names the
    environment variable, never any key material."""
    key = (env.get(primary) or env.get("SENTINEL_LLM_API_KEY") or "").strip()
    if key:
        return key
    import sys

    if getattr(sys.stdin, "isatty", lambda: False)():
        import getpass

        entered = getpass.getpass(f"{label} API key ({primary}, not stored): ").strip()
        if entered:
            return entered
    if required:
        raise LLMConfigError(
            f"{label} provider selected but no API key found "
            f"(set {primary} or SENTINEL_LLM_API_KEY)"
        )
    return ""


def _bind(transport, api_key):
    """Bind an API key into a hosted transport, yielding the uniform
    ``(system, user, *, model, url, timeout, num_predict)`` signature. The key
    is captured in a closure — deliberately NOT via functools.partial, whose
    repr would echo the key — so ``repr(provider)`` can never leak it."""

    def bound(system, user, *, model, url, timeout, num_predict):
        return transport(
            system,
            user,
            model=model,
            url=url,
            timeout=timeout,
            num_predict=num_predict,
            api_key=api_key,
        )

    return bound


def _build_provider(name, env):
    if name in ("", "ollama", "local"):
        return LLMProvider(
            name="ollama",
            transport=_ollama_json_chat,
            model=env.get("SENTINEL_LLM_MODEL") or OLLAMA_MODEL,
            url=env.get("SENTINEL_LLM_URL") or OLLAMA_URL,
        )
    if name == "anthropic":
        key = _resolve_api_key(env, "ANTHROPIC_API_KEY", "Anthropic")
        return LLMProvider(
            name="anthropic",
            transport=_bind(_anthropic_json_chat, key),
            model=env.get("SENTINEL_LLM_MODEL") or _DEFAULT_ANTHROPIC_MODEL,
            url=env.get("SENTINEL_LLM_URL") or "https://api.anthropic.com",
        )
    if name == "openai":
        key = _resolve_api_key(env, "OPENAI_API_KEY", "OpenAI")
        return LLMProvider(
            name="openai",
            transport=_bind(_openai_json_chat, key),
            model=env.get("SENTINEL_LLM_MODEL") or _DEFAULT_OPENAI_MODEL,
            url=env.get("SENTINEL_LLM_URL") or "https://api.openai.com/v1",
        )
    if name in ("compatible", "openai-compatible", "custom"):
        # A generic OpenAI-compatible gateway (vLLM, LM Studio, LiteLLM, a
        # corporate proxy, ...). The base URL is required; the key is optional
        # because many local gateways accept any/no bearer token.
        url = (env.get("SENTINEL_LLM_URL") or "").strip()
        if not url:
            raise LLMConfigError(
                "compatible provider selected but SENTINEL_LLM_URL is unset "
                "(point it at the gateway's OpenAI-compatible base, e.g. "
                "https://host/v1)"
            )
        key = _resolve_api_key(env, "OPENAI_API_KEY", "OpenAI-compatible", required=False)
        return LLMProvider(
            name="compatible",
            transport=_bind(_openai_json_chat, key),
            model=env.get("SENTINEL_LLM_MODEL") or OLLAMA_MODEL,
            url=url,
        )
    raise LLMConfigError(
        f"unknown SENTINEL_LLM_PROVIDER={name!r} "
        "(expected ollama|anthropic|openai|compatible)"
    )


_PROVIDER_CACHE: "LLMProvider | None" = None


def resolve_provider(env=None) -> LLMProvider:
    """Resolve the configured backend from ``SENTINEL_LLM_PROVIDER`` (default
    ``ollama`` — offline, no key). When ``env`` is omitted the result is cached
    process-wide, so an interactive getpass prompt happens at most once; tests
    pass an explicit ``env`` dict for a hermetic, uncached resolution."""
    global _PROVIDER_CACHE
    use_cache = env is None
    if use_cache and _PROVIDER_CACHE is not None:
        return _PROVIDER_CACHE
    source = os.environ if env is None else env
    name = (source.get("SENTINEL_LLM_PROVIDER") or "ollama").strip().lower()
    provider = _build_provider(name, source)
    if use_cache:
        _PROVIDER_CACHE = provider
    return provider


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
    """Call the LLM in JSON mode and return a parsed LLMResult. Never raises.

    When ``transport`` is not injected, the backend is resolved from the
    environment (``SENTINEL_LLM_PROVIDER``) and any API key is bound into the
    transport there; ``model``/``url`` fall back to that provider's own
    defaults. An explicitly injected ``transport`` keeps the legacy Ollama-shaped
    defaults, so existing tests that pass a fake transport are unaffected.
    """
    try:
        if transport is None:
            provider = resolve_provider()
            transport = provider.transport
            model = model or provider.model
            url = url or provider.url
        else:
            model = model or OLLAMA_MODEL
            url = url or OLLAMA_URL
        raw = transport(
            system,
            user,
            model=model,
            url=url,
            timeout=timeout or AI_ADVISORY_TIMEOUT,
            num_predict=num_predict,
        )
    except Exception as exc:  # network down, model missing, timeout, bad config
        logger.warning("LLM call failed: %s", exc)
        return LLMResult(ok=False, data=None, error=str(exc))

    data = _loads_lenient(raw)
    if data is None:
        return LLMResult(ok=False, data=None, raw=raw, error="unparseable JSON")
    return LLMResult(ok=True, data=data, raw=raw)
