"""OPERATOR STEER — fold a live operator suggestion into a running plan.

The operator is just another PROPOSER, exactly like the LLM and the proof-assist
tools: a suggestion becomes one or more ``source="operator"`` Hypotheses that are
merged into the plan via :func:`orchestrator.augment_plan`, and the SAME pure judge
still disposes each downstream. The operator can NEVER confirm a finding — a
suggestion only earns the judge another honest measurement (the §1 contract:
tools + LLM + operator PROPOSE, a pure judge DISPOSES).

This module is PURE parsing/data: it opens no socket, runs no judge, decides no
verdict, and reads no file. It turns free-form operator text into an
:class:`OperatorDirective` — new hypotheses (scope-guarded to the target host) plus
optional auth context (a captured bearer token and/or a path to a broken_auth /
privesc matrix) that a downstream matrix stage may use. Lines it cannot parse are
collected in ``ignored`` (never a crash), so the CLI can echo them back honestly.

Grammar (one directive per line, verbs case-insensitive):

    test <technique> <url|/path> [param] [location] [severity]   add a hypothesis
    <technique> <url|/path> [param] ...                          (bare, verb optional)
    token <bearer-jwt>                                           genuine session token
    matrix <path-to-matrix.json>                                 broken_auth/privesc oracle
    # …                                                          comment (ignored)
    (blank | go | done | continue)                               end of input (caller)
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from .hypotheses import KNOWN_TECHNIQUES, Hypothesis

# Verbs that introduce a hypothesis line; everything after is the hypothesis spec.
_ADD_VERBS = frozenset({"test", "try", "probe", "check", "add", "hypothesis",
                        "hypothesize", "hyp"})

# Friendly operator shorthands → canonical technique names. Anything already
# canonical passes through; an unknown token is dropped (line → ignored).
_TECHNIQUE_ALIASES = {
    "sqli": "sql_injection", "sql": "sql_injection", "sqlinjection": "sql_injection",
    "reflected_xss": "xss", "reflectedxss": "xss",
    "lfi": "path_traversal", "rfi": "path_traversal", "traversal": "path_traversal",
    "redirect": "open_redirect", "openredirect": "open_redirect",
    "template": "ssti", "template_injection": "ssti",
    "cors_misconfig": "cors",
    "privesc": "privilege_escalation", "authz": "privilege_escalation",
    "auth": "broken_auth", "jwt": "broken_auth", "jwt_weakness": "broken_auth",
}

_LOCATIONS = frozenset({"query", "body", "body_form", "body_json", "json",
                        "path", "header", "cookie"})
_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

# Lines the caller treats as "operator is done" — never a hypothesis.
_CONTINUE_WORDS = frozenset({"", "go", "done", "continue", "run", "proceed", "ok"})


@dataclass(frozen=True)
class OperatorDirective:
    """The parsed intent of one operator steer prompt. Pure DATA.

    ``hypotheses`` are already scope-guarded ``source="operator"`` proposals ready
    to hand to :func:`orchestrator.augment_plan`. ``token`` / ``matrix_path`` are
    optional auth context for a downstream broken_auth/privesc matrix stage — the
    token is a secret and MUST never be logged or echoed. ``ignored`` holds the raw
    lines we could not turn into any of the above, so the CLI can report them
    transparently instead of silently dropping operator intent."""

    hypotheses: tuple = ()
    token: "str | None" = None
    matrix_path: "str | None" = None
    ignored: tuple = ()

    @property
    def is_empty(self) -> bool:
        return not (self.hypotheses or self.token or self.matrix_path)

    @property
    def has_auth_context(self) -> bool:
        return bool(self.token or self.matrix_path)


def _canonical_technique(tok: str) -> "str | None":
    t = (tok or "").strip().lower()
    t = _TECHNIQUE_ALIASES.get(t, t)
    return t if t in KNOWN_TECHNIQUES else None


def _host(target_or_url: str) -> str:
    s = target_or_url or ""
    return urlsplit(s if "://" in s else f"http://{s}").netloc.lower()


def _origin(target: str) -> str:
    sp = urlsplit(target if "://" in (target or "") else f"http://{target or ''}")
    return f"{sp.scheme}://{sp.netloc}" if sp.netloc else ""


def _normalize_url(raw: str, surface) -> "str | None":
    """Absolutize a bare ``/path`` against the target origin; leave full URLs be.
    Returns None when no usable URL can be formed."""
    raw = (raw or "").strip().strip('"').strip("'")
    if not raw:
        return None
    target = getattr(surface, "target", "") or ""
    if raw.startswith("/"):
        origin = _origin(target)
        return f"{origin}{raw}" if origin else None
    if "://" not in raw:
        # host-relative token without a leading slash → treat as a path
        origin = _origin(target)
        return f"{origin}/{raw}" if origin else None
    return raw


def _in_scope(url: str, surface) -> bool:
    """A proposal is in scope only when its host matches the engagement host —
    the same never-propose-off-target guard the LLM parser applies."""
    host = (getattr(surface, "host", "") or "").lower()
    if not host:
        return True   # unknown target host → cannot scope-reject; trust the URL
    return _host(url) == host


def _parse_hypothesis_line(tokens, surface) -> "Hypothesis | None":
    """``[verb] <technique> <url|/path> [param] [location] [severity]`` → Hypothesis.
    Remaining tokens after technique+url are classified positionally-but-forgiving:
    a location keyword sets location, a severity word sets severity, else the first
    leftover becomes the param."""
    if tokens and tokens[0].lower() in _ADD_VERBS:
        tokens = tokens[1:]
    if len(tokens) < 2:
        return None
    technique = _canonical_technique(tokens[0])
    if technique is None:
        return None
    url = _normalize_url(tokens[1], surface)
    if url is None or not _in_scope(url, surface):
        return None

    param = None
    location = "query"
    severity = "MEDIUM"
    for tok in tokens[2:]:
        low = tok.lower()
        if low in _LOCATIONS:
            location = low
        elif tok.upper() in _SEVERITIES:
            severity = tok.upper()
        elif param is None:
            param = tok
    return Hypothesis(
        technique=technique, url=url, method="GET", param=param,
        location=location, rationale="operator suggestion", severity=severity,
        source="operator")


def parse_operator_suggestion(text: str, surface) -> OperatorDirective:
    """Parse free-form operator steer text into an :class:`OperatorDirective`.

    Never raises on bad input — unparseable lines land in ``ignored``. Hypotheses
    are scope-guarded to the target host and deduped by :attr:`Hypothesis.key`
    (the caller's :func:`augment_plan` dedups again against the live plan)."""
    hyps: list = []
    seen: set = set()
    token: "str | None" = None
    matrix_path: "str | None" = None
    ignored: list = []

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.lower() in _CONTINUE_WORDS:
            continue
        tokens = line.split()
        verb = tokens[0].lower()

        if verb == "token" and len(tokens) >= 2:
            # Strip an optional "Bearer " prefix; keep the raw credential in memory
            # only. NEVER log or echo this value.
            token = line.split(None, 1)[1].strip()
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            continue
        if verb == "matrix" and len(tokens) >= 2:
            matrix_path = line.split(None, 1)[1].strip().strip('"').strip("'")
            continue

        hyp = _parse_hypothesis_line(tokens, surface)
        if hyp is None:
            ignored.append(line)
            continue
        if hyp.key in seen:
            continue
        seen.add(hyp.key)
        hyps.append(hyp)

    return OperatorDirective(
        hypotheses=tuple(hyps), token=token, matrix_path=matrix_path,
        ignored=tuple(ignored))
