"""
Operator-supplied broken-authentication oracle (the "auth matrix").

Pure DATA, exactly like :mod:`app.security_graph.privesc.privesc_policy`. It is
deliberately **target-agnostic**: the engine holds no knowledge of any site,
route, or account. Everything specific to a target arrives here as declared
ground truth (typed by an operator) — while the one credential this class needs,
a genuine bearer token to forge FROM, is supplied LIVE from a captured browser
session and NEVER read from a file.

An operator declares one authenticated *principal* (its live session headers are
filled in at run time) and a set of *checks*, each naming a protected route that
MUST require an authentic token, plus the forgery strategy to attempt:

  alg_none         header alg="none", empty signature (pure; a shape-guard can
                   block it, so it is fully find→patch→PROVEN live)
  unsigned         signature stripped to a 2-part token (pure; guard-provable)
  hs256_confusion  RS256→HS256 confusion signed with the RSA public key as an
                   HMAC secret (needs `public_key` material; the forgery is a
                   VALIDLY-SIGNED token invisible to a shape-guard, so its
                   remediation is honestly advisory — the durable fix is
                   handler-side algorithm pinning)
  weak_secret      brute over a bounded dictionary, then re-sign a tampered
                   payload with the cracked secret (needs `secret_candidates`;
                   signed forgery → advisory remediation; a strong secret that
                   no candidate cracks yields no probe, never a false claim)

The declared boundary makes no security claim on its own. It only poses a
question the deterministic judge answers with a privesc-style **three-probe
differential** on the live target: a *control* probe (the genuine token → MUST
succeed, proving the route is token-authenticated and the session valid), a
*breach* probe (the forged token → the validation-flaw probe), and an anonymous
*baseline* probe (no token → MUST be denied, ruling out a public route). A bare
status code is never itself the verdict.

An empty matrix is legal — it simply means "no broken-auth pass requested".
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

# The forgery strategies a check may declare. Each maps to one pure derivation
# in :mod:`.forge` — no scoring, no heuristics.
_FORGERY_STRATEGIES = frozenset(
    {"alg_none", "unsigned", "hs256_confusion", "weak_secret"}
)

# The subset a gateway shape-guard (the `jwt` RequestGuardRule family) can block:
# an alg="none" or unsigned token is refusable by SHAPE alone. A validly-signed
# forgery (hs256_confusion / weak_secret) is indistinguishable from a genuine
# token at the gateway, so its durable fix is handler-side — remediation stays
# honestly advisory rather than claiming a proof a shape-guard cannot earn.
GUARD_PROVABLE_STRATEGIES = frozenset({"alg_none", "unsigned"})

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

# Default "accepted" statuses: any 2xx. The differential (control genuine token
# must ALSO be 2xx, anonymous MUST NOT) is what makes a 2xx breach meaningful;
# this is never a bare-status verdict.
_DEFAULT_SUCCESS_STATUSES = tuple(range(200, 300))


@dataclass(frozen=True)
class TokenLocation:
    """Where the app carries the session token — so control/breach probes ride it
    in the SAME place the real client does.

    ``kind == "header"`` (default) sends ``<name>: <scheme> <token>`` (the classic
    ``Authorization: Bearer <jwt>``). ``kind == "cookie"`` sends
    ``Cookie: <name>=<token>`` — the shape most PortSwigger JWT labs and real SPAs
    actually use. The location is declared ground truth (never a secret); only the
    token value itself is sensitive. Default preserves the historical behaviour.
    """

    kind: str = "header"                 # "header" | "cookie"
    name: str = "Authorization"          # header name, or cookie name
    scheme: str = "Bearer"               # header value prefix; ignored for cookie

    def header_for(self, token: str) -> tuple[str, str]:
        """The single request header that carries ``token`` in this location."""
        if self.kind == "cookie":
            return ("Cookie", f"{self.name}={token}")
        prefix = f"{self.scheme} " if self.scheme else ""
        return (self.name, f"{prefix}{token}")

    def extract(self, headers: tuple[tuple[str, str], ...]) -> str:
        """The bare token from a principal's declared headers, or ``""``.

        Mirrors :meth:`header_for` in reverse so a live-captured session (however
        it carries the token) is read from the SAME location the probes will use.
        """
        for name, value in headers:
            if self.kind == "cookie" and name.lower() == "cookie":
                for part in value.split(";"):
                    key, sep, val = part.strip().partition("=")
                    if sep and key == self.name:
                        return val.strip()
            elif self.kind != "cookie" and name.lower() == self.name.lower():
                text = value.strip()
                prefix = f"{self.scheme} "
                if self.scheme and text.lower().startswith(prefix.lower()):
                    return text[len(prefix):].strip()
                return text
        return ""


@dataclass(frozen=True)
class ControlRoute:
    """A route the GENUINE principal legitimately reaches — the session-alive
    control probe. For a VERTICAL forgery (a plain user forges an admin token) the
    genuine token is DENIED at the breach route, so the control must prove the
    session is live against a route the principal really owns (e.g. ``/my-account``)
    rather than the protected route itself."""

    method: str = "GET"
    path: str = ""


@dataclass(frozen=True)
class BrokenAuthPrincipal:
    """
    The one authenticated account whose genuine token is forged FROM.

    `headers` carry the identifying session headers a probe replays to act AS
    this principal — filled LIVE from a captured browser session (an
    ``Authorization: Bearer <genuine-jwt>`` header), never read from a file. A
    principal with no live token means the control probe cannot succeed, so the
    judge returns INCONCLUSIVE — never a manufactured finding.
    """

    name: str
    headers: tuple[tuple[str, str], ...] = ()
    role: str = "user"
    control: "ControlRoute | None" = None


@dataclass(frozen=True)
class BrokenAuthCheck:
    """
    One protected route that MUST reject a forged token.

    `forgery` selects the derivation attempted against the genuine token.
    `public_key` / `secret_candidates` carry the (operator-supplied) material a
    signed-forgery strategy needs; the pure/guard-provable strategies need none.
    `forge_claims` are operator-declared JWT payload overrides baked into the
    forged token — the escalation target (e.g. ``{"sub": "administrator"}``) for a
    VERTICAL bypass where the genuine principal is denied at the breach route.
    They are declared ground truth (never a secret); the pure judge still disposes
    the live differential, so a declared claim never fabricates a finding.
    """

    forgery: str
    method: str
    path: str
    severity: str = "HIGH"
    public_key: str = ""
    secret_candidates: tuple[str, ...] = ()
    forge_claims: tuple[tuple[str, Any], ...] = ()
    rationale: str = ""


@dataclass(frozen=True)
class BrokenAuthPolicy:
    principal: "BrokenAuthPrincipal | None" = None
    checks: tuple[BrokenAuthCheck, ...] = ()
    success_statuses: tuple[int, ...] = _DEFAULT_SUCCESS_STATUSES
    token_location: TokenLocation = field(default_factory=TokenLocation)


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"broken-auth matrix: '{field_name}' must be a non-empty string."
        )
    return value.strip()

def _parse_headers(payload: Any, field_name: str) -> tuple[tuple[str, str], ...]:
    """Accept ``[["Name","Value"], ...]`` or ``{"Name": "Value", ...}``."""
    if payload is None:
        return ()
    pairs: list[tuple[str, str]] = []
    if isinstance(payload, dict):
        items = list(payload.items())
    elif isinstance(payload, (list, tuple)):
        items = []
        for entry in payload:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise ValueError(
                    f"broken-auth matrix: each '{field_name}' entry must be a "
                    "[name, value] pair."
                )
            items.append((entry[0], entry[1]))
    else:
        raise ValueError(
            f"broken-auth matrix: '{field_name}' must be an object or a list of "
            "[name, value] pairs."
        )
    for name, value in items:
        pairs.append((_as_str(name, f"{field_name}[].name"), str(value)))
    return tuple(pairs)


def _parse_route(payload: Any, field_name: str) -> ControlRoute | None:
    """Parse an optional ``{method, path}`` route object (used by ``control``)."""
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ValueError(f"broken-auth matrix: '{field_name}' must be an object.")
    method = _as_str(payload.get("method", "GET"), f"{field_name}.method").upper()
    path = _as_str(payload.get("path"), f"{field_name}.path")
    return ControlRoute(method=method, path=path)


def _parse_token_location(payload: Any) -> TokenLocation:
    """Parse an optional ``token_location`` object; default = Authorization Bearer."""
    if payload is None:
        return TokenLocation()
    if not isinstance(payload, dict):
        raise ValueError("broken-auth matrix: 'token_location' must be an object.")
    kind = _as_str(payload.get("kind", "header"), "token_location.kind").lower()
    if kind not in ("header", "cookie"):
        raise ValueError(
            "broken-auth matrix: 'token_location.kind' must be 'header' or "
            f"'cookie', got {kind!r}."
        )
    default_name = "session" if kind == "cookie" else "Authorization"
    name = _as_str(payload.get("name", default_name), "token_location.name")
    scheme = payload.get("scheme", "" if kind == "cookie" else "Bearer")
    scheme = scheme if isinstance(scheme, str) else ""
    return TokenLocation(kind=kind, name=name, scheme=scheme)


def _parse_principal(payload: Any) -> BrokenAuthPrincipal | None:
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ValueError("broken-auth matrix: 'principal' must be an object.")
    name = _as_str(payload.get("name", "authenticated"), "principal.name")
    headers = _parse_headers(payload.get("headers"), "principal.headers")
    role = payload.get("role", "user")
    role = _as_str(role, "principal.role") if role else "user"
    control = _parse_route(payload.get("control"), "principal.control")
    return BrokenAuthPrincipal(name=name, headers=headers, role=role, control=control)


def _parse_secret_candidates(payload: Any) -> tuple[str, ...]:
    if payload is None:
        return ()
    if not isinstance(payload, (list, tuple)):
        raise ValueError(
            "broken-auth matrix: 'secret_candidates' must be a list of strings."
        )
    out: list[str] = []
    for item in payload:
        if not isinstance(item, str):
            raise ValueError(
                "broken-auth matrix: each secret candidate must be a string."
            )
        out.append(item)
    return tuple(out)


def _parse_forge_claims(payload: Any) -> tuple[tuple[str, Any], ...]:
    """Parse the optional ``forge_claims`` payload-override object.

    Maps JWT payload claim names to the values baked into the forged token — the
    operator-declared escalation target (e.g. ``{"sub": "administrator"}``). Values
    are constrained to JSON scalars so the resulting check stays hashable/frozen;
    ordering follows the declaration. An absent block yields ``()`` (the forged
    token then keeps the genuine payload verbatim, only marked).
    """
    if payload is None:
        return ()
    if not isinstance(payload, dict):
        raise ValueError(
            "broken-auth matrix: 'forge_claims' must be an object mapping JWT "
            "payload claim names to their forged values."
        )
    out: list[tuple[str, Any]] = []
    for key, value in payload.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError(
                "broken-auth matrix: each 'forge_claims' key must be a non-empty "
                "string."
            )
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise ValueError(
                "broken-auth matrix: each 'forge_claims' value must be a JSON "
                "scalar (string, number, boolean, or null)."
            )
        out.append((key.strip(), value))
    return tuple(out)


def _parse_check(payload: Any) -> BrokenAuthCheck:
    if not isinstance(payload, dict):
        raise ValueError("broken-auth matrix: each check must be an object.")

    forgery = _as_str(payload.get("forgery", "alg_none"), "checks[].forgery").lower()
    if forgery not in _FORGERY_STRATEGIES:
        raise ValueError(
            "broken-auth matrix: 'forgery' must be one of "
            f"{sorted(_FORGERY_STRATEGIES)}, got {forgery!r}."
        )

    route = payload.get("route")
    if not isinstance(route, dict):
        raise ValueError(
            "broken-auth matrix: each check needs a 'route' object naming the "
            "protected endpoint (method + path)."
        )
    method = _as_str(route.get("method", "GET"), "checks[].route.method").upper()
    path = _as_str(route.get("path"), "checks[].route.path")

    severity = _as_str(payload.get("severity", "HIGH"), "checks[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "broken-auth matrix: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    public_key = payload.get("public_key", "")
    public_key = public_key if isinstance(public_key, str) else ""

    secret_candidates = _parse_secret_candidates(payload.get("secret_candidates"))

    forge_claims = _parse_forge_claims(payload.get("forge_claims"))

    rationale = payload.get("rationale", "")
    rationale = rationale.strip() if isinstance(rationale, str) else ""

    return BrokenAuthCheck(
        forgery=forgery,
        method=method,
        path=path,
        severity=severity,
        public_key=public_key,
        secret_candidates=secret_candidates,
        forge_claims=forge_claims,
        rationale=rationale,
    )

def _parse_success_statuses(payload: Any) -> tuple[int, ...]:
    if payload is None:
        return _DEFAULT_SUCCESS_STATUSES
    if not isinstance(payload, (list, tuple)) or not payload:
        raise ValueError(
            "broken-auth matrix: 'success_statuses' must be a non-empty list of "
            "integer HTTP status codes."
        )
    out: list[int] = []
    for item in payload:
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError(
                "broken-auth matrix: each success status must be an integer."
            )
        out.append(item)
    return tuple(out)


def parse_broken_auth_policy(payload: Any) -> BrokenAuthPolicy:
    """
    Validate and normalise a decoded broken-authentication matrix.

    Accepts either a dedicated document ``{"broken_auth_matrix": {...}}`` or a
    combined access-policy document that also carries a ``broken_auth_matrix``
    section — so a single operator file drives every vulnerability class.
    Returns an empty policy (no checks) when no matrix is declared, which the
    caller treats as "broken-auth pass not requested".
    """
    if not isinstance(payload, dict):
        raise ValueError("broken-auth matrix: top level must be a JSON object.")

    matrix = payload.get("broken_auth_matrix", payload)
    if not isinstance(matrix, dict):
        raise ValueError(
            "broken-auth matrix: 'broken_auth_matrix' must be an object."
        )

    principal = _parse_principal(matrix.get("principal"))
    token_location = _parse_token_location(matrix.get("token_location"))

    checks_raw = matrix.get("checks", [])
    if not isinstance(checks_raw, (list, tuple)):
        raise ValueError("broken-auth matrix: 'checks' must be a list.")
    checks = tuple(_parse_check(item) for item in checks_raw)

    if not checks:
        return BrokenAuthPolicy(
            principal=principal,
            checks=(),
            success_statuses=_DEFAULT_SUCCESS_STATUSES,
            token_location=token_location,
        )

    success_statuses = _parse_success_statuses(matrix.get("success_statuses"))

    return BrokenAuthPolicy(
        principal=principal,
        checks=checks,
        success_statuses=success_statuses,
        token_location=token_location,
    )


def load_broken_auth_policy(path: str | Path) -> BrokenAuthPolicy:
    """Load and validate a broken-authentication matrix JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_broken_auth_policy(json.loads(text))



