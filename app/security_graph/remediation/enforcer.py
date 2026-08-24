"""
Enforcement shield — the live half of PATCH + PROVE.

Given a provider-agnostic :class:`AccessControlRule` derived from a
*confirmed* authorization contradiction, this module stands a real reverse
proxy up on loopback in front of the engagement target. The proxy denies
exactly the request the rule forbids (403) and forwards everything else
unchanged to the fixed upstream. Re-probing the same authorization
property THROUGH this proxy is what lets the deterministic judge PROVE the
fix live — no source code required.

Nothing here invents authorization semantics. The decision is a pure
function of the rule and the request's own headers; the proxy only ever
forwards to the one upstream it was constructed with (SSRF-safe by
construction), lives on an ephemeral loopback port, and is scoped to the
lifetime of a single verification.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

from .model import AccessControlRule


# Presence of any of these request headers marks a *non-anonymous* caller:
# bearer/basic auth, a session cookie, or the two most common custom token
# headers. General across stacks — nothing target-specific.
_AUTH_INDICATOR_HEADERS = frozenset(
    {"authorization", "cookie", "x-access-token", "x-api-key"}
)

# Hop-by-hop headers a proxy must never forward verbatim.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)

def _lower_keys(headers) -> dict[str, str]:
    """Normalise any header mapping/pair-iterable to lowercase-keyed dict."""
    if headers is None:
        return {}
    items = headers.items() if hasattr(headers, "items") else headers
    return {str(name).lower(): str(value) for name, value in items}


def _request_is_anonymous(lowered: dict[str, str]) -> bool:
    """True when the request presents no recognised principal credential."""
    return not any(name in lowered for name in _AUTH_INDICATOR_HEADERS)


def _rule_matches_principal(
    rule: AccessControlRule,
    lowered: dict[str, str],
) -> bool:
    if rule.principal_kind == "anonymous":
        # The anonymous deny rule targets only the credential-less caller.
        # A request bearing credentials is a *different* principal.
        return _request_is_anonymous(lowered)

    if rule.principal_headers:
        # A specific principal is recognised only by its exact identifying
        # headers (case-insensitive name, exact value).
        for name, value in rule.principal_headers:
            if lowered.get(str(name).lower()) != str(value):
                return False
        return True

    # A named principal we cannot fingerprint from the request alone:
    # enforce on the route itself (best-effort; documented).
    return True


def evaluate_request(rules, method, path, headers) -> str:
    """
    Pure access decision for one request against the derived rules.

    Returns ``"deny"`` if any rule forbids this request, else
    ``"forward"``. Matching is exact on method and path; principal
    identity is decided by the request's own headers. No HTTP status is
    interpreted here — this is enforcement, not observation.
    """
    method_norm = (method or "").strip().upper()
    path_norm = path or ""
    lowered = _lower_keys(headers)

    for rule in rules:
        if rule.decision != "deny":
            continue
        if rule.method.strip().upper() != method_norm:
            continue
        if rule.path != path_norm:
            continue
        if _rule_matches_principal(rule, lowered):
            return "deny"

    return "forward"


@dataclass(frozen=True)
class ResponseHeaderRule:
    """
    A provider-agnostic corrective mutation for one response header on a
    route. The shield applies it to the *forwarded* response so a fresh
    posture probe observes the corrected headers.

    `op` is the enforcement primitive, not an observation:
      set              -> emit `header: value`, replacing any upstream copy
      remove           -> drop the header entirely
      remove_if_equals -> drop the header only when it equals `value`
                          (case-insensitive), e.g. a wildcard CORS origin
    """

    method: str
    path: str
    header: str
    op: str
    value: str = ""


def apply_header_mutations(resp_headers, method, path, header_rules):
    """
    Pure: return a new ``[(name, value), ...]`` list with the corrective
    header mutations for this method+path applied. No security verdict is
    made here — this only rewrites headers the way the operator's declared
    posture requires, so the deterministic judge can re-decide honestly.
    """
    method_norm = (method or "").strip().upper()
    path_norm = path or ""
    active = [
        rule
        for rule in header_rules
        if rule.method.strip().upper() == method_norm
        and rule.path == path_norm
    ]
    if not active:
        return list(resp_headers)

    result = list(resp_headers)
    for rule in active:
        target = rule.header.lower()
        if rule.op == "remove":
            result = [(n, v) for (n, v) in result if n.lower() != target]
        elif rule.op == "remove_if_equals":
            want = rule.value.strip().lower()
            result = [
                (n, v)
                for (n, v) in result
                if not (n.lower() == target and v.strip().lower() == want)
            ]
        elif rule.op == "set":
            result = [(n, v) for (n, v) in result if n.lower() != target]
            result.append((rule.header, rule.value))
    return result


@dataclass(frozen=True)
class CookieAttributeRule:
    """
    A provider-agnostic corrective mutation for one ``Set-Cookie`` attribute
    on a route. The shield applies it to the *forwarded* response so a fresh
    cookie probe observes the hardened cookie.

    `op` is the enforcement primitive, not an observation:
      add_flag     -> append the valueless flag (`HttpOnly` / `Secure`) if absent
      remove_flag  -> drop the valueless flag if present
      set_samesite -> set/replace ``SameSite=<value>``

    `cookie_name` empty means "every Set-Cookie on this route".
    """

    method: str
    path: str
    cookie_name: str
    op: str
    flag: str = ""
    value: str = ""


def _rewrite_cookie(value: str, rules) -> str:
    """Pure: apply the applicable cookie-attribute mutations to one line."""
    segments = [seg.strip() for seg in value.split(";")]
    head = segments[0]
    attrs = [seg for seg in segments[1:] if seg]
    for rule in rules:
        if rule.op == "add_flag":
            flag = rule.flag
            if flag and not any(a.lower() == flag.lower() for a in attrs):
                attrs.append(flag)
        elif rule.op == "remove_flag":
            flag = rule.flag
            attrs = [a for a in attrs if a.lower() != flag.lower()]
        elif rule.op == "set_samesite":
            replaced = False
            new_attrs = []
            for a in attrs:
                if "=" in a and a.split("=", 1)[0].strip().lower() == "samesite":
                    new_attrs.append(f"SameSite={rule.value}")
                    replaced = True
                else:
                    new_attrs.append(a)
            if not replaced:
                new_attrs.append(f"SameSite={rule.value}")
            attrs = new_attrs
    return "; ".join([head, *attrs])


def apply_cookie_mutations(resp_headers, method, path, cookie_rules):
    """
    Pure: return a new ``[(name, value), ...]`` list with the corrective
    cookie-attribute mutations for this method+path applied to matching
    ``Set-Cookie`` headers. No security verdict is made here — this only
    hardens the cookie the way the operator's declared posture requires, so
    the deterministic judge can re-decide honestly. Duplicate ``Set-Cookie``
    headers are preserved (each is rewritten independently).
    """
    method_norm = (method or "").strip().upper()
    path_norm = path or ""
    active = [
        rule
        for rule in cookie_rules
        if rule.method.strip().upper() == method_norm
        and rule.path == path_norm
    ]
    if not active:
        return list(resp_headers)

    result = []
    for name, value in resp_headers:
        if name.lower() != "set-cookie":
            result.append((name, value))
            continue
        cookie_name = value.split(";", 1)[0].split("=", 1)[0].strip()
        applicable = [
            rule
            for rule in active
            if not rule.cookie_name or rule.cookie_name == cookie_name
        ]
        if not applicable:
            result.append((name, value))
            continue
        result.append((name, _rewrite_cookie(value, applicable)))
    return result


# Request-guard signature families (virtual patch). Each family is a tuple of
# payload-SHAPE patterns — never target-specific logic. The guard refuses to
# forward a request whose guarded parameter carries a signature from its family,
# BEFORE it reaches the upstream, so a fresh differential through the shield
# collapses and the pure judge can observe the fix. Nothing here decides a
# vulnerability; it only blocks a malicious request shape. One guard, many
# classes: a class picks its family by name on the RequestGuardRule.
# Matching is case-insensitive on the URL-decoded value.

# SQL injection — boolean-tautology / boolean-contradiction / UNION / comment.
_SQLI_SIGNATURES = (
    # quoted boolean: ' OR '1'='1  /  ") AND ("1"="2  /  ')) OR (('1'='1
    re.compile(r"""['"]\s*\)*\s*(or|and)\s*\(*\s*['"]?\s*\d""", re.IGNORECASE),
    # numeric boolean: OR 1=1 / AND 1=2
    re.compile(r"""\b(or|and)\b\s+\d+\s*=\s*\d""", re.IGNORECASE),
    # trivial tautology/contradiction: '1'='1  /  "2"="2
    re.compile(r"""['"]\s*\d+\s*['"]?\s*=\s*['"]?\s*\d""", re.IGNORECASE),
    # UNION-based extraction
    re.compile(r"""\bunion\b(\s+all)?\s+\bselect\b""", re.IGNORECASE),
    # SQL comment / statement terminators used to truncate the original query
    re.compile(r"""(--\s|#|/\*)"""),
)

# Template injection (SSTI) — server-side template expression delimiters.
_SSTI_SIGNATURES = (
    re.compile(r"\{\{.*?\}\}", re.DOTALL),   # Jinja2 / Twig / Angular  {{ 7*7 }}
    re.compile(r"\$\{.*?\}", re.DOTALL),     # JSP EL / Freemarker / JS  ${7*7}
    re.compile(r"#\{.*?\}", re.DOTALL),      # Ruby / Thymeleaf / JSF    #{7*7}
    re.compile(r"<%.*?%>", re.DOTALL),       # ERB / JSP scriptlet       <%= 7*7 %>
    re.compile(r"\{%.*?%\}", re.DOTALL),     # Jinja2 / Twig statement   {% ... %}
)

# Cross-site scripting — markup/JS breakout shapes.
_XSS_SIGNATURES = (
    re.compile(r"</?\s*script", re.IGNORECASE),   # <script> / </script>
    re.compile(r"<\s*(svg|img|iframe|body|input)", re.IGNORECASE),
    re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE),  # onload= / onerror= handlers
    re.compile(r"javascript:", re.IGNORECASE),
)

# Path traversal / LFI — directory-escape and OS-canary shapes.
_TRAVERSAL_SIGNATURES = (
    re.compile(r"\.\.[\\/]"),                 # ../  or  ..\
    re.compile(r"%2e%2e", re.IGNORECASE),     # encoded ..
    re.compile(r"%252e", re.IGNORECASE),      # double-encoded .
    re.compile(r"\x00"),                      # null-byte truncation
    re.compile(r"(etc/passwd|boot\.ini|win\.ini)", re.IGNORECASE),
)

_REGEX_FAMILIES: dict[str, tuple] = {
    "sqli": _SQLI_SIGNATURES,
    "ssti": _SSTI_SIGNATURES,
    "xss": _XSS_SIGNATURES,
    "traversal": _TRAVERSAL_SIGNATURES,
}

# Families whose family name in remediation metadata carries a descriptive
# suffix (e.g. "sql_injection_boolean_union_comment") still resolve here by
# prefix so a class need not know the exact registry key.
_FAMILY_ALIASES = {
    "sql_injection_boolean_union_comment": "sqli",
    "sql": "sqli",
    "template": "ssti",
    "template_injection": "ssti",
    "cross_site_scripting": "xss",
    "path_traversal": "traversal",
    "lfi": "traversal",
}


def _resolve_family(family: str) -> str:
    """Map a declared signature-family label to a registry key."""
    if not family:
        return "sqli"
    key = family.strip().lower()
    if key in _REGEX_FAMILIES or key in ("url_allowlist", "jwt"):
        return key
    return _FAMILY_ALIASES.get(key, key)


def _host_of(value: str) -> str:
    """Pure: the lowercased host of an absolute URL, else '' (relative/no host)."""
    try:
        return (urlsplit(value.strip()).hostname or "").lower()
    except (ValueError, AttributeError):
        return ""


def _matches_url_allowlist(value: str, allow) -> bool:
    """
    Pure: True (deny) when `value` is an absolute off-origin URL whose host is
    NOT in `allow`. Relative paths and empty values carry no host and are never
    denied (they cannot redirect/fetch off-origin). Inverted vs the regex
    families: this is an allowlist, so the DEFAULT for a foreign host is deny.
    """
    if not value:
        return False
    host = _host_of(value)
    if not host:
        return False  # relative path / same-origin — nothing to block
    allowed = {str(h).strip().lower() for h in (allow or ())}
    return host not in allowed


def _decode_jwt_alg(token: str):
    """Pure: best-effort ('alg', has_signature) from a compact JWS, else (None, None)."""
    import base64

    parts = token.strip().split(".")
    if len(parts) not in (2, 3):
        return None, None
    header_seg = parts[0]
    has_signature = len(parts) == 3 and parts[2] != ""
    pad = "=" * (-len(header_seg) % 4)
    try:
        raw = base64.urlsafe_b64decode(header_seg + pad)
        header = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, TypeError):
        return None, has_signature
    if not isinstance(header, dict):
        return None, has_signature
    return str(header.get("alg", "")).lower(), has_signature


def _matches_jwt_forgery(value: str) -> bool:
    """
    Pure: True (deny) when `value` carries a forged/unsafe JWT — `alg=none`
    (or any unsigned/empty-signature token). A well-formed signed token with a
    real algorithm is forwarded; the pure judge then re-decides. This blocks the
    forgery shape, not a specific secret.
    """
    if not value or "." not in value:
        return False
    # Pull the token out of a possible "Bearer <jwt>" wrapper.
    token = value.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    alg, has_signature = _decode_jwt_alg(token)
    if alg is None and has_signature is None:
        return False  # not a JWT shape
    if alg in ("none", ""):
        return True
    if has_signature is False:
        return True
    return False


def _matches_signature(value: str, family: str, allow=()) -> bool:
    """Pure: True when `value` carries a signature from the named family."""
    if not value:
        # url_allowlist and regex families never match empty; jwt likewise.
        return False
    resolved = _resolve_family(family)
    if resolved == "url_allowlist":
        return _matches_url_allowlist(value, allow)
    if resolved == "jwt":
        return _matches_jwt_forgery(value)
    patterns = _REGEX_FAMILIES.get(resolved)
    if not patterns:
        return False
    return any(pattern.search(value) for pattern in patterns)


def _matches_sqli_signature(value: str) -> bool:
    """Pure: True when a parameter value carries a SQL-injection signature.

    Back-compat shim over the generalised :func:`_matches_signature`.
    """
    return _matches_signature(value, "sqli")


@dataclass(frozen=True)
class RequestGuardRule:
    """
    A provider-agnostic request-guard (virtual patch) for one injectable
    parameter on a route. The shield inspects the REQUEST — the value of
    `param` in the declared `location` — and refuses to forward it (403) when
    it carries a signature from its `signature_family`, BEFORE the request ever
    reaches the upstream.

    `location` is one of:
      query      -> the parameter is read from the URL query string
      body_form  -> the parameter is read from an urlencoded request body
      body_json  -> the parameter is a top-level key of a JSON request body

    `signature_family` selects the payload-shape family to block — one guard,
    many vulnerability classes:
      sqli          -> SQL-injection boolean/UNION/comment shapes (default)
      ssti          -> server-side template expression delimiters
      xss           -> markup / JS breakout shapes
      traversal     -> directory-escape / OS-canary shapes
      url_allowlist -> INVERTED: deny an off-origin URL whose host is not in
                       `allow` (open-redirect / SSRF egress control)
      jwt           -> deny a forged/unsigned token (alg=none / no signature)

    `allow` is consulted only by the `url_allowlist` family (the set of hosts
    permitted as a redirect/fetch target).

    `param` empty means "guard every parameter in this location". This is a
    stop-gap gateway control; the durable fix lives in the handler. Nothing here
    interprets a response — it only blocks a malicious request shape so the
    deterministic judge can prove the differential is gone.
    """

    method: str
    path: str
    param: str = ""
    location: str = "query"
    signature_family: str = "sqli"
    allow: tuple = ()


def _guard_candidate_values(
    rule: "RequestGuardRule",
    query: str,
    body: bytes | None,
) -> list[str]:
    """Pure: the parameter values a guard rule must inspect for this request."""
    values: list[str] = []
    if rule.location == "query":
        parsed = parse_qs(query or "", keep_blank_values=True)
        source = parsed
    elif rule.location == "body_form":
        text = body.decode("utf-8", "replace") if body else ""
        source = parse_qs(text, keep_blank_values=True)
    elif rule.location == "body_json":
        text = body.decode("utf-8", "replace") if body else ""
        try:
            decoded = json.loads(text) if text else {}
        except (ValueError, TypeError):
            decoded = {}
        source = {}
        if isinstance(decoded, dict):
            for key, val in decoded.items():
                source[str(key)] = [val if isinstance(val, str) else json.dumps(val)]
    else:
        return values

    if rule.param:
        values.extend(str(v) for v in source.get(rule.param, ()))
    else:
        for entry in source.values():
            values.extend(str(v) for v in entry)
    return values


def evaluate_request_guard(method, path, query, body, guard_rules) -> str:
    """
    Pure request-side decision for the request-guard virtual patch.

    Returns ``"deny"`` when any guard rule matches this method+path and the
    guarded parameter value carries a signature from that rule's
    ``signature_family``, else ``"forward"``. It inspects only the REQUEST
    (query/body), never a response, so it cannot manufacture a verdict — it only
    refuses to relay a malicious request shape, which is exactly what collapses
    the differential the pure judge then re-measures. One guard covers every
    class (sqli / ssti / xss / traversal / url_allowlist / jwt).
    """
    method_norm = (method or "").strip().upper()
    path_norm = path or ""
    for rule in guard_rules:
        if rule.method.strip().upper() != method_norm:
            continue
        if rule.path != path_norm:
            continue
        family = getattr(rule, "signature_family", "sqli")
        allow = getattr(rule, "allow", ())
        for value in _guard_candidate_values(rule, query, body):
            if _matches_signature(value, family, allow):
                return "deny"
    return "forward"


class _EnforcementServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address,
        handler,
        *,
        rules,
        upstream_base,
        header_rules=(),
        cookie_rules=(),
        guard_rules=(),
    ):
        super().__init__(address, handler)
        self.rules = tuple(rules)
        self.header_rules = tuple(header_rules)
        self.cookie_rules = tuple(cookie_rules)
        self.guard_rules = tuple(guard_rules)
        parsed = urlsplit(upstream_base)
        self.upstream_scheme = (parsed.scheme or "http").lower()
        self.upstream_netloc = parsed.netloc
        self.upstream_base = f"{self.upstream_scheme}://{self.upstream_netloc}"


def _json_response(handler, code: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(body)


class _EnforcementHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 with explicit Content-Length + Connection: close on every
    # response keeps the tiny proxy correct without keep-alive bookkeeping.
    protocol_version = "HTTP/1.1"

    def log_message(self, *args, **kwargs):  # keep the CLI output clean
        return

    def _handle(self):
        server = self.server
        split = urlsplit(self.path)
        # The request body is read exactly ONCE here (self.rfile is single-use)
        # and then handed to both the request-guard and the forwarder.
        body = self._read_body()

        decision = evaluate_request(
            server.rules,
            self.command,
            split.path,
            self.headers,
        )
        if decision == "deny":
            _json_response(
                self,
                403,
                {"error": "Forbidden", "by": "sentinel-remediation"},
            )
            return

        # Request-guard / virtual patch (injection remediation): inspect the
        # request's own query/body and refuse to forward an injection signature
        # BEFORE it reaches the upstream. Access-control denial (above) is a
        # different, header-based decision and is unaffected.
        if server.guard_rules:
            guard = evaluate_request_guard(
                self.command,
                split.path,
                split.query,
                body,
                server.guard_rules,
            )
            if guard == "deny":
                _json_response(
                    self,
                    403,
                    {
                        "error": "Forbidden",
                        "by": "sentinel-remediation",
                        "reason": "request-guard",
                    },
                )
                return

        self._forward(server, body)

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if length is None:
            return None
        try:
            count = int(length)
        except (TypeError, ValueError):
            return None
        return self.rfile.read(count) if count > 0 else None

    def _forward(self, server, body):
        # self.path preserves the exact path + query; the host is fixed to
        # the single upstream this enforcer was constructed with. The body was
        # already read once by _handle and is passed in here.
        upstream_url = server.upstream_base + self.path

        forwarded = {}
        for name, value in self.headers.items():
            lname = name.lower()
            if lname in _HOP_BY_HOP or lname == "host":
                continue
            forwarded[name] = value
        forwarded["Host"] = server.upstream_netloc

        request = Request(
            upstream_url,
            data=body,
            headers=forwarded,
            method=self.command,
        )

        try:
            with urlopen(request, timeout=10) as response:
                status = response.status
                resp_headers = list(response.headers.items())
                resp_body = response.read()
        except HTTPError as exc:
            status = exc.code
            resp_headers = list(exc.headers.items())
            resp_body = exc.read()
        except (URLError, OSError) as exc:
            _json_response(
                self,
                502,
                {
                    "error": "Bad Gateway",
                    "detail": str(exc),
                    "by": "sentinel-remediation",
                },
            )
            return

        # Corrective response-header mutations (posture remediation): the
        # forwarded response is rewritten to satisfy the operator's declared
        # header posture so a fresh probe through the shield observes the
        # corrected headers. Access-control denial (above) is unaffected.
        if server.header_rules:
            split = urlsplit(self.path)
            resp_headers = apply_header_mutations(
                resp_headers,
                self.command,
                split.path,
                server.header_rules,
            )

        # Corrective cookie-attribute mutations (insecure-cookie remediation):
        # matching Set-Cookie headers are hardened (HttpOnly / Secure /
        # SameSite) so a fresh cookie probe through the shield observes the
        # corrected cookie. Duplicate Set-Cookie lines are preserved.
        if server.cookie_rules:
            split = urlsplit(self.path)
            resp_headers = apply_cookie_mutations(
                resp_headers,
                self.command,
                split.path,
                server.cookie_rules,
            )

        self.send_response_only(status)
        # The shield must not stamp its OWN identity onto the forwarded
        # response. Unlike send_response(), send_response_only() adds no
        # automatic Server/Date header — so a `remove`/`remove_if_equals`
        # posture fix (e.g. stripping an information-disclosing Server header)
        # actually proves out, instead of being silently masked by the proxy
        # re-introducing the very header it was asked to remove.
        has_date = any(name.lower() == "date" for name, _ in resp_headers)
        for name, value in resp_headers:
            lname = name.lower()
            if lname in _HOP_BY_HOP or lname == "content-length":
                continue
            self.send_header(name, value)
        if not has_date:
            self.send_header("Date", self.date_time_string())
        self.send_header("Content-Length", str(len(resp_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(resp_body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle

class RemediationEnforcer:
    """
    A live, provider-agnostic enforcement shield.

    Wraps a threaded HTTP reverse proxy bound to an ephemeral loopback
    port. It denies exactly what the supplied rule(s) forbid and forwards
    every other request to the fixed ``upstream_base``. Use as a context
    manager so the listener is always torn down::

        with RemediationEnforcer(rule, upstream_base) as shield:
            probe(shield.base_url + path)

    The proxy is unauthenticated but reachable only on 127.0.0.1 via a
    random port, exists solely for the duration of one verification, and
    can never reach any host other than the engagement target.
    """

    def __init__(self, rules, upstream_base: str, *, header_rules=(), cookie_rules=(), guard_rules=()):
        if isinstance(rules, AccessControlRule):
            rules = (rules,)
        if isinstance(header_rules, ResponseHeaderRule):
            header_rules = (header_rules,)
        if isinstance(cookie_rules, CookieAttributeRule):
            cookie_rules = (cookie_rules,)
        if isinstance(guard_rules, RequestGuardRule):
            guard_rules = (guard_rules,)
        self._server = _EnforcementServer(
            ("127.0.0.1", 0),
            _EnforcementHandler,
            rules=rules,
            upstream_base=upstream_base,
            header_rules=header_rules,
            cookie_rules=cookie_rules,
            guard_rules=guard_rules,
        )
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "RemediationEnforcer":
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name="sentinel-remediation-enforcer",
                daemon=True,
            )
            self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "RemediationEnforcer":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.stop()
        return False
