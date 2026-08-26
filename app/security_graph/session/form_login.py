"""Headless HTTP form-login — capture a genuine session token from credentials.

Sentinel's broken_auth class needs ONE live input: a genuine session token to
forge FROM. The browser Login Tester (:mod:`.browser_login`) captures that from a
real, VISIBLE browser — the right tool for an MFA/SPA flow a human drives. But a
classic server-rendered form login (the shape most PortSwigger labs and legacy
apps use) needs no browser at all: fetch the login page, read its ``<form>``, POST
the credentials through a cookie jar, and read the session token straight off the
response.

This module makes that capture a FIRST-CLASS Sentinel capability, so the
autonomous command can log in INDEPENDENTLY — given credentials and a login URL —
with no external driver script. It is pure/deterministic given an injected HTTP
client (the real one is a scoped :class:`requests.Session`), so the whole thing is
offline-testable with zero network.

The credentials drive the live form and are held in memory for the request only:
never logged, never echoed, never written to disk. The captured token is equally
secret — surfaced only as PRESENCE (a token-safe ``note``), its VALUE bound solely
into the broken_auth principal headers downstream and never into a log or a note.
Nothing here decides a verdict: it produces an OBSERVATION (a token) the pure judge
later tests through the three-probe control/breach/baseline differential.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
import json

from .browser_login import SESSION_COOKIE_NAMES


class LoginCaptureError(RuntimeError):
    """Raised when a credential login cannot be driven to a captured session."""


# Input names that hint at the username/identifier field. Used ONLY to fill the
# right field — never to assert anything; the pure judge still decides every
# downstream verdict.
_USER_FIELD_HINTS = ("user", "email", "login", "account", "identifier", "uname")

# Input `type`s that can NEVER hold a typed username/identifier. Everything else
# — text, email, tel, an unspecified type, or a non-standard one such as the
# PortSwigger-ism ``type=username`` — is a legitimate candidate. We exclude the
# impossible rather than allow-list the expected, so a real login form's quirky
# input type never silently drops the username field.
_NON_USER_INPUT_TYPES = frozenset({
    "password", "hidden", "checkbox", "radio", "submit", "button",
    "file", "image", "reset", "range", "color",
})

# Response-body keys a SPA/JSON login commonly parks a bearer/JWT under.
_BEARER_KEYS = ("token", "access_token", "accesstoken", "jwt", "authtoken",
                "auth_token", "id_token", "idtoken", "bearer")

# ---- login form (pure HTML parse) -------------------------------------------


@dataclass(frozen=True)
class LoginForm:
    """One login ``<form>`` reconstructed from HTML: where to POST + what to send.

    ``data`` carries every OTHER named field verbatim (hidden CSRF tokens, flow
    ids, prefilled values) so the POST looks exactly like the browser's would.
    """

    action: str
    method: str = "POST"
    data: dict = field(default_factory=dict)
    username_field: str = ""
    password_field: str = ""

    def payload(self, username: str, password: str) -> dict:
        """The full form body to POST: carried fields + the two credentials."""
        body = dict(self.data)
        if self.username_field:
            body[self.username_field] = username
        if self.password_field:
            body[self.password_field] = password
        return body


class _FormParser(HTMLParser):
    """Collect every ``<form>`` and its named inputs. Forms do not nest in HTML,
    so a single ``_current`` cursor is sufficient and robust."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current = {"attrs": a, "inputs": []}
            self.forms.append(self._current)
        elif tag in ("input", "textarea", "select") and self._current is not None:
            self._current["inputs"].append(
                {
                    "name": a.get("name", ""),
                    "type": a.get("type", "text").lower(),
                    "value": a.get("value", ""),
                }
            )

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None


def _choose_username_field(inputs: list[dict], password_index: int) -> str:
    """Pick the field to fill with the username. Preference order: an explicit
    email input, then a hint-named fillable input, then the last fillable named
    input appearing BEFORE the password (the classic username-above-password).
    "Fillable" excludes only the types that can never hold a typed identifier
    (password/hidden/checkbox/...), so a non-standard ``type=username`` still
    wins rather than being silently skipped."""
    for inp in inputs:
        if inp["type"] == "email" and inp["name"]:
            return inp["name"]
    for inp in inputs:
        if (inp["name"] and inp["type"] not in _NON_USER_INPUT_TYPES
                and any(h in inp["name"].lower() for h in _USER_FIELD_HINTS)):
            return inp["name"]
    chosen = ""
    for idx, inp in enumerate(inputs):
        if idx >= password_index:
            break
        if inp["name"] and inp["type"] not in _NON_USER_INPUT_TYPES:
            chosen = inp["name"]
    return chosen


def find_login_form(html: str, page_url: str) -> "LoginForm | None":
    """Locate the login form in ``html`` — the first ``<form>`` carrying a named
    password input. Returns ``None`` when no such form exists (an honest miss, so
    the caller can try another URL rather than POST to the wrong place)."""
    parser = _FormParser()
    try:
        parser.feed(html or "")
    except Exception:  # noqa: BLE001 — a malformed page is a miss, never a crash
        return None

    for form in parser.forms:
        inputs = form["inputs"]
        password_index = None
        password_field = ""
        for idx, inp in enumerate(inputs):
            if inp["type"] == "password" and inp["name"]:
                password_index, password_field = idx, inp["name"]
                break
        if not password_field:
            continue

        username_field = _choose_username_field(inputs, password_index)
        data = {
            inp["name"]: inp["value"]
            for inp in inputs
            if inp["name"] and inp["name"] not in (password_field, username_field)
        }
        action = urljoin(page_url, form["attrs"].get("action", "") or page_url)
        method = (form["attrs"].get("method", "POST") or "POST").upper()
        return LoginForm(action=action, method=method, data=data,
                         username_field=username_field, password_field=password_field)
    return None


# ---- captured session -------------------------------------------------------


@dataclass(frozen=True)
class CredentialSession:
    """The in-memory result of one headless login. Never persisted, never logged.

    ``cookies`` are the ``(name, value)`` pairs from the jar after login; ``bearer``
    is an optional token read from a JSON response body. ``note`` reports only
    PRESENCE (counts/kinds) and is safe to display — it never carries a value.
    """

    cookies: tuple = ()          # tuple[(name, value), ...]
    bearer: "str | None" = None
    final_url: str = ""
    note: str = ""

    def token_for(self, location=None) -> "str | None":
        """The bare token to forge FROM, read from the SAME place the app carries
        it (the matrix's declared :class:`TokenLocation`). A cookie location returns
        the named cookie (else any session-like cookie); a header/bearer location
        (or none) prefers a captured bearer, then a session-like cookie. Returns
        ``None`` when nothing usable was captured — an honest skip, never a guess."""
        kind = getattr(location, "kind", None)
        name = getattr(location, "name", None)
        if kind == "cookie":
            if name:
                for cookie_name, value in self.cookies:
                    if cookie_name == name:
                        return value
            return self._session_like_cookie()
        if self.bearer:
            return self.bearer
        return self._session_like_cookie()

    def _session_like_cookie(self) -> "str | None":
        for cookie_name, value in self.cookies:
            if cookie_name.strip().lower() in SESSION_COOKIE_NAMES:
                return value
        return None


def _capture_note(cookies, bearer) -> str:
    """A token-SAFE one-liner: counts and kinds only, never a value."""
    bits = []
    if cookies:
        bits.append(f"{len(cookies)} cookie(s)")
    if bearer:
        bits.append("bearer")
    return "captured " + " + ".join(bits) if bits else "no session credential captured"


# ---- HTTP seam + driver -----------------------------------------------------


def _origin(url: str) -> str:
    sp = urlsplit(url if "://" in (url or "") else f"http://{url or ''}")
    return f"{sp.scheme}://{sp.netloc}" if sp.netloc else ""


def _default_login_url(target: str) -> str:
    """The overwhelmingly common convention: ``<origin>/login``."""
    origin = _origin(target)
    return f"{origin}/login" if origin else ""


class _RequestsClient:
    """Default LIVE client: a :class:`requests.Session` (cookie jar + redirects)
    scoped to the login host. Refuses a non-HTTP scheme or an out-of-scope host on
    the explicitly-issued request, exactly like the probe executor's scope guard."""

    def __init__(self, *, allowed_host: "str | None" = None, timeout: float = 30.0):
        import requests  # lazy: keep the dep off the core hot path

        self._session = requests.Session()
        self._allowed_host = (allowed_host or "").lower() or None
        self._timeout = timeout

    def _check(self, url: str) -> None:
        sp = urlsplit(url)
        if sp.scheme.lower() not in ("http", "https"):
            raise LoginCaptureError(
                f"refusing non-HTTP scheme for login: {sp.scheme or 'none'}")
        if self._allowed_host and sp.netloc.lower() != self._allowed_host:
            raise LoginCaptureError(
                f"refusing out-of-scope login host: {sp.netloc or 'none'} "
                f"(in scope: {self._allowed_host})")

    def get(self, url: str):
        self._check(url)
        return self._session.get(url, timeout=self._timeout, allow_redirects=True)

    def post(self, url: str, data: dict):
        self._check(url)
        return self._session.post(url, data=data, timeout=self._timeout,
                                  allow_redirects=True)

    @property
    def cookies(self) -> dict:
        return {c.name: c.value for c in self._session.cookies}


def _text_of(response) -> str:
    return getattr(response, "text", "") or ""


def _url_of(response, fallback: str) -> str:
    return getattr(response, "url", "") or fallback


def _extract_bearer_from_body(text: str) -> "str | None":
    """Best-effort read of a bearer/JWT from a JSON login response. Returns ``None``
    for a non-JSON body or when no token-like key is present (an honest miss)."""
    text = (text or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if (isinstance(value, str) and value.strip()
                        and str(key).strip().lower() in _BEARER_KEYS):
                    token = value.strip()
                    if token.lower().startswith("bearer "):
                        token = token[7:].strip()
                    if token:
                        return token
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
    return None


def capture_login_session(login_url, *, username, password, http=None,
                          target=None, timeout=30.0) -> CredentialSession:
    """Drive a headless HTTP form login and capture the resulting session.

    GET the login page, locate its ``<form>`` (falling back to ``<origin>/login``
    if the entry page has none), POST the credentials with every carried field
    (CSRF/hidden included) through a cookie jar, and read the session token off the
    response. ``http`` is an injectable client seam (``.get`` / ``.post`` /
    ``.cookies``) so this is offline-testable; the real default is a host-scoped
    :class:`requests.Session`. Raises :class:`LoginCaptureError` when no login form
    can be found. Credentials are used only to fill the live form — never logged."""
    entry = (login_url or "").strip()
    if not entry and target:
        entry = _default_login_url(target)
    if not entry:
        raise LoginCaptureError(
            "no login URL supplied and no target to derive one from")

    client = http
    if client is None:
        host = urlsplit(entry if "://" in entry else f"http://{entry}").netloc.lower()
        client = _RequestsClient(allowed_host=host, timeout=timeout)

    page = client.get(entry)
    form = find_login_form(_text_of(page), _url_of(page, entry))
    if form is None:
        fallback = _default_login_url(entry)
        if fallback and fallback != entry:
            page = client.get(fallback)
            form = find_login_form(_text_of(page), _url_of(page, fallback))
    if form is None:
        raise LoginCaptureError(
            "no login form with a password field found at the login URL")

    response = client.post(form.action, form.payload(username, password))

    cookies = tuple((str(name), str(value))
                    for name, value in (client.cookies or {}).items())
    bearer = _extract_bearer_from_body(_text_of(response))
    return CredentialSession(
        cookies=cookies,
        bearer=bearer,
        final_url=_url_of(response, form.action),
        note=_capture_note(cookies, bearer),
    )
