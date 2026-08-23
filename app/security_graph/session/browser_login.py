"""
Login Tester — drive a real browser, wait for MFA, capture the session.

Sentinel's anonymous research proves *what an unauthenticated caller can
reach*. Real broken-access-control and the chaining that follows almost always
live *behind* a login. This module turns anonymous scanning into authenticated
reasoning without ever weakening the epistemic contract:

  * the operator types their own credentials (via ``getpass`` in the command —
    never stored, never logged, held in memory for the run only);
  * Sentinel opens a **visible** browser, best-effort auto-fills the login form,
    and then **waits** — polling for a session signal while a background thread
    lets the operator press Enter the moment they finish MFA (auto-detect +
    manual fallback, first signal wins);
  * once authenticated it captures the real ``context.cookies()`` — each cookie
    carrying its genuine ``httpOnly`` / ``secure`` / ``sameSite`` as the browser
    saw it — plus any bearer token the SPA stashed in ``localStorage``;
  * the browser is kept open during the subsequent test run and auto-closed when
    testing completes (or the operator closes it).

Playwright is an **opt-in extra** (``pip install -e ".[login]"``); it is
imported lazily so the core REPL never pays for it and degrades with a clear,
actionable error when the browser stack is absent.

Nothing here invents a finding. The captured cookies are *observations*; the
pure judge still decides every verdict downstream. Cookie oracles built from a
captured session are grounded in exactly the ``Set-Cookie`` the browser
observed, faithfully reconstructed — never guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


# Cookie names operators overwhelmingly use for a session/auth credential. Used
# ONLY as an auto-detect hint and to scope the advisory hardening baseline — it
# never asserts a finding. The pure judge still decides against observed flags.
SESSION_COOKIE_NAMES = frozenset(
    {
        "token",
        "session",
        "sessionid",
        "session_id",
        "sid",
        "jsessionid",
        "phpsessid",
        "asp.net_sessionid",
        "connect.sid",
        "auth",
        "authtoken",
        "auth_token",
        "access_token",
        "jwt",
        "csrftoken",
        "csrf_token",
        "xsrf-token",
        "remember_token",
        "continuecode",
    }
)

# Path fragments that indicate we are still on an auth/login/MFA step, so a URL
# containing one is NOT yet treated as "authenticated".
_AUTH_PATH_HINTS = ("login", "signin", "sign-in", "auth", "mfa", "otp", "2fa", "sso")


@dataclass(frozen=True)
class CapturedCookie:
    """One cookie exactly as the authenticated browser context reported it."""

    name: str
    value: str
    domain: str = ""
    path: str = "/"
    http_only: bool = False
    secure: bool = False
    same_site: str = ""  # "Strict" | "Lax" | "None" | "" (unset)


@dataclass(frozen=True)
class CapturedSession:
    """
    The in-memory result of one login. Never persisted, never logged.

    ``cookie_header`` is the ``Cookie:`` request header a probe replays to act
    as the authenticated principal; ``bearer`` is an optional localStorage
    token; ``cookies`` are the raw observed cookies (used to build a grounded
    cookie oracle for the insecure-cookie class).
    """

    cookie_header: str = ""
    bearer: str | None = None
    cookies: tuple[CapturedCookie, ...] = ()
    final_url: str = ""


def is_authenticated_signal(
    cookie_names,
    current_url: str,
    *,
    login_url: str | None = None,
) -> bool:
    """
    PURE MFA/login-done predicate (browser-free, unit-testable).

    Authenticated when either a session-like cookie is present, or navigation
    has clearly left the auth/login/MFA surface. Conservative: a URL still on
    an auth path is never treated as done on the URL signal alone.
    """
    names = {str(name).strip().lower() for name in cookie_names if str(name).strip()}
    if names & SESSION_COOKIE_NAMES:
        return True

    url = (current_url or "").strip().lower()
    if not url:
        return False

    path = urlsplit(url).path or "/"
    if any(hint in path for hint in _AUTH_PATH_HINTS):
        return False

    if login_url:
        login_path = urlsplit(login_url.strip().lower()).path or "/"
        # Left the exact login path for a different, non-auth page ⇒ signal.
        if login_path not in ("", "/") and path != login_path:
            return True
        # Login lived at root: any move to a deeper, non-auth path counts.
        if login_path in ("", "/") and path not in ("", "/"):
            return True
        return False

    # No login_url reference: a non-auth, non-root path is a reasonable signal.
    return path not in ("", "/")


def reconstruct_set_cookie(cookie: CapturedCookie) -> str:
    """
    Faithfully serialise an observed cookie back into a ``Set-Cookie`` line.

    This reflects EXACTLY the attributes the browser reported — it adds nothing
    the session did not carry — so the cookie judge measures real posture, not
    an invented one.
    """
    parts = [f"{cookie.name}={cookie.value}"]
    if cookie.path:
        parts.append(f"Path={cookie.path}")
    if cookie.domain:
        parts.append(f"Domain={cookie.domain}")
    if cookie.http_only:
        parts.append("HttpOnly")
    if cookie.secure:
        parts.append("Secure")
    if cookie.same_site:
        parts.append(f"SameSite={cookie.same_site}")
    return "; ".join(parts)


def cookie_header_from(cookies) -> str:
    """Build a replayable ``Cookie:`` request header from captured cookies."""
    pairs = [f"{c.name}={c.value}" for c in cookies if c.name]
    return "; ".join(pairs)


def _normalize_same_site(raw) -> str:
    """Map Playwright's sameSite ('Strict'|'Lax'|'None') to our canonical form."""
    text = str(raw or "").strip().lower()
    return {"strict": "Strict", "lax": "Lax", "none": "None"}.get(text, "")


class LoginDependencyError(RuntimeError):
    """Raised when the opt-in browser stack is unavailable, with a fix hint."""


_INSTALL_HINT = (
    "The Login Tester needs the opt-in browser extra. Install it once with:\n"
    '    pip install -e ".[login]"\n'
    "    python -m playwright install chromium\n"
    "then re-run `login`. (The core scanner never requires this.)"
)


def _autofill_login(page, username: str, password: str) -> None:
    """Best-effort fill of a standard login form. Silent on any miss."""
    for selector in (
        "input[type=email]",
        "input[name=email]",
        "input[id*=email i]",
        "input[type=text][name*=user i]",
        "input[type=text]",
    ):
        try:
            if page.locator(selector).count():
                page.fill(selector, username, timeout=2000)
                break
        except Exception:
            continue
    for selector in ("input[type=password]", "input[name=password]"):
        try:
            if page.locator(selector).count():
                page.fill(selector, password, timeout=2000)
                break
        except Exception:
            continue
    for selector in (
        "button[type=submit]",
        "button#loginButton",
        "button:has-text('Log in')",
        "button:has-text('Login')",
        "button:has-text('Sign in')",
    ):
        try:
            if page.locator(selector).count():
                page.click(selector, timeout=2000)
                return
        except Exception:
            continue


def _collect_cookies(context) -> tuple[CapturedCookie, ...]:
    out = []
    for raw in context.cookies():
        out.append(
            CapturedCookie(
                name=str(raw.get("name", "")),
                value=str(raw.get("value", "")),
                domain=str(raw.get("domain", "")),
                path=str(raw.get("path", "/")) or "/",
                http_only=bool(raw.get("httpOnly", False)),
                secure=bool(raw.get("secure", False)),
                same_site=_normalize_same_site(raw.get("sameSite")),
            )
        )
    return tuple(out)


def _extract_bearer(page) -> str | None:
    """Best-effort read of a bearer/JWT the SPA parked in localStorage."""
    try:
        keys = page.evaluate("Object.keys(window.localStorage)")
    except Exception:
        return None
    for key in keys or []:
        if not any(hint in str(key).lower() for hint in ("token", "jwt", "auth")):
            continue
        try:
            val = page.evaluate("k => window.localStorage.getItem(k)", key)
        except Exception:
            continue
        if isinstance(val, str) and val.strip():
            token = val.strip().strip('"')
            # Some SPAs prefix the scheme; keep only the raw credential.
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            return token or None
    return None


def capture_session(
    target: str,
    *,
    username: str,
    password: str,
    login_url: str | None = None,
    timeout: float = 300.0,
    poll_interval: float = 1.0,
    headless: bool = False,
    on_status=None,
    manual_done=None,
    keep_open_seconds: float = 0.0,
):
    """
    Open a real browser, log in, WAIT for MFA, and capture the session.

    Credentials are used only to drive the live form; they are never persisted
    or logged here. Returns a :class:`CapturedSession`. Raises
    :class:`LoginDependencyError` if the opt-in Playwright stack is missing.

    ``manual_done`` is an optional zero-arg callable returning ``True`` once the
    operator signals completion (the CLI wires this to an Enter-key thread);
    the auto-detect cookie/URL signal and this manual signal race — first wins.
    ``on_status`` is an optional ``callable(str)`` for progress narration.
    """
    import time

    def _say(message: str) -> None:
        if on_status is not None:
            on_status(message)

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001 — translate to an actionable error
        raise LoginDependencyError(_INSTALL_HINT) from exc

    entry = login_url or target
    deadline = time.monotonic() + max(1.0, timeout)

    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=headless)
        except Exception as exc:  # noqa: BLE001 — missing browser binary etc.
            raise LoginDependencyError(
                f"{_INSTALL_HINT}\n\n(browser launch failed: {exc})"
            ) from exc

        context = browser.new_context()
        page = context.new_page()
        try:
            _say(f"opening {entry}")
            page.goto(entry, wait_until="domcontentloaded", timeout=30000)
            _say("auto-filling credentials (finish login + MFA in the window)")
            _autofill_login(page, username, password)

            while True:
                if manual_done is not None and manual_done():
                    _say("manual completion signal received")
                    break
                try:
                    names = [c.get("name", "") for c in context.cookies()]
                    current = page.url
                except Exception:
                    names, current = [], ""
                if is_authenticated_signal(names, current, login_url=login_url):
                    _say("authenticated session detected")
                    break
                if time.monotonic() >= deadline:
                    _say("login wait timed out — capturing whatever is present")
                    break
                time.sleep(max(0.1, poll_interval))

            cookies = _collect_cookies(context)
            bearer = _extract_bearer(page)
            final_url = ""
            try:
                final_url = page.url
            except Exception:
                final_url = ""

            if keep_open_seconds > 0:
                _say(f"keeping the browser open for {keep_open_seconds:.0f}s")
                time.sleep(keep_open_seconds)

            return CapturedSession(
                cookie_header=cookie_header_from(cookies),
                bearer=bearer,
                cookies=cookies,
                final_url=final_url,
            )
        finally:
            try:
                context.close()
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass




