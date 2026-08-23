"""
Login Tester — capture a real authenticated browser session, then reason over
it with Sentinel's existing prove-chain (authenticated authz + insecure
cookies). Playwright is an opt-in extra imported lazily inside
:func:`browser_login.capture_session`.
"""

from .browser_login import (
    CapturedCookie,
    CapturedSession,
    LoginDependencyError,
    SESSION_COOKIE_NAMES,
    capture_session,
    cookie_header_from,
    is_authenticated_signal,
    reconstruct_set_cookie,
)
from .authenticated import (
    authenticated_policy,
    session_baseline_cookie_policy,
    session_headers,
)

__all__ = [
    "CapturedCookie",
    "CapturedSession",
    "LoginDependencyError",
    "SESSION_COOKIE_NAMES",
    "capture_session",
    "cookie_header_from",
    "is_authenticated_signal",
    "reconstruct_set_cookie",
    "authenticated_policy",
    "session_baseline_cookie_policy",
    "session_headers",
]
