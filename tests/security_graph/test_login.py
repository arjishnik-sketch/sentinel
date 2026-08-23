"""
Offline, network-free proof of the Login Tester's PURE pieces and its cookie
prove-path on a captured session. The real browser path is exercised only when
Playwright is installed AND ``SENTINEL_LIVE_BROWSER`` is set (a local stub
server, headless), so the suite stays green with or without the opt-in extra.

Nothing here contacts a real target. The captured cookies are fixtures standing
in for a genuine ``context.cookies()`` capture; the pure judge still decides
every verdict, and every corrective control is applied by the real
``apply_cookie_mutations`` primitive.
"""

import os

import pytest

from app.security_graph.graph import SecurityGraph
from app.security_graph.policy.access_policy import (
    AccessPolicy,
    PolicyPrincipal,
    PolicyRule,
)
from app.security_graph.session import (
    CapturedCookie,
    CapturedSession,
    authenticated_policy,
    cookie_header_from,
    is_authenticated_signal,
    privesc_policy_from_sessions,
    reconstruct_set_cookie,
    session_baseline_cookie_policy,
    session_headers,
)


def _session(*cookies, bearer=None, final_url=""):
    return CapturedSession(
        cookie_header=cookie_header_from(cookies),
        bearer=bearer,
        cookies=tuple(cookies),
        final_url=final_url,
    )


# --- pure: Set-Cookie reconstruction ---------------------------------------

def test_reconstruct_set_cookie_is_faithful_to_observed_flags():
    secure = CapturedCookie(
        name="token", value="abc", path="/", http_only=True,
        secure=True, same_site="Strict",
    )
    line = reconstruct_set_cookie(secure)
    assert line.startswith("token=abc")
    assert "HttpOnly" in line and "Secure" in line
    assert "SameSite=Strict" in line

    weak = CapturedCookie(name="token", value="abc", path="/")
    weak_line = reconstruct_set_cookie(weak)
    # Adds nothing the session did not carry.
    assert "HttpOnly" not in weak_line
    assert "Secure" not in weak_line
    assert "SameSite" not in weak_line


def test_cookie_header_joins_captured_pairs():
    header = cookie_header_from(
        [CapturedCookie("a", "1"), CapturedCookie("b", "2")]
    )
    assert header == "a=1; b=2"


# --- pure: MFA / login-done predicate --------------------------------------

def test_session_cookie_presence_signals_authenticated():
    assert is_authenticated_signal(["token"], "http://x/login", login_url="http://x/login")
    assert is_authenticated_signal(["JSESSIONID"], "http://x/anything")


def test_still_on_auth_path_is_not_authenticated():
    assert not is_authenticated_signal([], "http://x/login", login_url="http://x/login")
    assert not is_authenticated_signal([], "http://x/mfa", login_url="http://x/login")
    assert not is_authenticated_signal(["consent"], "http://x/2fa")


def test_leaving_login_path_signals_authenticated():
    assert is_authenticated_signal(
        [], "http://x/dashboard", login_url="http://x/login"
    )
    # Login at root: any deeper non-auth path counts.
    assert is_authenticated_signal([], "http://x/account", login_url="http://x/")


# --- pure: authenticated policy build (no decision rewriting) ---------------

def _base_policy():
    return AccessPolicy(
        principals=(PolicyPrincipal(name="anonymous", kind="anonymous"),),
        rules=(
            PolicyRule(
                principal="authenticated", method="GET", path="/api/me",
                action="read", decision="allow",
            ),
            PolicyRule(
                principal="anonymous", method="GET", path="/admin",
                action="read", decision="deny",
            ),
        ),
    )


def test_authenticated_policy_fills_headers_without_rewriting_rules():
    session = _session(
        CapturedCookie("token", "abc"), bearer="jwt.here.sig"
    )
    policy = authenticated_policy(_base_policy(), session)
    principal = policy.principal("authenticated")
    keys = {k for k, _ in principal.headers}
    assert "Cookie" in keys and "Authorization" in keys
    # Declared decisions and rule→principal bindings are untouched.
    assert policy.rules == _base_policy().rules
    assert any(
        r.principal == "anonymous" and r.decision == "deny"
        for r in policy.rules
    )


def test_authenticated_policy_none_without_operator_policy():
    session = _session(CapturedCookie("token", "abc"))
    assert authenticated_policy(None, session) is None


def test_session_headers_omit_absent_parts():
    only_cookie = _session(CapturedCookie("sid", "9"))
    assert dict(session_headers(only_cookie)) == {"Cookie": "sid=9"}
    nothing = _session()
    assert session_headers(nothing) == ()


# --- pure: advisory baseline is grounded in observed session cookies --------

def test_baseline_targets_only_session_like_cookies():
    session = _session(
        CapturedCookie("token", "abc"),           # session-like
        CapturedCookie("cookieconsent", "dismiss"),  # not session-like
    )
    payload = session_baseline_cookie_policy(session)
    names = {
        exp["cookie_name"]
        for rule in payload["cookie_rules"]
        for exp in rule["expectations"]
    }
    assert names == {"token"}


def test_baseline_empty_when_no_session_cookie():
    session = _session(CapturedCookie("language", "en"))
    assert session_baseline_cookie_policy(session) == {"cookie_rules": []}


# --- pure: bind LIVE logins to an operator login-matrix (by index) ----------

def _structure_only_matrix():
    """A login matrix that declares STRUCTURE only — no credentials in the file.

    Each principal owns a control endpoint it legitimately reaches; the check
    declares the boundary the attacker must not cross. No headers/tokens are
    ever written here — those arrive from a live browser login at run time.
    """
    from app.security_graph.privesc import parse_privesc_policy

    return parse_privesc_policy(
        {
            "privesc_matrix": {
                "principals": [
                    {"name": "alice",
                     "control": {"method": "GET", "path": "/rest/basket/1"},
                     "role": "user"},
                    {"name": "bob",
                     "control": {"method": "GET", "path": "/rest/basket/2"},
                     "role": "user"},
                ],
                "checks": [
                    {"type": "horizontal", "attacker": "alice", "victim": "bob",
                     "breach": {"method": "GET", "path": "/rest/basket/2"},
                     "severity": "HIGH"},
                ],
            }
        }
    )


def test_privesc_sessions_bind_headers_by_index():
    matrix = _structure_only_matrix()
    # Structure-only: the operator declared no credentials in the file.
    assert all(p.headers == () for p in matrix.principals)

    alice = _session(CapturedCookie("token", "AAA"), bearer="alice.jwt")
    bob = _session(CapturedCookie("token", "BBB"), bearer="bob.jwt")

    live = privesc_policy_from_sessions(matrix, [alice, bob])

    a, b = live.principals
    assert dict(a.headers)["Cookie"] == "token=AAA"
    assert dict(a.headers)["Authorization"] == "Bearer alice.jwt"
    assert dict(b.headers)["Cookie"] == "token=BBB"
    assert dict(b.headers)["Authorization"] == "Bearer bob.jwt"

    # STRUCTURE is never rewritten — only the identity headers change.
    assert [p.control_path for p in live.principals] == \
        [p.control_path for p in matrix.principals]
    assert [p.control_method for p in live.principals] == \
        [p.control_method for p in matrix.principals]
    assert live.checks == matrix.checks
    # The builder is PURE: the operator's source policy is left untouched.
    assert all(p.headers == () for p in matrix.principals)


def test_privesc_missing_session_keeps_declared_headers_for_inconclusive():
    # bob's login was skipped / failed -> None. His control probe then cannot
    # succeed, so the two-probe judge returns INCONCLUSIVE and NO finding is
    # manufactured. The builder must NOT invent headers for him.
    matrix = _structure_only_matrix()
    alice = _session(CapturedCookie("token", "AAA"), bearer="alice.jwt")

    live = privesc_policy_from_sessions(matrix, [alice, None])

    a, b = live.principals
    assert dict(a.headers)["Cookie"] == "token=AAA"
    assert b.headers == ()  # declared (empty) headers preserved verbatim


def test_privesc_fewer_sessions_than_principals_leaves_tail_declared():
    # Fewer captured sessions than declared principals: the unbound tail keeps
    # its declared (empty) headers rather than borrowing another account's.
    matrix = _structure_only_matrix()
    alice = _session(CapturedCookie("token", "AAA"))

    live = privesc_policy_from_sessions(matrix, [alice])

    a, b = live.principals
    assert dict(a.headers)["Cookie"] == "token=AAA"
    assert b.headers == ()


# --- end-to-end (browser-free): captured weak cookie → CONFIRMED → PROVEN ---

def test_captured_weak_cookie_confirmed_then_fix_proven_and_isolated():
    from app.security_graph.cookies import (
        parse_cookie_policy,
        run_cookie_investigation,
    )
    from app.commands.login_cmd import (
        _CapturedCookieExecutor,
        _prove_session_cookies,
    )

    # A real-world weak session cookie: no HttpOnly, no Secure.
    session = _session(CapturedCookie("token", "abc", path="/"))
    observed = [reconstruct_set_cookie(c) for c in session.cookies]
    policy = parse_cookie_policy(session_baseline_cookie_policy(session))

    graph = SecurityGraph()
    results = run_cookie_investigation(
        graph,
        policy,
        target_base="http://127.0.0.1:3000",
        executor=_CapturedCookieExecutor(observed),
    )

    # HttpOnly + Secure missing ⇒ VALIDATED; SameSite≠None with no SameSite
    # attribute ⇒ DISPROVED (honest: absence of SameSite=None is not a
    # violation of "must not equal None").
    validated = [r for r in results if r.status == "VALIDATED"]
    assert len(validated) == 2

    confirmed = list(graph.findings_for(kind="insecure_cookie", status="OPEN"))
    assert len(confirmed) == 2

    outcomes = _prove_session_cookies(graph, confirmed, observed)
    assert outcomes and all(o.result == "FIX_PROVEN" for o in outcomes)

    # Isolation: proving never mutates the confirmed state.
    for finding in confirmed:
        assert graph.hypotheses[finding.hypothesis_id].status == "CONFIRMED"
    assert len(
        list(graph.findings_for(kind="insecure_cookie", status="OPEN"))
    ) == 2


def test_compliant_captured_cookie_yields_no_finding():
    from app.security_graph.cookies import (
        parse_cookie_policy,
        run_cookie_investigation,
    )
    from app.commands.login_cmd import _CapturedCookieExecutor

    session = _session(
        CapturedCookie("token", "abc", path="/", http_only=True,
                       secure=True, same_site="Strict")
    )
    observed = [reconstruct_set_cookie(c) for c in session.cookies]
    policy = parse_cookie_policy(session_baseline_cookie_policy(session))

    graph = SecurityGraph()
    results = run_cookie_investigation(
        graph, policy, target_base="http://127.0.0.1:3000",
        executor=_CapturedCookieExecutor(observed),
    )
    assert all(r.status == "DISPROVED" for r in results)
    assert not list(graph.findings_for(kind="insecure_cookie", status="OPEN"))


# --- real browser path (opt-in, gated) -------------------------------------

def test_live_browser_captures_session_from_local_stub():
    pytest.importorskip("playwright")
    if not os.environ.get("SENTINEL_LIVE_BROWSER"):
        pytest.skip("set SENTINEL_LIVE_BROWSER=1 to run the headed/headless browser path")

    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from app.security_graph.session import capture_session

    class _LoginStub(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            return

        def do_GET(self):
            body = b"<html><body><h1>ok</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            # A weak session cookie the capture should observe.
            self.send_header("Set-Cookie", "token=abc123; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _LoginStub)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        session = capture_session(
            base,
            username="u@example.com",
            password="pw",
            timeout=15,
            headless=True,
        )
        assert any(c.name == "token" for c in session.cookies)
    finally:
        server.shutdown()
        server.server_close()


