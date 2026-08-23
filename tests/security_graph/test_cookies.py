"""
Offline, network-free proof of the insecure-cookie class and its PATCH +
PROVE remediation. No real target is ever contacted: a canned executor
supplies fixed ``Set-Cookie`` headers so the epistemic contract is pinned
deterministically:

  * a declared expectation becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when an observed cookie CONTRADICTS
    the declared posture, DISPROVED when it satisfies it — or when the route
    issues no matching cookie at all (the honest differential);
  * a corrective control is derived only from a confirmed violation, and the
    same judge — re-run through the cookie-hardening shield — flips
    VALIDATED -> DISPROVED only when the observed cookie is actually corrected;
  * verification NEVER mutates the confirmed hypothesis or finding.

One localhost integration test proves the real reverse proxy hardens a
forwarded ``Set-Cookie`` as the rule requires.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import urllib.request

import pytest

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.cookies import (
    parse_cookie_policy,
    remediate_cookie_and_prove,
    render_cookie_artifacts,
    run_cookie_investigation,
    synthesize_cookie_remediation,
)
from app.security_graph.remediation.enforcer import (
    CookieAttributeRule,
    RemediationEnforcer,
    apply_cookie_mutations,
)


TARGET_BASE = "http://127.0.0.1:3000"


# CHUNK_MARKER


class _CannedCookieExecutor(ExperimentExecutor):
    """A network-free cookie executor returning fixed Set-Cookie headers.

    The cookie judge reads `data["set_cookie"]` (a list of raw Set-Cookie
    lines), so this supplies the observed cookies directly.
    """

    kind = "cookie_check"

    def __init__(self, set_cookies, *, status_code=200):
        self._cookies = list(set_cookies)
        self._status = status_code

    def execute(self, experiment):
        evidence = Evidence(
            id=f"ev:cookie:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": self._status,
                "response_headers": {},
                "set_cookie": list(self._cookies),
                "url": experiment.request.url if experiment.request else "",
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", str(self._status)),),
        )


def _policy(expectations, *, method="GET", path="/", resource="app root"):
    return parse_cookie_policy(
        {
            "cookie_rules": [
                {
                    "method": method,
                    "path": path,
                    "resource": resource,
                    "expectations": list(expectations),
                }
            ]
        }
    )


def _confirmed_graph(expectation, observed_cookies):
    """Seed one expectation and drive it to a verdict with canned cookies."""
    graph = SecurityGraph()
    results = run_cookie_investigation(
        graph,
        _policy([expectation]),
        target_base=TARGET_BASE,
        executor=_CannedCookieExecutor(observed_cookies),
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(
        graph.findings_for(kind="insecure_cookie", status="OPEN")
    )
    assert len(findings) == 1
    return findings[0]


# --- parse -----------------------------------------------------------------

def test_parse_cookie_policy_reads_rules():
    policy = _policy(
        [{"cookie_name": "token", "check": "must_have_flag",
          "flag": "HttpOnly", "severity": "HIGH"}]
    )
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.method == "GET" and rule.path == "/"
    assert rule.expectations[0].cookie_name == "token"
    assert rule.expectations[0].check == "must_have_flag"
    assert rule.expectations[0].flag == "HttpOnly"


def test_parse_rejects_malformed_specs():
    # flag check without a flag
    with pytest.raises(ValueError):
        _policy([{"cookie_name": "t", "check": "must_have_flag"}])
    # flag check with an invalid flag
    with pytest.raises(ValueError):
        _policy([{"cookie_name": "t", "check": "must_have_flag",
                  "flag": "Bogus"}])
    # samesite check without a value
    with pytest.raises(ValueError):
        _policy([{"cookie_name": "t", "check": "samesite_must_equal"}])
    # samesite check carrying a flag
    with pytest.raises(ValueError):
        _policy([{"cookie_name": "t", "check": "samesite_must_equal",
                  "value": "Strict", "flag": "Secure"}])
    # unknown check
    with pytest.raises(ValueError):
        _policy([{"cookie_name": "t", "check": "must_be_nice"}])


# --- seed + PURE judge ------------------------------------------------------

def test_missing_httponly_is_validated_and_confirmed():
    graph, results = _confirmed_graph(
        {"cookie_name": "token", "check": "must_have_flag",
         "flag": "HttpOnly", "severity": "HIGH"},
        ["token=abc; Path=/"],  # HttpOnly absent -> contradiction
    )
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "insecure_cookie"
    assert finding.severity == "MEDIUM"  # coarse reporting default per kind


def test_present_httponly_is_disproved_and_yields_no_finding():
    graph, results = _confirmed_graph(
        {"cookie_name": "token", "check": "must_have_flag",
         "flag": "HttpOnly", "severity": "HIGH"},
        ["token=abc; Path=/; HttpOnly; Secure"],  # satisfies posture
    )
    assert results[0].status == "DISPROVED"
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(
        graph.findings_for(kind="insecure_cookie", status="OPEN")
    )


def test_unset_cookie_is_disproved_no_manufactured_finding():
    # The route issues no matching cookie at all -> compliant by construction.
    graph, results = _confirmed_graph(
        {"cookie_name": "token", "check": "must_have_flag",
         "flag": "HttpOnly"},
        [],  # nothing observed
    )
    assert results[0].status == "DISPROVED"
    assert not list(
        graph.findings_for(kind="insecure_cookie", status="OPEN")
    )


def test_samesite_none_violates_but_strict_satisfies():
    expectation = {"cookie_name": "token", "check": "samesite_must_not_equal",
                   "value": "None", "severity": "HIGH"}
    _, permissive = _confirmed_graph(
        expectation, ["token=abc; SameSite=None"]
    )
    _, strict = _confirmed_graph(
        expectation, ["token=abc; SameSite=Strict"]
    )
    assert permissive[0].status == "VALIDATED"
    assert strict[0].status == "DISPROVED"


# MUTATE_MARKER


# --- pure cookie mutation ---------------------------------------------------

def test_apply_cookie_mutations_add_set_and_remove():
    rules = (
        CookieAttributeRule("GET", "/", "token", "add_flag", flag="HttpOnly"),
        CookieAttributeRule("GET", "/", "token", "add_flag", flag="Secure"),
        CookieAttributeRule("GET", "/", "token", "set_samesite", value="Strict"),
    )
    original = [
        ("Set-Cookie", "token=abc; Path=/"),
        ("Content-Type", "text/html"),
    ]
    out = apply_cookie_mutations(original, "GET", "/", rules)
    cookie = next(v for n, v in out if n == "Set-Cookie")
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=Strict" in cookie
    # non-cookie headers untouched
    assert ("Content-Type", "text/html") in out


def test_apply_cookie_mutations_remove_flag_and_replace_samesite():
    rules = (
        CookieAttributeRule("GET", "/", "token", "remove_flag", flag="Secure"),
        CookieAttributeRule("GET", "/", "token", "set_samesite", value="Lax"),
    )
    original = [("Set-Cookie", "token=abc; Secure; SameSite=None")]
    out = apply_cookie_mutations(original, "GET", "/", rules)
    cookie = out[0][1]
    assert "Secure" not in cookie
    assert "SameSite=Lax" in cookie
    assert "SameSite=None" not in cookie


def test_apply_cookie_mutations_only_matching_name_and_route():
    rules = (
        CookieAttributeRule("GET", "/", "token", "add_flag", flag="HttpOnly"),
    )
    original = [("Set-Cookie", "other=xyz; Path=/")]
    # cookie name does not match -> untouched
    assert apply_cookie_mutations(original, "GET", "/", rules) == original
    # route does not match -> untouched
    token = [("Set-Cookie", "token=abc")]
    assert apply_cookie_mutations(token, "POST", "/", rules) == token
    assert apply_cookie_mutations(token, "GET", "/other", rules) == token


def test_apply_cookie_mutations_wildcard_name_hits_all():
    rules = (CookieAttributeRule("GET", "/", "", "add_flag", flag="HttpOnly"),)
    original = [
        ("Set-Cookie", "a=1"),
        ("Set-Cookie", "b=2; HttpOnly"),
    ]
    out = apply_cookie_mutations(original, "GET", "/", rules)
    cookies = [v for n, v in out if n == "Set-Cookie"]
    assert all("HttpOnly" in c for c in cookies)
    # the one that already had it is not duplicated
    assert cookies[1].count("HttpOnly") == 1


# --- synthesize -------------------------------------------------------------

def test_synthesize_cookie_remediation_from_violation():
    graph, _ = _confirmed_graph(
        {"cookie_name": "token", "check": "must_have_flag",
         "flag": "HttpOnly", "severity": "HIGH"},
        ["token=abc; Path=/"],  # HttpOnly absent
    )
    plan = synthesize_cookie_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.cookie_name == "token"
    assert plan.rule.op == "add_flag"
    assert plan.rule.flag == "HttpOnly"
    assert plan.rule.method == "GET" and plan.rule.path == "/"
    assert plan.upstream_base == TARGET_BASE
    assert plan.target_url == TARGET_BASE + "/"


def test_synthesize_ignores_non_cookie_finding():
    from dataclasses import replace

    graph, _ = _confirmed_graph(
        {"cookie_name": "token", "check": "must_have_flag", "flag": "HttpOnly"},
        ["token=abc"],
    )
    foreign = replace(
        _confirmed_finding(graph), kind="authorization_policy_violation"
    )
    assert synthesize_cookie_remediation(graph, foreign) is None


# --- artifacts --------------------------------------------------------------

def test_render_cookie_artifacts_are_non_empty_and_name_the_cookie():
    graph, _ = _confirmed_graph(
        {"cookie_name": "token", "check": "must_have_flag",
         "flag": "HttpOnly", "severity": "HIGH"},
        ["token=abc"],
    )
    plan = synthesize_cookie_remediation(graph, _confirmed_finding(graph))
    artifacts = render_cookie_artifacts(plan.rule, plan.upstream_base)
    for config in (artifacts.portable_json, artifacts.nginx,
                   artifacts.caddy, artifacts.envoy):
        assert config.strip()
        assert "token" in config
    assert plan.upstream_base in artifacts.nginx


# REMEDIATE_MARKER


# --- remediate + PROVE (injected executors, no live proxy) -----------------

def test_remediate_cookie_and_prove_fix_proven_and_isolated():
    graph, _ = _confirmed_graph(
        {"cookie_name": "token", "check": "must_have_flag",
         "flag": "HttpOnly", "severity": "HIGH"},
        ["token=abc; Path=/"],  # HttpOnly absent -> confirmed
    )
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id

    outcome = remediate_cookie_and_prove(
        graph,
        finding,
        before_executor=_CannedCookieExecutor(["token=abc; Path=/"]),
        after_executor=_CannedCookieExecutor(
            ["token=abc; Path=/; HttpOnly"]  # corrected
        ),
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_cookie_and_prove_fix_failed_when_still_insecure():
    graph, _ = _confirmed_graph(
        {"cookie_name": "token", "check": "must_have_flag", "flag": "HttpOnly"},
        ["token=abc; Path=/"],
    )
    outcome = remediate_cookie_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedCookieExecutor(["token=abc; Path=/"]),
        after_executor=_CannedCookieExecutor(["token=abc; Path=/"]),  # still
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_non_cookie_finding_is_not_applicable():
    from dataclasses import replace

    graph, _ = _confirmed_graph(
        {"cookie_name": "token", "check": "must_have_flag", "flag": "HttpOnly"},
        ["token=abc"],
    )
    foreign = replace(
        _confirmed_finding(graph), kind="authorization_policy_violation"
    )
    outcome = remediate_cookie_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"


# --- live integration: real reverse proxy hardens forwarded Set-Cookie -----

class _StubUpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        # An insecure session cookie: no HttpOnly, no Secure, SameSite=None.
        self.send_header("Set-Cookie", "token=abc123; Path=/; SameSite=None")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def test_live_enforcer_hardens_forwarded_set_cookie():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _StubUpstreamHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"
        cookie_rules = (
            CookieAttributeRule("GET", "/", "token", "add_flag",
                                flag="HttpOnly"),
            CookieAttributeRule("GET", "/", "token", "add_flag", flag="Secure"),
            CookieAttributeRule("GET", "/", "token", "set_samesite",
                                value="Strict"),
        )
        with RemediationEnforcer(
            (), upstream_base, cookie_rules=cookie_rules
        ) as shield:
            with urllib.request.urlopen(
                shield.base_url + "/", timeout=10
            ) as resp:
                set_cookies = resp.headers.get_all("Set-Cookie") or []
        assert len(set_cookies) == 1
        hardened = set_cookies[0]
        assert "HttpOnly" in hardened
        assert "Secure" in hardened
        assert "SameSite=Strict" in hardened
        assert "SameSite=None" not in hardened
    finally:
        upstream.shutdown()
        upstream.server_close()



