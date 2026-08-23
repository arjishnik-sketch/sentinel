"""
Offline, network-free proof of the ZERO-CONFIG secure baseline oracle.

The baseline is a built-in DECLARED oracle (OWASP secure-headers + secure-cookie
defaults) so `investigate <target>` runs the header + cookie classes with no
operator authoring. The epistemic contract is unchanged and pinned here with a
canned executor:

  * every baseline expectation becomes an OPEN hypothesis, never a finding;
  * the same PURE judges decide — an insecure response reproduces VALIDATED and
    materialises a finding; a fully compliant response DISPROVES every check and
    yields NOTHING (the honest differential);
  * a target that sets no cookie DISPROVES the cookie baseline (never a
    manufactured finding);
  * the baseline round-trips losslessly through the real policy parsers, proving
    the serialisers the spec importer reuses emit a valid oracle.
"""

from app.security_graph.baseline import (
    BASELINE_COOKIE_SOURCE,
    BASELINE_HEADER_SOURCE,
    cookie_rules_payload,
    default_cookie_policy,
    default_header_policy,
    header_rules_payload,
)
from app.security_graph.cookies import parse_cookie_policy, run_cookie_investigation
from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.posture import parse_header_policy, run_posture_investigation


TARGET_BASE = "http://127.0.0.1:3000"


class _CannedHeaderExecutor(ExperimentExecutor):
    kind = "security_header_check"

    def __init__(self, response_headers, *, status_code=200):
        self._headers = dict(response_headers)
        self._status = status_code

    def execute(self, experiment):
        evidence = Evidence(
            id=f"ev:hdr:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": self._status,
                "response_headers": dict(self._headers),
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


class _CannedCookieExecutor(ExperimentExecutor):
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


# --- shape ------------------------------------------------------------------

def test_default_header_policy_shape():
    policy = default_header_policy()
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.method == "GET" and rule.path == "/"
    headers = {exp.header for exp in rule.expectations}
    assert "Content-Security-Policy" in headers
    assert "Access-Control-Allow-Origin" in headers  # must_not_equal *
    assert "X-Powered-By" in headers                  # must_absent
    assert BASELINE_HEADER_SOURCE  # provenance string is set


def test_default_cookie_policy_shape():
    policy = default_cookie_policy()
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.method == "GET" and rule.path == "/"
    # cookie_name empty ⇒ every Set-Cookie the route issues
    assert all(exp.cookie_name == "" for exp in rule.expectations)
    checks = {exp.check for exp in rule.expectations}
    assert "must_have_flag" in checks
    assert BASELINE_COOKIE_SOURCE


# --- header baseline through the PURE judge ---------------------------------

def _run_headers(observed):
    graph = SecurityGraph()
    results = run_posture_investigation(
        graph,
        default_header_policy(),
        target_base=TARGET_BASE,
        executor=_CannedHeaderExecutor(observed),
    )
    return graph, results


def test_header_baseline_confirms_on_insecure_response():
    # Nothing secure set; two disclosing/dangerous headers present.
    graph, results = _run_headers(
        {"X-Powered-By": "Express", "Access-Control-Allow-Origin": "*"}
    )
    expectations = default_header_policy().rules[0].expectations
    assert len(results) == len(expectations)
    # Every baseline check is contradicted by this response.
    assert all(r.status == "VALIDATED" for r in results)
    findings = list(
        graph.findings_for(kind="security_misconfiguration", status="OPEN")
    )
    assert len(findings) == len(expectations)


def test_header_baseline_fully_compliant_yields_no_finding():
    graph, results = _run_headers(
        {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            # no ACAO (must_not_equal * ⇒ absent is compliant),
            # no X-Powered-By (must_absent ⇒ absent is compliant)
        }
    )
    assert all(r.status == "DISPROVED" for r in results)
    assert not list(
        graph.findings_for(kind="security_misconfiguration", status="OPEN")
    )


# --- cookie baseline through the PURE judge ---------------------------------

def _run_cookies(set_cookies):
    graph = SecurityGraph()
    results = run_cookie_investigation(
        graph,
        default_cookie_policy(),
        target_base=TARGET_BASE,
        executor=_CannedCookieExecutor(set_cookies),
    )
    return graph, results


def test_cookie_baseline_no_cookie_yields_no_finding():
    # A target that sets no cookie on the root: the honest differential.
    graph, results = _run_cookies([])
    assert results  # every baseline check still ran
    assert all(r.status == "DISPROVED" for r in results)
    assert not list(graph.findings_for(kind="insecure_cookie", status="OPEN"))


def test_cookie_baseline_confirms_insecure_session_cookie():
    # A bare session cookie: no HttpOnly, no Secure, no SameSite.
    graph, results = _run_cookies(["session=abc123; Path=/"])
    validated = [r for r in results if r.status == "VALIDATED"]
    # HttpOnly + Secure are contradicted; SameSite=None check is compliant
    # (SameSite absent ≠ None), so it DISPROVES — the honest differential.
    assert len(validated) == 2
    findings = list(graph.findings_for(kind="insecure_cookie", status="OPEN"))
    assert len(findings) == 2


# --- serialiser round-trip (the seam the spec importer reuses) --------------

def test_header_serializer_round_trips_through_parser():
    payload = header_rules_payload(default_header_policy())
    reparsed = parse_header_policy({"header_rules": payload})
    original = default_header_policy().rules[0].expectations
    assert len(reparsed.rules) == 1
    assert len(reparsed.rules[0].expectations) == len(original)
    assert {e.header for e in reparsed.rules[0].expectations} == {
        e.header for e in original
    }


def test_cookie_serializer_round_trips_through_parser():
    payload = cookie_rules_payload(default_cookie_policy())
    reparsed = parse_cookie_policy({"cookie_rules": payload})
    original = default_cookie_policy().rules[0].expectations
    assert len(reparsed.rules) == 1
    assert len(reparsed.rules[0].expectations) == len(original)
    assert {e.check for e in reparsed.rules[0].expectations} == {
        e.check for e in original
    }

