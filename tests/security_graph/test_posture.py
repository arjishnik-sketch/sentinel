"""
Offline, network-free proof of the security-header posture class and its
PATCH + PROVE remediation. No real target is ever contacted: a canned
executor supplies fixed response headers so the epistemic contract is pinned
deterministically:

  * a declared expectation becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when the observed header
    CONTRADICTS the declared posture, DISPROVED when it satisfies it;
  * a compliant header yields DISPROVED and NO finding (the differential);
  * a corrective control is derived only from a confirmed violation, and the
    same judge — re-run through the header-rewriting shield — flips
    VALIDATED -> DISPROVED only when the observed headers are actually
    corrected;
  * verification NEVER mutates the confirmed hypothesis or finding.

One localhost integration test proves the real reverse proxy injects,
rewrites, and strips response headers as the rule requires.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import urllib.request

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.posture import (
    parse_header_policy,
    remediate_header_and_prove,
    render_header_artifacts,
    run_posture_investigation,
    synthesize_header_remediation,
)
from app.security_graph.remediation.enforcer import (
    RemediationEnforcer,
    ResponseHeaderRule,
    apply_header_mutations,
)


TARGET_BASE = "http://127.0.0.1:3000"

import pytest


class _CannedHeaderExecutor(ExperimentExecutor):
    """A network-free posture executor returning fixed response headers.

    The posture judge reads `data["response_headers"]`, so a status-code-only
    stub is insufficient — this supplies the observed header set directly.
    """

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


def _policy(expectations, *, method="GET", path="/", resource="app root"):
    return parse_header_policy(
        {
            "header_rules": [
                {
                    "method": method,
                    "path": path,
                    "resource": resource,
                    "expectations": list(expectations),
                }
            ]
        }
    )


def _confirmed_graph(expectation, observed_headers):
    """Seed one expectation and drive it to a verdict with canned headers."""
    graph = SecurityGraph()
    results = run_posture_investigation(
        graph,
        _policy([expectation]),
        target_base=TARGET_BASE,
        executor=_CannedHeaderExecutor(observed_headers),
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(
        graph.findings_for(kind="security_misconfiguration", status="OPEN")
    )
    assert len(findings) == 1
    return findings[0]


# --- parse -----------------------------------------------------------------

def test_parse_header_policy_reads_rules():
    policy = _policy(
        [{"header": "Content-Security-Policy", "requirement": "must_present",
          "severity": "HIGH"}]
    )
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.method == "GET" and rule.path == "/"
    assert rule.expectations[0].header == "Content-Security-Policy"
    assert rule.expectations[0].requirement == "must_present"


def test_parse_rejects_value_on_presence_and_missing_value_on_comparison():
    with pytest.raises(ValueError):
        _policy([{"header": "X-CSP", "requirement": "must_present",
                  "value": "nope"}])
    with pytest.raises(ValueError):
        _policy([{"header": "Access-Control-Allow-Origin",
                  "requirement": "must_not_equal"}])


# --- seed + PURE judge ------------------------------------------------------

def test_missing_required_header_is_validated_and_confirmed():
    graph, results = _confirmed_graph(
        {"header": "Content-Security-Policy", "requirement": "must_present",
         "severity": "HIGH"},
        {"X-Content-Type-Options": "nosniff"},  # CSP absent -> contradiction
    )
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "security_misconfiguration"
    assert finding.severity == "MEDIUM"  # coarse reporting default per kind


def test_compliant_header_is_disproved_and_yields_no_finding():
    graph, results = _confirmed_graph(
        {"header": "X-Content-Type-Options", "requirement": "must_present",
         "severity": "MEDIUM"},
        {"X-Content-Type-Options": "nosniff"},  # satisfies posture
    )
    assert results[0].status == "DISPROVED"
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(
        graph.findings_for(kind="security_misconfiguration", status="OPEN")
    )


def test_wildcard_cors_violates_but_specific_origin_satisfies():
    expectation = {"header": "Access-Control-Allow-Origin",
                   "requirement": "must_not_equal", "value": "*",
                   "severity": "HIGH"}
    _, wildcard = _confirmed_graph(
        expectation, {"Access-Control-Allow-Origin": "*"}
    )
    _, scoped = _confirmed_graph(
        expectation, {"Access-Control-Allow-Origin": "https://app.example.test"}
    )
    assert wildcard[0].status == "VALIDATED"
    assert scoped[0].status == "DISPROVED"


# --- pure header mutation ---------------------------------------------------

def test_apply_header_mutations_set_remove_and_conditional():
    rules = (
        ResponseHeaderRule("GET", "/", "Content-Security-Policy", "set",
                           "default-src 'self'"),
        ResponseHeaderRule("GET", "/", "X-Powered-By", "remove"),
        ResponseHeaderRule("GET", "/", "Access-Control-Allow-Origin",
                           "remove_if_equals", "*"),
    )
    original = [
        ("X-Powered-By", "Express"),
        ("Access-Control-Allow-Origin", "*"),
        ("Content-Type", "text/html"),
    ]
    out = apply_header_mutations(original, "GET", "/", rules)
    lowered = {name.lower(): value for name, value in out}
    assert lowered["content-security-policy"] == "default-src 'self'"
    assert "x-powered-by" not in lowered
    assert "access-control-allow-origin" not in lowered
    assert lowered["content-type"] == "text/html"  # untouched


def test_apply_header_mutations_keeps_safe_cors_value():
    rules = (ResponseHeaderRule("GET", "/", "Access-Control-Allow-Origin",
                                "remove_if_equals", "*"),)
    original = [("Access-Control-Allow-Origin", "https://ok.test")]
    assert apply_header_mutations(original, "GET", "/", rules) == original


def test_apply_header_mutations_ignores_other_routes():
    rules = (ResponseHeaderRule("GET", "/", "X-Powered-By", "remove"),)
    original = [("X-Powered-By", "Express")]
    assert apply_header_mutations(original, "POST", "/", rules) == original
    assert apply_header_mutations(original, "GET", "/other", rules) == original


# --- synthesize -------------------------------------------------------------

def test_synthesize_header_remediation_from_violation():
    graph, _ = _confirmed_graph(
        {"header": "Content-Security-Policy", "requirement": "must_present",
         "severity": "HIGH"},
        {},  # CSP absent
    )
    plan = synthesize_header_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.header == "Content-Security-Policy"
    assert plan.rule.op == "set"
    assert plan.rule.value  # a hardening default was chosen
    assert plan.rule.method == "GET" and plan.rule.path == "/"
    assert plan.upstream_base == TARGET_BASE
    assert plan.target_url == TARGET_BASE + "/"


def test_synthesize_ignores_non_posture_finding():
    from dataclasses import replace

    graph, _ = _confirmed_graph(
        {"header": "Content-Security-Policy", "requirement": "must_present"},
        {},
    )
    foreign = replace(
        _confirmed_finding(graph), kind="authorization_policy_violation"
    )
    assert synthesize_header_remediation(graph, foreign) is None


# --- artifacts --------------------------------------------------------------

def test_render_header_artifacts_are_non_empty_and_name_the_header():
    graph, _ = _confirmed_graph(
        {"header": "Content-Security-Policy", "requirement": "must_present",
         "severity": "HIGH"},
        {},
    )
    plan = synthesize_header_remediation(graph, _confirmed_finding(graph))
    artifacts = render_header_artifacts(plan.rule, plan.upstream_base)
    for config in (artifacts.portable_json, artifacts.nginx,
                   artifacts.caddy, artifacts.envoy):
        assert config.strip()
        assert "Content-Security-Policy" in config
    assert plan.upstream_base in artifacts.nginx


# --- remediate + PROVE (injected executors, no live proxy) -----------------

def test_remediate_header_and_prove_fix_proven_and_isolated():
    graph, _ = _confirmed_graph(
        {"header": "Content-Security-Policy", "requirement": "must_present",
         "severity": "HIGH"},
        {},  # CSP absent -> confirmed
    )
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id

    outcome = remediate_header_and_prove(
        graph,
        finding,
        before_executor=_CannedHeaderExecutor({}),  # still violating
        after_executor=_CannedHeaderExecutor(
            {"Content-Security-Policy": "default-src 'self'"}  # corrected
        ),
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_header_and_prove_fix_failed_when_still_violating():
    graph, _ = _confirmed_graph(
        {"header": "Content-Security-Policy", "requirement": "must_present"},
        {},
    )
    outcome = remediate_header_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedHeaderExecutor({}),
        after_executor=_CannedHeaderExecutor({}),  # header still absent
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_non_posture_finding_is_not_applicable():
    from dataclasses import replace

    graph, _ = _confirmed_graph(
        {"header": "Content-Security-Policy", "requirement": "must_present"},
        {},
    )
    foreign = replace(
        _confirmed_finding(graph), kind="authorization_policy_violation"
    )
    outcome = remediate_header_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"


# --- live integration: real reverse proxy rewrites forwarded headers -------

class _StubUpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        body = b"<html>ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "Express")            # must be stripped
        self.send_header("Access-Control-Allow-Origin", "*")   # must be stripped
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def test_live_enforcer_rewrites_forwarded_response_headers():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _StubUpstreamHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"
        header_rules = (
            ResponseHeaderRule("GET", "/", "Content-Security-Policy", "set",
                               "default-src 'self'"),
            ResponseHeaderRule("GET", "/", "X-Powered-By", "remove"),
            ResponseHeaderRule("GET", "/", "Access-Control-Allow-Origin",
                               "remove_if_equals", "*"),
        )
        with RemediationEnforcer(
            (), upstream_base, header_rules=header_rules
        ) as shield:
            with urllib.request.urlopen(
                shield.base_url + "/", timeout=10
            ) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read()
        assert headers.get("content-security-policy") == "default-src 'self'"
        assert "x-powered-by" not in headers
        assert "access-control-allow-origin" not in headers
        assert body == b"<html>ok</html>"
    finally:
        upstream.shutdown()
        upstream.server_close()

