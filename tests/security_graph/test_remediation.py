"""
Offline, network-free proof of the PATCH + PROVE remediation stage.

These tests never touch a real target. A canned executor stands in for the
live probe so the epistemic contract can be pinned deterministically:

  * a corrective rule is derived only from a confirmed deny-violation;
  * the pure judge, re-run through enforcement, flips VALIDATED -> DISPROVED
    only when the "after" probe is actually denied (403);
  * the confirmed hypothesis and finding are NEVER mutated by verification;
  * an availability regression (allow policy denied) is not shieldable.

A single localhost integration test proves the real reverse proxy denies
the anonymous caller and forwards everyone else.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import urllib.error
import urllib.request

from app.security_graph.execution import ExecutorRegistry, ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.orchestration.cycle import run_investigation_cycle
from app.security_graph.policy import parse_access_policy, seed_access_policy
from app.security_graph.remediation import (
    AccessControlRule,
    RemediationEnforcer,
    evaluate_request,
    generate_source_patch,
    remediate_and_prove,
    render_artifacts,
    synthesize_remediation,
)


TARGET_BASE = "http://127.0.0.1:3000"


class _CannedExecutor(ExperimentExecutor):
    """Return a fixed HTTP status for every probe."""

    kind = "authorization_http_check"

    def __init__(self, status_code: int):
        self._status_code = status_code

    def execute(self, experiment) -> ExecutionResult:
        evidence = Evidence(
            id=f"ev:probe:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": self._status_code,
                "experiment_id": experiment.id,
                "endpoint_id": None,
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", str(self._status_code)),),
        )


def _policy(decision: str, path: str = "/api/Feedbacks"):
    return parse_access_policy(
        {
            "principals": [{"name": "anonymous", "kind": "anonymous"}],
            "rules": [
                {
                    "principal": "anonymous",
                    "method": "GET",
                    "path": path,
                    "action": "read",
                    "decision": decision,
                }
            ],
        }
    )


def _confirmed_graph(decision: str, observed: int):
    """Seed a policy and run one decisive cycle to CONFIRM a finding."""
    graph = SecurityGraph()
    hyp_id = seed_access_policy(graph, _policy(decision), target_base=TARGET_BASE)[0]
    registry = ExecutorRegistry()
    registry.register(_CannedExecutor(observed))
    run_investigation_cycle(graph, registry)
    return graph, hyp_id

_ANON_RULE = AccessControlRule(
    principal_name="anonymous",
    principal_kind="anonymous",
    method="GET",
    path="/api/Feedbacks",
    action="read",
)

_TOKEN_RULE = AccessControlRule(
    principal_name="carol",
    principal_kind="user",
    method="GET",
    path="/api/Feedbacks",
    action="read",
    principal_headers=(("X-Access-Token", "carol-token"),),
)


# --- pure enforcement decision -------------------------------------------


def test_evaluate_request_denies_anonymous_without_credentials():
    assert evaluate_request((_ANON_RULE,), "GET", "/api/Feedbacks", {}) == "deny"


def test_evaluate_request_forwards_credentialed_caller():
    # A request bearing credentials is a different principal than anonymous.
    assert (
        evaluate_request(
            (_ANON_RULE,),
            "GET",
            "/api/Feedbacks",
            {"Authorization": "Bearer x"},
        )
        == "forward"
    )


def test_evaluate_request_forwards_unmatched_path_or_method():
    assert evaluate_request((_ANON_RULE,), "GET", "/api/Users", {}) == "forward"
    assert evaluate_request((_ANON_RULE,), "POST", "/api/Feedbacks", {}) == "forward"


def test_evaluate_request_matches_specific_principal_headers():
    hit = {"X-Access-Token": "carol-token"}
    miss = {"X-Access-Token": "someone-else"}
    assert evaluate_request((_TOKEN_RULE,), "GET", "/api/Feedbacks", hit) == "deny"
    assert evaluate_request((_TOKEN_RULE,), "GET", "/api/Feedbacks", miss) == "forward"


# --- deployable artifacts -------------------------------------------------


def test_render_artifacts_are_populated_and_reference_the_path():
    artifacts = render_artifacts(_ANON_RULE, TARGET_BASE)
    for text in (
        artifacts.portable_json,
        artifacts.nginx,
        artifacts.envoy_rbac,
        artifacts.caddy,
    ):
        assert text.strip()
        assert "/api/Feedbacks" in text


# --- source patch (auto-detect) ------------------------------------------


def test_source_patch_not_provided_without_repo():
    patch = generate_source_patch(_ANON_RULE, source_root=None)
    assert patch.status == "NOT_PROVIDED"


def test_source_patch_generated_for_express_repo(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "^4"}}', encoding="utf-8"
    )
    (tmp_path / "routes.js").write_text(
        "app.get('/api/Feedbacks', handler)\n", encoding="utf-8"
    )
    patch = generate_source_patch(_ANON_RULE, source_root=str(tmp_path))
    assert patch.status == "GENERATED"
    assert patch.framework == "express"
    assert "Sentinel remediation" in patch.unified_diff
    assert patch.file_path == "routes.js"


def test_source_patch_advisory_when_handler_absent(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    patch = generate_source_patch(_ANON_RULE, source_root=str(tmp_path))
    assert patch.status == "ADVISORY"
    assert patch.framework == "flask"

# --- synthesis (deterministic derivation from a CONFIRMED finding) --------


def _confirmed_finding(graph: SecurityGraph):
    findings = graph.findings_for(
        kind="authorization_policy_violation", status="OPEN"
    )
    assert findings, "expected a materialized authorization finding"
    return sorted(findings, key=lambda f: f.id)[0]


def test_synthesize_derives_deny_rule_from_confirmed_violation():
    # deny policy, but the target actually served 200 -> CONFIRMED violation.
    graph, _ = _confirmed_graph("deny", 200)
    finding = _confirmed_finding(graph)

    plan = synthesize_remediation(graph, finding)
    assert plan is not None
    assert plan.rule.decision == "deny"
    assert plan.rule.method == "GET"
    assert plan.rule.path == "/api/Feedbacks"
    assert plan.rule.principal_kind == "anonymous"
    assert plan.upstream_base == TARGET_BASE
    assert plan.target_url == f"{TARGET_BASE}/api/Feedbacks"


def test_synthesize_returns_none_for_allow_policy():
    # allow policy, target denied (401) -> a finding is raised, but it is an
    # availability regression, not a broken-access-control we can shield.
    graph, _ = _confirmed_graph("allow", 401)
    findings = graph.findings_for(
        kind="authorization_policy_violation", status="OPEN"
    )
    for finding in findings:
        assert synthesize_remediation(graph, finding) is None


# --- PATCH + PROVE (pure judge, injected executors, isolation) ------------


def test_remediate_and_prove_flips_to_fix_proven_when_enforced():
    graph, hyp_id = _confirmed_graph("deny", 200)
    finding = _confirmed_finding(graph)

    outcome = remediate_and_prove(
        graph,
        finding,
        before_executor=_CannedExecutor(200),  # contradiction still reproduces
        after_executor=_CannedExecutor(403),   # shield denies the anon caller
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification is not None
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"
    assert outcome.verification.before_status_code == 200
    assert outcome.verification.observed_status_code == 403
    assert outcome.verification.proven is True

    # Isolation: the real CONFIRMED hypothesis and finding are untouched.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_and_prove_reports_failure_when_still_allowed():
    graph, hyp_id = _confirmed_graph("deny", 200)
    finding = _confirmed_finding(graph)

    outcome = remediate_and_prove(
        graph,
        finding,
        before_executor=_CannedExecutor(200),
        after_executor=_CannedExecutor(200),  # shield did NOT deny -> not proven
        use_enforcer=False,
    )

    assert outcome.result == "FIX_FAILED"
    assert outcome.verification is not None
    assert outcome.verification.after_status != "DISPROVED"
    # A failed proof still never mutates the confirmed finding.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_and_prove_not_applicable_for_allow_policy():
    graph, _ = _confirmed_graph("allow", 401)
    findings = graph.findings_for(
        kind="authorization_policy_violation", status="OPEN"
    )
    assert findings
    outcome = remediate_and_prove(
        graph,
        sorted(findings, key=lambda f: f.id)[0],
        before_executor=_CannedExecutor(401),
        after_executor=_CannedExecutor(403),
        use_enforcer=False,
    )
    assert outcome.result == "NOT_APPLICABLE"


# --- live reverse proxy (single localhost integration) --------------------


class _StubUpstream(BaseHTTPRequestHandler):
    """A trivial always-200 origin the enforcer forwards allowed traffic to."""

    def log_message(self, *args):  # silence
        return

    def do_GET(self):
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_live_enforcer_denies_anonymous_and_forwards_credentialed():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _StubUpstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"

    try:
        with RemediationEnforcer((_ANON_RULE,), upstream_base) as enforcer:
            url = f"{enforcer.base_url}/api/Feedbacks"

            # Anonymous (no credential header) -> shield denies with 403.
            try:
                urllib.request.urlopen(url, timeout=5)
                denied_status = 200
            except urllib.error.HTTPError as exc:
                denied_status = exc.code
            assert denied_status == 403

            # Credentialed caller is a different principal -> forwarded (200).
            req = urllib.request.Request(url, headers={"Authorization": "Bearer x"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200

            # An unmatched path is always forwarded.
            other = urllib.request.urlopen(
                f"{enforcer.base_url}/api/Users", timeout=5
            )
            assert other.status == 200
    finally:
        upstream.shutdown()
        upstream.server_close()
