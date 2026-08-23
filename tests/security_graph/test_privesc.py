"""
Offline, network-free proof of the privilege-escalation (login-matrix) class
and its PATCH + PROVE remediation. No real target is contacted for the unit
tests: a canned executor maps each probe's path to a fixed status code — and
crucially distinguishes the attacker's session probes (which carry captured
headers) from the anonymous baseline probe (which carries none) — so the
three-probe (control + breach + anonymous baseline) differential is pinned
deterministically:

  * a declared boundary becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when the control probe SUCCEEDS
    (session provably alive) AND the breach is GRANTED AND an anonymous caller
    is DENIED that same route (the grant is attributable to the attacker's
    identity, not to a public route); DISPROVED when the control succeeds but
    the breach is denied (the boundary holds); and INCONCLUSIVE when the control
    itself does not succeed (dead session), or when an anonymous caller is ALSO
    granted the breach (public route / the app 200s everything) — in both cases
    nothing is claimed;
  * a corrective access-control rule is derived only from a confirmed
    escalation, and the same judge — re-run through the enforcement shield —
    proves the fix ONLY when it flips VALIDATED -> DISPROVED (the escalation
    reproduced pre-fix and stops reproducing under enforcement) while the
    attacker's own control access still succeeds;
  * verification NEVER mutates the confirmed hypothesis or finding.

One localhost integration test stands the real reverse proxy in front of a stub
upstream that grants any authenticated caller BOTH routes but denies anonymous
callers, and proves the shield denies the breach (403) while still forwarding
the control (2xx) — the honest, non-broken fix.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.privesc import (
    judge_privilege_escalation,
    parse_privesc_policy,
    remediate_privesc_and_prove,
    render_privesc_artifacts,
    run_privesc_investigation,
    synthesize_privesc_remediation,
)
from app.security_graph.remediation.enforcer import (
    AccessControlRule,
    RemediationEnforcer,
)


TARGET_BASE = "http://127.0.0.1:3000"

ATTACKER_HEADERS = [["Authorization", "Bearer ATTACKER"]]
CONTROL_PATH = "/rest/basket/1"
BREACH_PATH = "/rest/basket/2"


class _CannedPrivEscExecutor(ExperimentExecutor):
    """A network-free privesc executor mapping request path -> status code.

    The privilege-escalation judge reads the single ``mode=="http"`` evidence's
    ``status_code`` for each probe, so this supplies the observed codes directly
    without touching a network.

    It models identity the way the three-probe differential demands: the
    attacker's control/breach probes carry captured session headers, while the
    anonymous *baseline* probe carries none. Header-bearing requests are scored
    from ``status_by_path`` (attacker view); headerless requests are scored from
    ``anon_status_by_path`` and default to ``anon_default`` (401 — an anonymous
    caller is denied), so a real BOLA (attacker granted, anon denied) is modeled
    rather than "200 for everyone" (which is correctly the INCONCLUSIVE
    public-route confound).
    """

    kind = "privilege_escalation_check"

    def __init__(
        self,
        status_by_path,
        *,
        default_status=200,
        anon_status_by_path=None,
        anon_default=401,
    ):
        self._by_path = dict(status_by_path)
        self._default = default_status
        self._anon_by_path = dict(anon_status_by_path or {})
        self._anon_default = anon_default

    def execute(self, experiment):
        req = experiment.request
        url = req.url if req else ""
        path = urlsplit(url).path or "/"
        # The anonymous baseline probe is the only one carrying NO headers; the
        # attacker's control/breach probes always carry the captured session.
        is_attacker = bool(req.headers) if req is not None else False
        if is_attacker:
            status = self._by_path.get(path, self._default)
        else:
            status = self._anon_by_path.get(path, self._anon_default)
        evidence = Evidence(
            id=f"ev:privesc:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": status,
                "response_headers": {},
                "url": url,
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", str(status)),),
        )


def _matrix(check, *, principals=None, success_statuses=None):
    """Build a one-check login matrix policy (attacker = 'alice')."""
    base_principals = principals or [
        {
            "name": "alice",
            "headers": ATTACKER_HEADERS,
            "control": {"method": "GET", "path": CONTROL_PATH},
            "role": "user",
        },
        {
            "name": "bob",
            "headers": [["Authorization", "Bearer VICTIM"]],
            "control": {"method": "GET", "path": BREACH_PATH},
            "role": "user",
        },
    ]
    matrix = {"principals": base_principals, "checks": [check]}
    if success_statuses is not None:
        matrix["success_statuses"] = success_statuses
    return parse_privesc_policy({"privesc_matrix": matrix})


_HORIZONTAL_CHECK = {
    "type": "horizontal",
    "attacker": "alice",
    "victim": "bob",
    "breach": {"method": "GET", "path": BREACH_PATH},
    "severity": "HIGH",
}


def _resolved_graph(
    status_by_path,
    *,
    check=None,
    success_statuses=None,
    anon_status_by_path=None,
    anon_default=401,
):
    """Seed one boundary and drive it to a verdict with canned probe codes."""
    graph = SecurityGraph()
    results = run_privesc_investigation(
        graph,
        _matrix(check or dict(_HORIZONTAL_CHECK), success_statuses=success_statuses),
        target_base=TARGET_BASE,
        executor=_CannedPrivEscExecutor(
            status_by_path,
            anon_status_by_path=anon_status_by_path,
            anon_default=anon_default,
        ),
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(
        graph.findings_for(kind="privilege_escalation", status="OPEN")
    )
    assert len(findings) == 1
    return findings[0]


# --- parse -----------------------------------------------------------------

def test_parse_privesc_matrix_reads_principals_and_checks():
    policy = _matrix(dict(_HORIZONTAL_CHECK))
    assert {p.name for p in policy.principals} == {"alice", "bob"}
    assert len(policy.checks) == 1
    check = policy.checks[0]
    assert check.type == "horizontal"
    assert check.attacker == "alice" and check.victim == "bob"
    assert check.breach_method == "GET" and check.breach_path == BREACH_PATH


def test_parse_rejects_unknown_attacker_and_missing_victim():
    # attacker is not a declared principal
    with pytest.raises(ValueError):
        parse_privesc_policy(
            {
                "privesc_matrix": {
                    "principals": [
                        {"name": "alice",
                         "control": {"method": "GET", "path": CONTROL_PATH}}
                    ],
                    "checks": [
                        {"type": "horizontal", "attacker": "mallory",
                         "victim": "alice",
                         "breach": {"method": "GET", "path": BREACH_PATH}}
                    ],
                }
            }
        )
    # horizontal check with no victim named
    with pytest.raises(ValueError):
        parse_privesc_policy(
            {
                "privesc_matrix": {
                    "principals": [
                        {"name": "alice",
                         "control": {"method": "GET", "path": CONTROL_PATH}}
                    ],
                    "checks": [
                        {"type": "horizontal", "attacker": "alice",
                         "breach": {"method": "GET", "path": BREACH_PATH}}
                    ],
                }
            }
        )
    # principal without a control baseline
    with pytest.raises(ValueError):
        parse_privesc_policy(
            {"privesc_matrix": {"principals": [{"name": "alice"}],
                                "checks": []}}
        )


# --- seed + PURE three-probe judge -----------------------------------------

def test_control_ok_and_breach_granted_is_validated_and_confirmed():
    graph, results = _resolved_graph(
        {CONTROL_PATH: 200, BREACH_PATH: 200},  # live session, breach granted
    )
    # Anonymous baseline on the breach route defaults to 401 (denied), so the
    # grant is attributable to alice's identity.
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert results[0].control_status_code == 200
    assert results[0].breach_status_code == 200
    assert results[0].baseline_status_code == 401
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "privilege_escalation"
    assert finding.severity == "HIGH"  # coarse reporting default per kind


def test_public_route_confound_is_inconclusive_no_finding():
    # Attacker is granted the breach, but so is an anonymous caller: the route
    # is public (or the app 200s everything). The grant is NOT attributable to
    # privilege, so the three-probe judge returns INCONCLUSIVE and NO finding is
    # manufactured — even though a bare status code alone would have "confirmed"
    # it. This is the confound the anonymous negative control exists to catch.
    graph, results = _resolved_graph(
        {CONTROL_PATH: 200, BREACH_PATH: 200},
        anon_status_by_path={BREACH_PATH: 200},  # anon ALSO granted
    )
    assert results[0].status == "INCONCLUSIVE"
    assert results[0].breach_status_code == 200
    assert results[0].baseline_status_code == 200
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(
        graph.findings_for(kind="privilege_escalation", status="OPEN")
    )


def test_control_ok_but_breach_denied_is_disproved_no_finding():
    graph, results = _resolved_graph(
        {CONTROL_PATH: 200, BREACH_PATH: 403},  # boundary holds
    )
    assert results[0].status == "DISPROVED"
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(
        graph.findings_for(kind="privilege_escalation", status="OPEN")
    )


def test_dead_control_session_is_inconclusive_no_finding():
    # Control does NOT succeed -> session not proven alive -> a breach 200
    # cannot be attributed, so nothing is claimed (no manufactured finding).
    graph, results = _resolved_graph(
        {CONTROL_PATH: 401, BREACH_PATH: 200},
    )
    assert results[0].status == "INCONCLUSIVE"
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(
        graph.findings_for(kind="privilege_escalation", status="OPEN")
    )


def test_vertical_escalation_confirms_the_same_way():
    vertical = {
        "type": "vertical",
        "attacker": "alice",
        "breach": {"method": "GET", "path": "/rest/admin/users"},
        "severity": "CRITICAL",
    }
    graph, results = _resolved_graph(
        {CONTROL_PATH: 200, "/rest/admin/users": 200},
        check=vertical,
    )
    assert results[0].status == "VALIDATED"
    assert _confirmed_finding(graph).kind == "privilege_escalation"


def test_pure_judge_reads_the_two_probe_differential_directly():
    # Legacy two-probe mode: when NO baseline id is supplied the judge skips the
    # public-route check and decides from control+breach alone. Drive to a
    # confirmed graph, then re-run the PURE judge against the same recorded
    # probes and assert it is a deterministic function of them.
    graph, results = _resolved_graph({CONTROL_PATH: 200, BREACH_PATH: 200})
    hyp = graph.hypotheses[results[0].hypothesis_id]
    control_id = f"exp:privesc-control:{hyp.id}"
    breach_id = f"exp:privesc-breach:{hyp.id}"
    judgment = judge_privilege_escalation(
        graph,
        hypothesis=hyp,
        control_experiment_id=control_id,
        breach_experiment_id=breach_id,
    )
    assert judgment.status == "VALIDATED"
    assert judgment.contradiction_kind == "privilege_escalation"
    assert judgment.observed is True  # breach was granted


def test_pure_judge_three_probe_public_route_is_inconclusive():
    # With the anonymous baseline supplied AND granted, the same recorded probes
    # yield INCONCLUSIVE — the public-route confound the third probe exists to
    # catch. This pins the three-probe verdict as a pure function of the probes.
    graph, results = _resolved_graph(
        {CONTROL_PATH: 200, BREACH_PATH: 200},
        anon_status_by_path={BREACH_PATH: 200},
    )
    hyp = graph.hypotheses[results[0].hypothesis_id]
    judgment = judge_privilege_escalation(
        graph,
        hypothesis=hyp,
        control_experiment_id=f"exp:privesc-control:{hyp.id}",
        breach_experiment_id=f"exp:privesc-breach:{hyp.id}",
        baseline_experiment_id=f"exp:privesc-baseline:{hyp.id}",
    )
    assert judgment.status == "INCONCLUSIVE"
    assert "public" in judgment.reason or "everything" in judgment.reason


# --- synthesize + artifacts -------------------------------------------------

def test_synthesize_privesc_remediation_from_confirmed_escalation():
    graph, _ = _resolved_graph({CONTROL_PATH: 200, BREACH_PATH: 200})
    plan = synthesize_privesc_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.method == "GET" and plan.rule.path == BREACH_PATH
    assert plan.rule.attacker_name == "alice"
    assert ("Authorization", "Bearer ATTACKER") in plan.rule.attacker_headers
    assert plan.upstream_base == TARGET_BASE
    assert plan.control_url == TARGET_BASE + CONTROL_PATH
    assert plan.breach_url == TARGET_BASE + BREACH_PATH


def test_synthesize_ignores_non_privesc_finding():
    from dataclasses import replace

    graph, _ = _resolved_graph({CONTROL_PATH: 200, BREACH_PATH: 200})
    foreign = replace(
        _confirmed_finding(graph), kind="authorization_policy_violation"
    )
    assert synthesize_privesc_remediation(graph, foreign) is None


def test_render_privesc_artifacts_non_empty_and_name_the_route():
    graph, _ = _resolved_graph({CONTROL_PATH: 200, BREACH_PATH: 200})
    plan = synthesize_privesc_remediation(graph, _confirmed_finding(graph))
    artifacts = render_privesc_artifacts(plan.rule, plan.upstream_base)
    for config in (artifacts.portable_json, artifacts.nginx,
                   artifacts.caddy, artifacts.envoy):
        assert config.strip()
        assert BREACH_PATH in config
    assert plan.upstream_base in artifacts.nginx


# --- remediate + PROVE (injected executors, no live proxy) -----------------

def test_remediate_privesc_and_prove_fix_proven_and_isolated():
    graph, _ = _resolved_graph({CONTROL_PATH: 200, BREACH_PATH: 200})
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id

    outcome = remediate_privesc_and_prove(
        graph,
        finding,
        # before: attacker still gets both routes -> VALIDATED
        before_executor=_CannedPrivEscExecutor(
            {CONTROL_PATH: 200, BREACH_PATH: 200}
        ),
        # after: shield denies the breach, control still succeeds -> DISPROVED
        after_executor=_CannedPrivEscExecutor(
            {CONTROL_PATH: 200, BREACH_PATH: 403}
        ),
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_privesc_fix_failed_when_breach_still_granted():
    graph, _ = _resolved_graph({CONTROL_PATH: 200, BREACH_PATH: 200})
    outcome = remediate_privesc_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedPrivEscExecutor(
            {CONTROL_PATH: 200, BREACH_PATH: 200}
        ),
        after_executor=_CannedPrivEscExecutor(
            {CONTROL_PATH: 200, BREACH_PATH: 200}  # breach still granted
        ),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_privesc_fix_failed_when_control_breaks_through_shield():
    # An over-broad shield that also blocks the attacker's OWN object is NOT a
    # proof: the after judgment goes INCONCLUSIVE (control no longer alive), so
    # the fix is not proven. This guards the honesty of the control leg.
    graph, _ = _resolved_graph({CONTROL_PATH: 200, BREACH_PATH: 200})
    outcome = remediate_privesc_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedPrivEscExecutor(
            {CONTROL_PATH: 200, BREACH_PATH: 200}
        ),
        after_executor=_CannedPrivEscExecutor(
            {CONTROL_PATH: 403, BREACH_PATH: 403}  # control ALSO broken
        ),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "INCONCLUSIVE"


def test_remediate_privesc_fix_not_proven_when_escalation_did_not_reproduce():
    # The after-shield judge is DISPROVED, but the escalation did NOT reproduce
    # on the pre-fix re-probe (before != VALIDATED). A shield cannot take credit
    # for closing a boundary that was already holding, so FIX_PROVEN requires
    # the full VALIDATED -> DISPROVED flip, not just after == DISPROVED.
    graph, _ = _resolved_graph({CONTROL_PATH: 200, BREACH_PATH: 200})
    outcome = remediate_privesc_and_prove(
        graph,
        _confirmed_finding(graph),
        # before: breach already denied -> DISPROVED (no live reproduction)
        before_executor=_CannedPrivEscExecutor(
            {CONTROL_PATH: 200, BREACH_PATH: 403}
        ),
        # after: also denied -> DISPROVED
        after_executor=_CannedPrivEscExecutor(
            {CONTROL_PATH: 200, BREACH_PATH: 403}
        ),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.before_status == "DISPROVED"
    assert outcome.verification.after_status == "DISPROVED"
    assert not outcome.verification.proven


def test_remediate_non_privesc_finding_is_not_applicable():
    from dataclasses import replace

    graph, _ = _resolved_graph({CONTROL_PATH: 200, BREACH_PATH: 200})
    foreign = replace(
        _confirmed_finding(graph), kind="authorization_policy_violation"
    )
    outcome = remediate_privesc_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"


# --- live integration: real reverse proxy denies the breach, keeps control --

class _StubUpstreamHandler(BaseHTTPRequestHandler):
    """The pre-fix vulnerable target.

    Grants ANY authenticated caller BOTH routes (the broken access control),
    but denies an anonymous caller (401 when no ``Authorization`` header). The
    anonymous denial is what lets the three-probe judge attribute the breach to
    the attacker's identity: before the fix the attacker crosses the boundary
    (VALIDATED) while an anonymous caller is refused, so the route is not merely
    public.
    """

    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        if not self.headers.get("Authorization"):
            body = b'{"error":"unauthorized"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def test_live_enforcer_denies_breach_but_forwards_control():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _StubUpstreamHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"

        # Seed a fresh graph bound to the live stub, drive it to a confirmed
        # escalation, then prove the fix through the REAL reverse proxy.
        graph = SecurityGraph()
        run_privesc_investigation(
            graph,
            _matrix(dict(_HORIZONTAL_CHECK)),
            target_base=upstream_base,
            executor=_CannedPrivEscExecutor({CONTROL_PATH: 200, BREACH_PATH: 200}),
        )
        finding = _confirmed_finding(graph)

        outcome = remediate_privesc_and_prove(graph, finding, use_enforcer=True)

        assert outcome.result == "FIX_PROVEN"
        assert outcome.verification.before_status == "VALIDATED"
        assert outcome.verification.after_status == "DISPROVED"
        assert outcome.verification.observed_status_code == 403
    finally:
        upstream.shutdown()
        upstream.server_close()
