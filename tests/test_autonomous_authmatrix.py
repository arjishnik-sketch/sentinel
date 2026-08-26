"""Offline tests for the AUTH MATRIX stage (app.autonomous.authmatrix).

Proves the §1 contract holds for the matrix classes: the stage NEVER mints a
verdict — it runs the SAME pure judges (here injected as seams) and adapts their
ProbeResults, VALIDATED→CONFIRMED via the single orchestrator translation site.
broken_auth fires only with a genuine token (never a blind run); privesc fires on
a declared matrix; the token VALUE never leaks into a note. No network, no files.
"""
from dataclasses import dataclass

from app.autonomous import authmatrix as AM
from app.autonomous import orchestrator as O
from app.autonomous import report as R
from app.autonomous.steer import OperatorDirective

from app.security_graph.broken_auth.broken_auth_policy import (
    BrokenAuthCheck, BrokenAuthPolicy, BrokenAuthPrincipal)
from app.security_graph.privesc.privesc_policy import (
    PrivEscCheck, PrivEscPolicy, PrivEscPrincipal)

TARGET = "http://shop.test"


@dataclass(frozen=True)
class FakeResult:
    hypothesis_id: str
    status: str
    reason: str = "differential reproduced"
    claim: str = "route accepts a forged token"
    severity: str = "HIGH"


class FakeGraph:
    """Minimal stand-in: authmatrix only reads .experiments off the graph."""
    def __init__(self):
        self.experiments = {}


def _ba_policy():
    return BrokenAuthPolicy(
        principal=BrokenAuthPrincipal(name="authenticated", role="admin"),
        checks=(BrokenAuthCheck(forgery="alg_none", method="GET", path="/admin"),))


def _pe_policy():
    return PrivEscPolicy(
        principals=(PrivEscPrincipal(name="alice"), PrivEscPrincipal(name="bob")),
        checks=(PrivEscCheck(type="horizontal", attacker="alice", victim="bob",
                             breach_method="GET", breach_path="/orders/2"),))


# ---- token injection --------------------------------------------------------

def test_inject_bearer_binds_token_as_sole_authenticator():
    bound = AM.inject_bearer(_ba_policy(), "eyJ.a.b")
    assert bound.principal.headers == (("Authorization", "Bearer eyJ.a.b"),)
    assert bound.principal.name == "authenticated" and bound.principal.role == "admin"


def test_inject_empty_token_leaves_principal_tokenless():
    bound = AM.inject_bearer(_ba_policy(), "")
    assert bound.principal.headers == ()


# ---- broken_auth adaptation -------------------------------------------------

def test_broken_auth_validated_becomes_confirmed_and_injects_token():
    seen = {}

    def fake_run(graph, policy, *, target_base):
        seen["headers"] = policy.principal.headers
        seen["target"] = target_base
        return [FakeResult("ba-1", "VALIDATED")]

    verdicts = AM.broken_auth_verdicts(
        TARGET, _ba_policy(), "tok.tok.tok",
        _run=fake_run, graph_factory=FakeGraph)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.status == O.VERDICT_CONFIRMED
    assert v.hypothesis.technique == "broken_auth"
    assert v.evidence.technique == "broken_auth" and v.evidence.result.hypothesis_id == "ba-1"
    # the genuine token was injected as the sole authenticator before the judge ran
    assert seen["headers"] == (("Authorization", "Bearer tok.tok.tok"),)
    assert seen["target"] == TARGET


def test_broken_auth_without_token_is_skipped_never_blind_run():
    called = {"n": 0}

    def fake_run(graph, policy, *, target_base):
        called["n"] += 1
        return [FakeResult("ba-1", "VALIDATED")]

    assert AM.broken_auth_verdicts(TARGET, _ba_policy(), None, _run=fake_run) == []
    assert called["n"] == 0  # the judge is never even invoked without a token


# ---- privesc adaptation -----------------------------------------------------

def test_privesc_maps_each_probe_result_status():
    def fake_run(graph, policy, *, target_base):
        return [FakeResult("pe-1", "VALIDATED"), FakeResult("pe-2", "DISPROVED"),
                FakeResult("pe-3", "INCONCLUSIVE")]

    verdicts = AM.privesc_verdicts(TARGET, _pe_policy(),
                                   _run=fake_run, graph_factory=FakeGraph)
    statuses = {v.status for v in verdicts}
    assert statuses == {O.VERDICT_CONFIRMED, O.VERDICT_DISPROVED, O.VERDICT_INCONCLUSIVE}
    assert all(v.hypothesis.technique == "privilege_escalation" for v in verdicts)


def test_privesc_no_checks_is_empty():
    assert AM.privesc_verdicts(TARGET, PrivEscPolicy(), _run=lambda *a, **k: []) == []


# ---- synthetic hypothesis pulls the real breach request ---------------------

def test_synthetic_hypothesis_uses_breach_request_from_graph():
    class Req:
        method, url = "DELETE", "http://shop.test/orders/2"

    class Exp:
        hypothesis_id, action, request = "pe-1", "probe_privilege_escalation_breach", Req()

    graph = FakeGraph()
    graph.experiments = {"e": Exp()}
    hyp = AM._synthetic_hypothesis("privilege_escalation", FakeResult("pe-1", "VALIDATED"),
                                   graph, TARGET, source="operator")
    assert hyp.method == "DELETE" and hyp.url == "http://shop.test/orders/2"
    assert hyp.source == "operator"


# ---- run_auth_matrix orchestration ------------------------------------------

def test_run_auth_matrix_runs_both_classes():
    ctx = AM.AuthContext(broken_auth_policy=_ba_policy(), privesc_policy=_pe_policy(),
                         token="t.t.t")
    verdicts = AM.run_auth_matrix(
        TARGET, ctx,
        _run_broken_auth=lambda *a, **k: [FakeResult("ba", "VALIDATED")],
        _run_privesc=lambda *a, **k: [FakeResult("pe", "DISPROVED")],
        graph_factory=FakeGraph)
    techs = sorted(v.hypothesis.technique for v in verdicts)
    assert techs == ["broken_auth", "privilege_escalation"]


def test_run_auth_matrix_skips_broken_auth_without_token():
    ctx = AM.AuthContext(broken_auth_policy=_ba_policy(), privesc_policy=None, token=None)
    assert AM.run_auth_matrix(TARGET, ctx,
                              _run_broken_auth=lambda *a, **k: [FakeResult("x", "VALIDATED")]) == []


# ---- context resolution -----------------------------------------------------

def test_resolve_context_token_from_directive_and_matrix_precedence():
    d = OperatorDirective(token="dir.tok", matrix_path="/tmp/m.json")
    ba = _ba_policy()
    ctx = AM.resolve_auth_context(
        d, env={},
        load_broken_auth=lambda p: ba if p == "/tmp/m.json" else BrokenAuthPolicy(),
        load_privesc=lambda p: PrivEscPolicy())
    assert ctx.token == "dir.tok"
    assert ctx.has_broken_auth and ctx.broken_auth_policy is ba


def test_resolve_context_env_token_and_dedicated_paths():
    env = {"SENTINEL_SESSION_TOKEN": "env.tok",
           "SENTINEL_PRIVESC_POLICY": "/p.json"}
    ctx = AM.resolve_auth_context(
        None, env=env,
        load_broken_auth=lambda p: BrokenAuthPolicy(),
        load_privesc=lambda p: _pe_policy() if p == "/p.json" else PrivEscPolicy())
    assert ctx.token == "env.tok"
    assert ctx.has_privesc and not ctx.has_broken_auth


def test_resolve_context_note_never_leaks_token_value():
    d = OperatorDirective(token="SUPER-SECRET-JWT", matrix_path="/m.json")
    ctx = AM.resolve_auth_context(
        d, env={}, load_broken_auth=lambda p: _ba_policy(),
        load_privesc=lambda p: PrivEscPolicy())
    joined = " ".join(ctx.notes)
    assert "SUPER-SECRET-JWT" not in joined
    assert "token captured" in joined  # presence reported, value never


def test_resolve_context_load_failure_degrades_to_note():
    def boom(_p):
        raise ValueError("bad json")

    ctx = AM.resolve_auth_context(
        None, env={"SENTINEL_BROKEN_AUTH_POLICY": "/x.json"},
        load_broken_auth=boom, load_privesc=lambda p: PrivEscPolicy())
    assert ctx.broken_auth_policy is None
    assert any("load failed" in n for n in ctx.notes)


def test_resolve_context_broken_auth_without_token_reports_skip():
    ctx = AM.resolve_auth_context(
        OperatorDirective(matrix_path="/m.json"), env={},
        load_broken_auth=lambda p: _ba_policy(), load_privesc=lambda p: PrivEscPolicy())
    assert not ctx.has_broken_auth  # policy present but no token
    assert any("NO token" in n for n in ctx.notes)


# ---- report integration: a matrix CONFIRMED renders as a finding ------------

def test_matrix_confirmed_verdict_renders_in_report():
    verdicts = AM.broken_auth_verdicts(
        TARGET, _ba_policy(), "t.t.t",
        _run=lambda g, p, *, target_base: [FakeResult("ba-1", "VALIDATED")],
        graph_factory=FakeGraph)
    report = O.Report(plan=O.Plan(surface=None), verdicts=tuple(verdicts))
    model = R.build_report(report, target=TARGET)
    assert model.counts["confirmed"] == 1
    assert model.findings[0].technique == "broken_auth"
