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


# ---- credential-driven token capture (Sentinel logs in itself) --------------

def test_resolve_context_captures_token_from_credentials():
    seen = {}

    def fake_login(login_url, *, username, password, target, location):
        seen.update(login_url=login_url, username=username, password=password,
                    target=target, location=location)
        return "CAPTURED.JWT.SIG", "captured 1 cookie(s)"

    d = OperatorDirective(credentials=("wiener", "peter"),
                          login_url="http://shop.test/login", matrix_path="/m.json")
    ctx = AM.resolve_auth_context(
        d, env={}, target="http://shop.test", login=fake_login,
        load_broken_auth=lambda p: _ba_policy(), load_privesc=lambda p: PrivEscPolicy())
    # a token was CAPTURED live and the class is now active
    assert ctx.token == "CAPTURED.JWT.SIG"
    assert ctx.has_broken_auth
    # the seam saw the real login inputs, incl. the matrix's declared token_location
    assert seen["username"] == "wiener" and seen["password"] == "peter"
    assert seen["login_url"] == "http://shop.test/login"
    assert seen["target"] == "http://shop.test"
    assert seen["location"] == _ba_policy().token_location  # declared location, forwarded


def test_resolve_context_captures_token_from_env_credentials():
    def fake_login(login_url, *, username, password, target, location):
        assert (username, password) == ("admin", "hunter2")
        return "T.O.K", "captured 1 cookie(s)"

    env = {"SENTINEL_LOGIN_USERNAME": "admin", "SENTINEL_LOGIN_PASSWORD": "hunter2",
           "SENTINEL_BROKEN_AUTH_POLICY": "/m.json"}
    ctx = AM.resolve_auth_context(
        None, env=env, target="http://shop.test", login=fake_login,
        load_broken_auth=lambda p: _ba_policy(), load_privesc=lambda p: PrivEscPolicy())
    assert ctx.token == "T.O.K" and ctx.has_broken_auth


def test_resolve_context_login_note_never_leaks_password_or_token():
    def fake_login(login_url, *, username, password, target, location):
        return "SECRET-CAPTURED-JWT", "captured 1 cookie(s)"

    d = OperatorDirective(credentials=("wiener", "s3cr3tP@ss"), matrix_path="/m.json")
    ctx = AM.resolve_auth_context(
        d, env={}, target="http://shop.test", login=fake_login,
        load_broken_auth=lambda p: _ba_policy(), load_privesc=lambda p: PrivEscPolicy())
    joined = " ".join(ctx.notes)
    assert "s3cr3tP@ss" not in joined          # password never surfaces
    assert "SECRET-CAPTURED-JWT" not in joined  # token value never surfaces
    assert "wiener" in joined                   # username (identity) is safe to show
    assert "token captured" in joined


def test_resolve_context_login_failure_degrades_to_note():
    def boom(login_url, *, username, password, target, location):
        raise RuntimeError("no login form")

    d = OperatorDirective(credentials=("wiener", "peter"), matrix_path="/m.json")
    ctx = AM.resolve_auth_context(
        d, env={}, target="http://shop.test", login=boom,
        load_broken_auth=lambda p: _ba_policy(), load_privesc=lambda p: PrivEscPolicy())
    assert ctx.token is None and not ctx.has_broken_auth
    assert any("credential login failed" in n for n in ctx.notes)
    assert any("NO token" in n for n in ctx.notes)  # honest final state


def test_resolve_context_explicit_token_skips_credential_login():
    called = {"n": 0}

    def fake_login(*a, **k):
        called["n"] += 1
        return "SHOULD-NOT-BE-USED", "captured"

    d = OperatorDirective(token="dir.tok", credentials=("wiener", "peter"),
                          matrix_path="/m.json")
    ctx = AM.resolve_auth_context(
        d, env={}, target="http://shop.test", login=fake_login,
        load_broken_auth=lambda p: _ba_policy(), load_privesc=lambda p: PrivEscPolicy())
    assert ctx.token == "dir.tok"     # the supplied token wins
    assert called["n"] == 0           # no needless live login when a token exists


def test_resolve_context_credentials_without_matrix_do_not_login():
    called = {"n": 0}

    def fake_login(*a, **k):
        called["n"] += 1
        return "X", "captured"

    d = OperatorDirective(credentials=("wiener", "peter"))
    ctx = AM.resolve_auth_context(
        d, env={}, target="http://shop.test", login=fake_login,
        load_broken_auth=lambda p: BrokenAuthPolicy(), load_privesc=lambda p: PrivEscPolicy())
    # no broken_auth matrix → nothing to forge FROM → never drive a login
    assert called["n"] == 0 and ctx.token is None


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


# ---- impact opt-in resolution (state-changing demo is doubly gated) ---------

def test_resolve_context_impact_disabled_by_default():
    ctx = AM.resolve_auth_context(
        OperatorDirective(token="t.t.t", matrix_path="/m.json"), env={},
        load_broken_auth=lambda p: _ba_policy(), load_privesc=lambda p: PrivEscPolicy())
    assert ctx.impact_enabled is False
    assert not any("impact demonstration ENABLED" in n for n in ctx.notes)


def test_resolve_context_impact_enabled_by_env_flag():
    ctx = AM.resolve_auth_context(
        OperatorDirective(token="t.t.t", matrix_path="/m.json"),
        env={"SENTINEL_ENABLE_IMPACT": "1"},
        load_broken_auth=lambda p: _ba_policy(), load_privesc=lambda p: PrivEscPolicy())
    assert ctx.impact_enabled is True
    assert any("impact demonstration ENABLED" in n for n in ctx.notes)


def test_run_auth_matrix_forwards_impact_flag():
    seen = {}

    def spy_broken_auth(target_base, policy, token, *, source, impact_enabled,
                        _run, graph_factory):
        seen["impact_enabled"] = impact_enabled
        return []

    ctx = AM.AuthContext(broken_auth_policy=_ba_policy(), privesc_policy=None,
                         token="t.t.t", impact_enabled=True)
    # patch the module-level broken_auth_verdicts the orchestrator calls
    original = AM.broken_auth_verdicts
    AM.broken_auth_verdicts = spy_broken_auth
    try:
        AM.run_auth_matrix(TARGET, ctx,
                           _run_broken_auth=lambda *a, **k: [])
    finally:
        AM.broken_auth_verdicts = original
    assert seen["impact_enabled"] is True
