"""Offline tests for the judge bridge (app.autonomous.judges).

Every security_graph ``run_*`` call is replaced by a recording fake via the
``_run`` seam, so these prove the ADAPTER (policy/check construction, baseline
anchoring, location mapping, honest INCONCLUSIVE fallbacks) with zero network —
never the real differential judges, which have their own live-proven suites.
"""
from app.autonomous import judges as J
from app.autonomous import orchestrator as O
from app.autonomous.hypotheses import Hypothesis


class FakeRun:
    """Stand-in for run_<class>_investigation. Records (target_base, policy)."""

    def __init__(self, status="VALIDATED", reason="ok", results=None):
        self.status, self.reason, self._results = status, reason, results
        self.calls = []

    def __call__(self, graph, policy, *, target_base):
        self.calls.append((target_base, policy))
        if self._results is not None:
            return self._results
        return [type("R", (), {"status": self.status, "reason": self.reason})()]


def _h(technique, url="http://shop.test/item?id=1", param="id", location="query", method="GET"):
    return Hypothesis(technique, url, method, param, location)


# ---- wiring -----------------------------------------------------------------

def test_default_judges_wires_only_single_probe_differentials():
    d = J.default_judges()
    assert set(d) == {"sql_injection", "xss", "path_traversal", "ssti",
                      "open_redirect", "ssrf", "cors"}
    for lead in ("broken_auth", "idor", "privilege_escalation"):
        assert lead not in d          # need a login/identity matrix -> honest LEAD


# ---- injection baseline anchoring + target derivation -----------------------

def test_injection_uses_observed_value_as_baseline_and_correct_target():
    fake = FakeRun(status="VALIDATED", reason="boolean toggled")
    h = _h("sql_injection", "http://shop.test/rest/search?q=apple", param="q")
    status, reason, ev = J.make_judge("sql_injection")(h, None, _run=fake)
    assert status == "VALIDATED" and reason == "boolean toggled" and ev is not None
    base, policy = fake.calls[0]
    assert base == "http://shop.test"
    chk = policy.checks[0]
    assert chk.path == "/rest/search" and chk.param == "q"
    assert chk.baseline_value == "apple"      # observed value = the real anchor


def test_injection_baseline_falls_back_to_benign_token():
    fake = FakeRun()
    J.make_judge("sql_injection")(_h("sql_injection", "http://shop.test/rest/search", param="q"),
                                  None, _run=fake)
    assert fake.calls[0][1].checks[0].baseline_value == J._BENIGN_TOKEN


# ---- location mapping -------------------------------------------------------

def test_location_body_maps_to_body_form():
    fake = FakeRun()
    h = _h("sql_injection", "http://shop.test/login", param="email", location="body", method="POST")
    J.make_judge("sql_injection")(h, None, _run=fake)
    chk = fake.calls[0][1].checks[0]
    assert chk.location == "body_form" and chk.method == "POST"


def test_location_body_json_maps_and_forwards_success_statuses():
    # A login-body SQLi hypothesis maps location straight through to body_json AND
    # carries its 401/403 anchor onto the InjectionPolicy, so the pure judge's
    # baseline gate (which defaults to 2xx) accepts a login's legitimate baseline.
    fake = FakeRun()
    h = Hypothesis("sql_injection", "http://shop.test/rest/user/login", "POST",
                   "email", "body_json", success_statuses=(200, 401, 403))
    J.make_judge("sql_injection")(h, None, _run=fake)
    _base, policy = fake.calls[0]
    assert policy.checks[0].location == "body_json"
    assert policy.success_statuses == (200, 401, 403)


def test_injection_policy_keeps_2xx_default_without_success_statuses():
    # An ordinary query hypothesis carries no anchor override → the InjectionPolicy
    # keeps its conservative 2xx default (no silent broadening of the anchor).
    fake = FakeRun()
    J.make_judge("sql_injection")(_h("sql_injection", "http://shop.test/rest/search", param="q"),
                                  None, _run=fake)
    assert fake.calls[0][1].success_statuses == tuple(range(200, 300))


def test_unknown_location_falls_back_to_query():
    fake = FakeRun()
    J.make_judge("xss")(_h("xss", param="q", location="header"), None, _run=fake)
    assert fake.calls[0][1].checks[0].location == "query"


def test_location_path_maps_through_and_anchors_last_segment():
    # A path-located SQLi hypothesis maps location straight through to the
    # security_graph "path" vocab (no silent degrade to "query"), and the baseline
    # anchor is the concrete id already sitting in the injected segment
    # (…/users/1 -> "1"), so the differential reproduces the response recon saw.
    fake = FakeRun()
    h = _h("sql_injection", "http://shop.test/api/users/1", param="users", location="path")
    J.make_judge("sql_injection")(h, None, _run=fake)
    base, policy = fake.calls[0]
    assert base == "http://shop.test"
    chk = policy.checks[0]
    assert chk.location == "path"
    assert chk.path == "/api/users/1"       # concrete crawled path = its own template
    assert chk.baseline_value == "1"        # the id already in the segment = the anchor


def test_loc_and_baseline_path_helpers_are_pure():
    assert J._loc("path") == "path"
    h = _h("sql_injection", "http://shop.test/rest/products/42", param="products", location="path")
    assert J._baseline(h) == "42"


# ---- honest INCONCLUSIVE fallbacks (never a manufactured verdict) -----------

def test_param_required_technique_without_param_is_inconclusive_and_skips_run():
    fake = FakeRun()
    status, reason, ev = J.make_judge("xss")(_h("xss", param=None), None, _run=fake)
    assert status == "INCONCLUSIVE" and "no parameter" in reason and ev is None
    assert fake.calls == []            # judge never invoked


def test_no_origin_is_inconclusive():
    fake = FakeRun()
    status, reason, _ = J.make_judge("sql_injection")(_h("sql_injection", "/only/path"), None, _run=fake)
    assert status == "INCONCLUSIVE" and fake.calls == []


def test_empty_results_is_inconclusive():
    fake = FakeRun(results=[])
    status, reason, _ = J.make_judge("ssti")(_h("ssti", param="tpl"), None, _run=fake)
    assert status == "INCONCLUSIVE" and "no probe result" in reason


# ---- cors is the param-free class -------------------------------------------

def test_cors_needs_no_param():
    fake = FakeRun(status="VALIDATED", reason="reflected origin")
    status, _r, _e = J.make_judge("cors")(_h("cors", "http://shop.test/api/data", param=None),
                                           None, _run=fake)
    assert status == "VALIDATED" and len(fake.calls) == 1
    assert not hasattr(fake.calls[0][1].checks[0], "param")   # CorsCheck has no param


def test_status_passthrough_disproved():
    fake = FakeRun(status="DISPROVED", reason="escaped")
    assert J.make_judge("path_traversal")(_h("path_traversal", param="file"), None, _run=fake)[0] == "DISPROVED"


# ---- evidence carries the proven graph (so PATCH->PROVE reuses it) -----------

def test_evidence_carries_graph_policy_and_technique():
    sentinel_graph = object()
    fake = FakeRun(status="VALIDATED", reason="boolean toggled")
    _s, _r, ev = J.make_judge("sql_injection")(
        _h("sql_injection", "http://shop.test/rest/search?q=apple", param="q"),
        None, _run=fake, _graph=lambda: sentinel_graph,
    )
    assert isinstance(ev, J.JudgeEvidence)
    assert ev.graph is sentinel_graph          # the very graph the judge proved on
    assert ev.technique == "sql_injection"
    assert ev.policy is fake.calls[0][1]        # the single-check policy that ran
    assert ev.status == "VALIDATED" and ev.reason == "boolean toggled"  # delegates to result


# ---- integration with the orchestrator's dispose seam -----------------------

def test_orchestrator_confirms_via_real_adapter():
    fake = FakeRun(status="VALIDATED", reason="boolean toggled")
    judges = {"sql_injection": lambda h, p=None: J.make_judge("sql_injection")(h, p, _run=fake)}
    v = O.adjudicate(_h("sql_injection"), judges)
    assert v.confirmed and v.status == O.VERDICT_CONFIRMED and v.detail == "boolean toggled"


def test_run_plan_tiers_confirmed_disproved_and_unwired_lead():
    val, dis = FakeRun("VALIDATED", ""), FakeRun("DISPROVED", "")
    judges = {
        "sql_injection": lambda h, p=None: J.make_judge("sql_injection")(h, p, _run=val),
        "xss": lambda h, p=None: J.make_judge("xss")(h, p, _run=dis),
    }
    recon = {"target": "http://shop.test", "crawl": ["http://shop.test/item?id=1"], "alive": [{"tech": []}]}
    findings = {"parameters": ["id"], "logins": [], "javascript": [], "graphql": [],
                "swagger": [], "uploads": [], "apis": []}
    plan = O.build_plan(recon, findings, use_llm=False)
    by = {v.hypothesis.technique: v.status for v in O.run_plan(plan, judges)}
    assert by["sql_injection"] == O.VERDICT_CONFIRMED
    assert by["xss"] == O.VERDICT_DISPROVED
    assert by["path_traversal"] == O.VERDICT_LEAD     # provable but un-wired here
