"""Offline tests for the autonomous orchestrator (no network/Ollama/tools).

Judges are injected fakes; the whole loop is deterministic here.
"""
from app.autonomous import orchestrator as O
from app.autonomous.probe import Probe
from app.autonomous import session as S


# ---- shared fakes/helpers ---------------------------------------------------

def _recon(crawl, tech=()):
    return {"target": "http://shop.test", "crawl": crawl, "alive": [{"tech": list(tech)}]}


def _findings(**kw):
    base = {
        "parameters": [], "logins": [], "javascript": [], "graphql": [],
        "swagger": [], "uploads": [], "apis": [],
    }
    base.update(kw)
    return base


def _transport(payload):
    def t(system, user, *, model, url, timeout, num_predict):
        return payload
    return t


class FakeProber:
    def __init__(self, decide):
        self.decide = decide
        self.calls = []

    def request(self, method, url, *, headers=None, body=None):
        cookie = (headers or {}).get("Cookie", "")
        self.calls.append((method, url, cookie))
        status, body_text = self.decide(url, cookie)
        return Probe(method, url, status, {}, (), body_text)


def _param_plan(use_llm=False, transport=None):
    return O.build_plan(
        _recon(["http://shop.test/item?id=1"]),
        _findings(parameters=["id"]),
        use_llm=use_llm, transport=transport,
    )


# ---- plan build + ranking ---------------------------------------------------

def test_build_plan_ranks_provable_first_and_covers_param():
    plan = _param_plan()
    assert plan.surface.host == "shop.test"
    techs = {h.technique for h in plan.hypotheses}
    assert {"sql_injection", "xss", "path_traversal"} <= techs
    # provable-first ordering: no lead may precede a provable hypothesis
    seen_lead = False
    for h in plan.hypotheses:
        if not h.provable:
            seen_lead = True
        elif seen_lead:
            raise AssertionError("a provable hypothesis followed a lead in the ranking")


def test_build_plan_llm_lead_lands_in_lead_tier():
    payload = '{"hypotheses":[{"technique":"graphql_introspection","url":"http://shop.test/graphql"}]}'
    plan = _param_plan(use_llm=True, transport=_transport(payload))
    lead_techs = {h.technique for h in plan.leads}
    assert "graphql_introspection" in lead_techs
    assert "sql_injection" in {h.technique for h in plan.provable}  # rule floor intact


# ---- skill selection --------------------------------------------------------

def test_select_skills_none_is_empty():
    assert O.select_skills(object(), None) == ()


def test_select_skills_prefers_selector_and_limits():
    class Idx:
        def select_for_surface(self, surface):
            return [f"card{i}" for i in range(50)]
    cards = O.select_skills(object(), Idx(), limit=5)
    assert cards == ("card0", "card1", "card2", "card3", "card4")


def test_select_skills_plain_iterable_and_flaky_is_safe():
    assert O.select_skills(object(), ["a", "b", "c"], limit=2) == ("a", "b")

    class Boom:
        def select(self, surface):
            raise RuntimeError("kb down")
    assert O.select_skills(object(), Boom()) == ()  # never breaks the loop


# ---- adjudication -----------------------------------------------------------

def _hyp(technique="sql_injection"):
    from app.autonomous.hypotheses import Hypothesis
    return Hypothesis(technique, "http://shop.test/item", param="id")


def test_adjudicate_validated_becomes_confirmed():
    judges = {"sql_injection": lambda h, p: ("VALIDATED", "boolean toggled", {"e": 1})}
    v = O.adjudicate(_hyp(), judges)
    assert v.status == O.VERDICT_CONFIRMED and v.confirmed and v.detail == "boolean toggled"


def test_adjudicate_disproved_and_object_shape():
    class J:
        status = "DISPROVED"
        reason = "escaped"
    v = O.adjudicate(_hyp(), {"sql_injection": lambda h, p: J()})
    assert v.status == O.VERDICT_DISPROVED and v.detail == "escaped"


def test_adjudicate_no_judge_and_nonprovable_are_leads():
    assert O.adjudicate(_hyp(), {}).status == O.VERDICT_LEAD                     # provable, un-wired
    assert O.adjudicate(_hyp("graphql_introspection"), {}).status == O.VERDICT_LEAD  # non-differential


def test_adjudicate_judge_fault_is_error_not_confirm():
    def boom(h, p):
        raise ValueError("kaboom")
    v = O.adjudicate(_hyp(), {"sql_injection": boom})
    assert v.status == O.VERDICT_ERROR and "kaboom" in v.detail


# ---- concurrent run ---------------------------------------------------------

def test_run_plan_is_concurrent_ordered_and_tiered():
    plan = _param_plan()
    judges = {
        "sql_injection": lambda h, p: ("VALIDATED", "", None),
        "xss": lambda h, p: ("DISPROVED", "", None),
        # path_traversal intentionally un-wired -> LEAD
    }
    verdicts = O.run_plan(plan, judges, max_workers=8)
    assert len(verdicts) == len(plan.hypotheses)
    # order mirrors plan.hypotheses regardless of completion order
    assert [v.hypothesis for v in verdicts] == list(plan.hypotheses)
    by_tech = {v.hypothesis.technique: v.status for v in verdicts}
    assert by_tech["sql_injection"] == O.VERDICT_CONFIRMED
    assert by_tech["xss"] == O.VERDICT_DISPROVED
    assert by_tech["path_traversal"] == O.VERDICT_LEAD


def test_run_plan_empty_is_empty():
    assert O.run_plan(O.Plan(surface=None, hypotheses=()), {}) == []


# ---- session-aware stage ----------------------------------------------------

def test_probe_session_bisects_and_mutates_holding_cookie():
    prober = FakeProber(lambda url, cookie: (200 if "sid=" in cookie else 401, url))
    sm = O.probe_session(
        prober, "http://shop.test/item?id=1", "sid=abc; theme=dark",
        mutate=[{"param": "id", "values": ["2", "3"]}],
    )
    assert sm.cookie_report.load_bearing == ("sid",)
    assert set(sm.cookie_report.placeholders) == {"theme"}
    assert len(sm.mutations) == 1
    mutated = [p.url for _v, p in sm.mutations[0].mutations]
    assert any("id=2" in u for u in mutated) and any("id=3" in u for u in mutated)
    # the full captured jar is held constant on every mutation call
    mutation_cookies = {c for _m, _u, c in prober.calls if "id=2" in _u or "id=3" in _u}
    assert mutation_cookies == {"sid=abc; theme=dark"}


# ---- end-to-end (offline) ---------------------------------------------------

def test_investigate_produces_tiered_report():
    judges = {"sql_injection": lambda h, p: ("VALIDATED", "", None)}
    report = O.investigate(
        _recon(["http://shop.test/item?id=1"]),
        _findings(parameters=["id"]),
        judges, use_llm=False,
    )
    assert report.confirmed and report.confirmed[0].hypothesis.technique == "sql_injection"
    assert all(v.status != O.VERDICT_ERROR for v in report.verdicts)

