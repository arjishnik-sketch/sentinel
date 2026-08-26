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


# ---- adaptive EXECUTE: failure-cause + retry --------------------------------

def _login_plan():
    from app.autonomous.hypotheses import Hypothesis
    from app.autonomous.surface import Surface
    hyp = Hypothesis("sql_injection", "http://shop.test/rest/user/login", "POST",
                     "email", "body_json", success_statuses=(200, 401, 403))
    return O.Plan(surface=Surface(target="http://shop.test"), hypotheses=(hyp,))


def test_adaptive_confirms_after_shape_toggle_and_replaces_slot():
    """body_json is INCONCLUSIVE, body_form VALIDATES → the retry supersedes the
    slot with a CONFIRMED whose hypothesis carries the WINNING shape."""
    def judge(h, p=None):
        if h.location == "body_form":
            return ("VALIDATED", "auth bypass", {"e": 1})
        return ("INCONCLUSIVE", "judge produced no probe result", None)

    verdicts = O.run_plan_adaptive(_login_plan(), {"sql_injection": judge}, max_rounds=2)
    assert len(verdicts) == 1                          # count never inflates
    v = verdicts[0]
    assert v.status == O.VERDICT_CONFIRMED
    assert v.hypothesis.location == "body_form"        # the proving shape
    assert v.detail.startswith("[refined via location body_json→body_form]")


def test_adaptive_single_round_is_a_plain_forward_pass():
    def judge(h, p=None):
        return ("VALIDATED", "", None) if h.location == "body_form" else ("INCONCLUSIVE", "", None)
    verdicts = O.run_plan_adaptive(_login_plan(), {"sql_injection": judge}, max_rounds=1)
    assert verdicts[0].status == O.VERDICT_INCONCLUSIVE  # no retry with max_rounds=1


def test_adaptive_never_retries_a_terminal_verdict():
    calls = []

    def judge(h, p=None):
        calls.append(h.location)
        return ("DISPROVED", "escaped", None)

    verdicts = O.run_plan_adaptive(_login_plan(), {"sql_injection": judge}, max_rounds=3)
    assert verdicts[0].status == O.VERDICT_DISPROVED
    assert calls == ["body_json"]                      # judged once, never retried


def test_adaptive_keeps_original_when_no_variant_improves():
    def judge(h, p=None):
        return ("INCONCLUSIVE", "unanchored", None)    # every shape fails to measure
    verdicts = O.run_plan_adaptive(_login_plan(), {"sql_injection": judge}, max_rounds=3)
    assert verdicts[0].status == O.VERDICT_INCONCLUSIVE
    assert verdicts[0].hypothesis.location == "body_json"  # original slot preserved


def test_adaptive_inconclusive_upgrades_to_disproved_when_measured():
    """A measured negative beats an unmeasured one: INCONCLUSIVE→DISPROVED is a
    strict improvement and supersedes the slot."""
    def judge(h, p=None):
        return ("DISPROVED", "escaped", None) if h.location == "body_form" \
            else ("INCONCLUSIVE", "unanchored", None)
    verdicts = O.run_plan_adaptive(_login_plan(), {"sql_injection": judge}, max_rounds=2)
    assert verdicts[0].status == O.VERDICT_DISPROVED
    assert verdicts[0].hypothesis.location == "body_form"


def test_investigate_max_rounds_threads_through():
    judges = {"sql_injection": (lambda h, p=None:
                                ("VALIDATED", "", None) if h.location == "body_form"
                                else ("INCONCLUSIVE", "", None))}
    plan_recon = _recon([])
    findings = _findings(logins=["http://shop.test/rest/user/login"])
    report = O.investigate(plan_recon, findings, judges, use_llm=False, max_rounds=2)
    # the login SQLi rule-floor poses body_json; the retry toggles to body_form → CONFIRMED
    assert any(v.status == O.VERDICT_CONFIRMED and v.hypothesis.technique == "sql_injection"
               for v in report.verdicts)


# ---- augment_plan: fold tool NOMINATIONS into an existing plan --------------

def _thyp(technique, url, param, *, severity="MEDIUM", source="rule"):
    from app.autonomous.hypotheses import Hypothesis
    return Hypothesis(technique, url, "GET", param, "query", severity=severity, source=source)


def test_augment_plan_merges_dedups_and_reranks():
    from app.autonomous.surface import Surface
    base = _thyp("xss", "http://shop.test/a", "q", severity="MEDIUM")
    plan = O.Plan(surface=Surface(target="http://shop.test"), hypotheses=(base,))
    dup = _thyp("xss", "http://shop.test/a", "q", severity="MEDIUM")          # same shape
    tool = _thyp("sql_injection", "http://shop.test/b", "id", severity="HIGH", source="tool")

    out = O.augment_plan(plan, [dup, tool])
    assert len(out.hypotheses) == 2                       # dup dropped, tool added
    assert out.hypotheses[0].technique == "sql_injection" # provable+HIGH re-ranked first
    assert out.hypotheses[0].source == "tool"
    assert out is not plan                                # a new plan, surface preserved
    assert out.surface is plan.surface


def test_augment_plan_noop_when_nothing_new_returns_same_plan():
    from app.autonomous.surface import Surface
    base = _thyp("xss", "http://shop.test/a", "q")
    plan = O.Plan(surface=Surface(target="http://shop.test"), hypotheses=(base,))
    assert O.augment_plan(plan, []) is plan                # empty → identity
    assert O.augment_plan(plan, [base]) is plan            # only a known shape → identity

