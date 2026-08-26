"""Offline tests for the failure-cause analyzer (app.autonomous.refine).

The analyzer is a pure function of (verdict, surface): no network, no judge, no
LLM. It only ever PROPOSES a differently-shaped re-probe — the judge still
disposes downstream. These tests pin the deterministic floor + the scope/dedup
invariants that keep the retry loop honest and bounded.
"""
from app.autonomous import orchestrator as O
from app.autonomous import refine as RF
from app.autonomous.hypotheses import Hypothesis, _LOGIN_SUCCESS_STATUSES
from app.autonomous.surface import Surface


def _surface(params=("id",), target="http://shop.test"):
    return Surface(target=target, params=tuple(params))


def _v(hyp, status="INCONCLUSIVE", detail=""):
    return O.Verdict(hyp, status, detail=detail)


# ---- terminal verdicts are never retried ------------------------------------

def test_terminal_verdicts_yield_no_retries():
    hyp = Hypothesis("sql_injection", "http://shop.test/rest/user/login", "POST",
                     "email", "body_json")
    for status in (O.VERDICT_CONFIRMED, O.VERDICT_DISPROVED, O.VERDICT_LEAD):
        assert RF.diagnose(_v(hyp, status), _surface()) == ()


def test_error_is_retryable_like_inconclusive():
    hyp = Hypothesis("sql_injection", "http://shop.test/rest/user/login", "POST",
                     "email", "body_json")
    outs = RF.diagnose(_v(hyp, O.VERDICT_ERROR), _surface())
    assert outs and outs[0].hypothesis.location == "body_form"


# ---- POST-SQLi body-shape toggle (the wrong-login-shape fix) -----------------

def test_body_json_toggles_to_form_and_marks_mutation():
    hyp = Hypothesis("sql_injection", "http://shop.test/rest/user/login", "POST",
                     "email", "body_json", success_statuses=_LOGIN_SUCCESS_STATUSES)
    outs = RF.diagnose(_v(hyp), _surface())
    # already anchored → the single mutation is the shape toggle
    assert [o.hypothesis.location for o in outs] == ["body_form"]
    assert outs[0].mutation == "location body_json→body_form"
    assert outs[0].hypothesis.source == "retry"
    assert outs[0].hypothesis.success_statuses == _LOGIN_SUCCESS_STATUSES  # carried


def test_login_without_anchor_gets_anchor_variants():
    hyp = Hypothesis("sql_injection", "http://shop.test/login", "POST",
                     "username", "body_form")   # no success_statuses
    outs = RF.diagnose(_v(hyp), _surface())
    locs = [(o.hypothesis.location, o.hypothesis.success_statuses) for o in outs]
    # toggle (no anchor) + same-loc+anchor + toggled-loc+anchor, all distinct keys
    assert ("body_json", None) in locs
    assert ("body_form", _LOGIN_SUCCESS_STATUSES) in locs
    assert ("body_json", _LOGIN_SUCCESS_STATUSES) in locs


def test_non_login_post_only_toggles_no_anchor():
    hyp = Hypothesis("sql_injection", "http://shop.test/api/items", "POST",
                     "q", "body_json")
    outs = RF.diagnose(_v(hyp), _surface())
    assert [o.hypothesis.location for o in outs] == ["body_form"]
    assert all(o.hypothesis.success_statuses is None for o in outs)


def test_get_query_sqli_has_no_body_mutation():
    hyp = Hypothesis("sql_injection", "http://shop.test/item?id=1", "GET", "id", "query")
    assert RF.diagnose(_v(hyp), _surface()) == ()


# ---- missing-param backfill --------------------------------------------------

def test_missing_param_backfills_from_surface():
    hyp = Hypothesis("sql_injection", "http://shop.test/item", "GET", None, "query")
    outs = RF.diagnose(_v(hyp, detail="no parameter to probe for 'sql_injection'"),
                       _surface(params=("id", "q")))
    params = {o.hypothesis.param for o in outs}
    assert params == {"id", "q"}
    assert all(o.mutation.startswith("param=") for o in outs)


# ---- dedup + scope invariants ------------------------------------------------

def test_already_tried_shapes_are_dropped():
    hyp = Hypothesis("sql_injection", "http://shop.test/rest/user/login", "POST",
                     "email", "body_json", success_statuses=_LOGIN_SUCCESS_STATUSES)
    toggled = Hypothesis("sql_injection", "http://shop.test/rest/user/login", "POST",
                         "email", "body_form", success_statuses=_LOGIN_SUCCESS_STATUSES)
    assert RF.diagnose(_v(hyp), _surface(), tried={toggled.shape}) == ()


def test_propose_extra_is_appended_scoped_and_fault_tolerant():
    hyp = Hypothesis("sql_injection", "http://shop.test/item?id=1", "GET", "id", "query")
    off = Hypothesis("sql_injection", "http://evil.test/item?id=1", "GET", "id", "query")
    on = Hypothesis("xss", "http://shop.test/item?id=1", "GET", "id", "query")
    outs = RF.diagnose(_v(hyp), _surface(), propose_extra=lambda v, s: [off, on])
    techs = {o.hypothesis.technique for o in outs}
    assert "xss" in techs                       # in-scope llm proposal kept
    assert all("evil.test" not in o.hypothesis.url for o in outs)  # off-host dropped

    def boom(v, s):
        raise RuntimeError("proposer down")
    # a flaky proposer must never break the loop
    assert RF.diagnose(_v(hyp), _surface(), propose_extra=boom) == ()
