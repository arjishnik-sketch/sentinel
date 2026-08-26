"""Offline tests for Stage 5 PLAN EXECUTION (app.autonomous.execplan).

Pure data — no network, no judges run. Proves the execution shape is honest
annotation + real knobs: every hypothesis keeps a slot, assignments are correct,
concurrency is capped (never inflated), and proof-assist tools surface only when
enabled.
"""
from app.autonomous import execplan as EXEC
from app.autonomous import judges as J
from app.autonomous import orchestrator as O
from app.autonomous.hypotheses import Hypothesis
from app.autonomous.surface import Surface
from app.tools.selector import select_tools


def _plan(*hyps):
    return O.Plan(surface=Surface(target="http://shop.test"), hypotheses=tuple(hyps))


def _h(technique, param="p"):
    return Hypothesis(technique, "http://shop.test/x", "GET", param, "query")


WIRED = J.WIRED_TECHNIQUES


def test_every_hypothesis_gets_a_slot_never_dropped():
    hyps = [_h("sql_injection"), _h("xss"), _h("broken_auth"),
            _h("graphql_introspection")]
    ep = EXEC.plan_execution(_plan(*hyps), wired_techniques=WIRED)
    assert len(ep.slots) == len(hyps)                      # nothing dropped
    assert [s.hypothesis for s in ep.slots] == hyps        # order preserved


def test_assignment_judge_vs_unwired_lead_vs_lead():
    ep = EXEC.plan_execution(
        _plan(_h("sql_injection"), _h("broken_auth"), _h("graphql_introspection")),
        wired_techniques=WIRED)
    by = {s.technique: s.assignment for s in ep.slots}
    assert by["sql_injection"] == EXEC.ASSIGN_JUDGE          # provable + wired
    assert by["broken_auth"] == EXEC.ASSIGN_UNWIRED_LEAD     # provable, no single-probe judge
    assert by["graphql_introspection"] == EXEC.ASSIGN_LEAD   # non-differential
    assert ep.techniques == ("sql_injection",)               # only judged techniques


def test_workers_capped_by_slots_then_budget():
    plan = _plan(_h("sql_injection"), _h("xss"))
    # cap by slot count (2 slots < 8 workers)
    assert EXEC.plan_execution(plan, wired_techniques=WIRED, max_workers=8).max_workers == 2
    # budget caps further, never inflates
    assert EXEC.plan_execution(plan, wired_techniques=WIRED, max_workers=8,
                               budget=1).max_workers == 1
    # a budget larger than the work never raises the worker count above slots
    assert EXEC.plan_execution(plan, wired_techniques=WIRED, max_workers=8,
                               budget=99).max_workers == 2


def test_empty_plan_has_one_worker_floor():
    ep = EXEC.plan_execution(_plan(), wired_techniques=WIRED)
    assert ep.slots == () and ep.max_workers == 1


def test_rounds_has_a_floor_of_one():
    plan = _plan(_h("sql_injection"))
    assert EXEC.plan_execution(plan, wired_techniques=WIRED, max_rounds=0).max_rounds == 1
    assert EXEC.plan_execution(plan, wired_techniques=WIRED, max_rounds=3).max_rounds == 3


def test_tools_disabled_yields_no_tool_names():
    plan = _plan(_h("sql_injection"), _h("xss"))
    tool_plan = select_tools(plan.surface, plan.hypotheses)
    ep = EXEC.plan_execution(plan, wired_techniques=WIRED, tool_plan=tool_plan,
                             tools_enabled=False)
    assert ep.tools == ()
    assert all(s.tools == () for s in ep.slots)


def test_tools_enabled_maps_proof_assist_per_technique():
    plan = _plan(_h("sql_injection"), _h("xss"), _h("broken_auth"))
    tool_plan = select_tools(plan.surface, plan.hypotheses)
    ep = EXEC.plan_execution(plan, wired_techniques=WIRED, tool_plan=tool_plan,
                             tools_enabled=True)
    by = {s.technique: s.tools for s in ep.slots}
    assert "sqlmap" in by["sql_injection"]      # sqlmap nominates SQLi
    assert "dalfox" in by["xss"]                # dalfox nominates XSS
    assert by["broken_auth"] == ()              # no proof-assist tool for this class
    assert "sqlmap" in ep.tools and "dalfox" in ep.tools
    assert ep.tools_enabled is True


def test_derived_views_partition_the_slots():
    ep = EXEC.plan_execution(
        _plan(_h("sql_injection"), _h("broken_auth"), _h("graphql_introspection")),
        wired_techniques=WIRED)
    assert len(ep.judged) + len(ep.unwired_leads) + len(ep.leads) == len(ep.slots)
    assert len(ep.judged) == 1 and len(ep.unwired_leads) == 1 and len(ep.leads) == 1
