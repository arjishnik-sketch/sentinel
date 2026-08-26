"""Stage 5 PLAN EXECUTION — turn a built Plan into the concrete execution shape:
the ordered work slots, how each hypothesis will be adjudicated (a wired pure
judge, a provable class with no single-probe judge, or an honest lead), the real
worker concurrency, the bounded retry-round budget, and which in-scope
proof-assist tools are available per technique.

CONTRACT: pure DATA. It decides nothing, opens nothing, confirms nothing. This is
honest ANNOTATION plus a real concurrency/rounds knob — NOT a coverage gate: every
hypothesis in the plan gets a slot, and no hypothesis is ever dropped here. The one
place coverage is intentionally focused is upstream (Stage 2 SELECT ENDPOINTS), and
that pruning is explicit + budgeted. A ``budget`` here only CAPS parallelism (to be
gentler on a fragile target); it never removes work.
"""
from __future__ import annotations

from dataclasses import dataclass


# How a hypothesis will be adjudicated downstream.
ASSIGN_JUDGE = "judge"                 # provable + a wired single-probe pure judge
ASSIGN_UNWIRED_LEAD = "unwired_lead"   # provable class, no single-probe judge → LEAD (needs a matrix)
ASSIGN_LEAD = "lead"                   # non-differential technique → honest LEAD


@dataclass(frozen=True)
class ExecutionSlot:
    hypothesis: object
    technique: str
    assignment: str
    tools: tuple = ()          # in-scope proof-assist tool names targeting this technique

    @property
    def is_judged(self) -> bool:
        return self.assignment == ASSIGN_JUDGE


@dataclass(frozen=True)
class ExecutionPlan:
    slots: tuple = ()
    max_workers: int = 1
    max_rounds: int = 1
    tools: tuple = ()           # all in-scope proof-assist tool names (deduped, stable)
    tools_enabled: bool = False

    @property
    def judged(self):
        return tuple(s for s in self.slots if s.assignment == ASSIGN_JUDGE)

    @property
    def unwired_leads(self):
        return tuple(s for s in self.slots if s.assignment == ASSIGN_UNWIRED_LEAD)

    @property
    def leads(self):
        return tuple(s for s in self.slots if s.assignment == ASSIGN_LEAD)

    @property
    def techniques(self):
        """Distinct techniques that will actually be judged, first-seen order."""
        out, seen = [], set()
        for s in self.judged:
            if s.technique not in seen:
                seen.add(s.technique)
                out.append(s.technique)
        return tuple(out)


def _assignment(hyp, wired) -> str:
    if not getattr(hyp, "provable", False):
        return ASSIGN_LEAD
    return ASSIGN_JUDGE if hyp.technique in wired else ASSIGN_UNWIRED_LEAD


def _assist_names_for(tool_plan, technique) -> tuple:
    if tool_plan is None:
        return ()
    try:
        return tuple(r.name for r in tool_plan.for_technique(technique))
    except Exception:
        return ()


def _all_assist_names(tool_plan) -> tuple:
    if tool_plan is None:
        return ()
    try:
        return tuple(r.name for r in tool_plan.assist())
    except Exception:
        return ()


def plan_execution(plan, *, wired_techniques=(), tool_plan=None, tools_enabled=False,
                   max_workers=8, max_rounds=2, budget=None) -> ExecutionPlan:
    """Derive the execution shape from a built plan. NEVER drops a hypothesis.

    ``budget`` optionally CAPS concurrency (gentler on a fragile target); it never
    removes a slot. ``max_workers`` is derived as ``min(cap, budget, num_slots)``
    with a floor of 1, so the returned worker count matches what will actually run.
    """
    wired = set(wired_techniques)
    hyps = tuple(getattr(plan, "hypotheses", ()) or ())

    slots = []
    for h in hyps:
        assignment = _assignment(h, wired)
        tools = _assist_names_for(tool_plan, h.technique) if tools_enabled else ()
        slots.append(ExecutionSlot(
            hypothesis=h, technique=h.technique, assignment=assignment, tools=tools))

    caps = [max_workers, len(slots)]
    if budget is not None and budget > 0:
        caps.append(budget)
    workers = max(1, min(caps))

    tools = _all_assist_names(tool_plan) if tools_enabled else ()
    return ExecutionPlan(
        slots=tuple(slots), max_workers=workers, max_rounds=max(1, max_rounds),
        tools=tuple(tools), tools_enabled=bool(tools_enabled))
