"""Autonomous orchestrator: the loop that fuses recon → surface → KB skills →
qwen hypotheses → (session-aware probing) → tiered adjudication.

CONTRACT — "LLM/tools propose, a pure judge disposes." This module OWNS the loop
but NEVER owns a verdict. Provable hypotheses are routed to INJECTED pure judges
(the security_graph differential judges, adapted downstream); everything else is
surfaced as an honest LEAD, never conflated with a CONFIRMED result. A judge
reports VALIDATED/DISPROVED/INCONCLUSIVE; only then does the orchestrator label a
VALIDATED result CONFIRMED. The judge map is injected, so the whole orchestrator
is deterministic and fully offline-testable — no network, no Ollama, no tools.

Patch→prove and the human deploy gate live DOWNSTREAM (the CLI renderer): this
module stops at a tiered report of verdicts + leads.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace

from . import hypotheses as HYP
from . import session as SESSION
from .endpoints import select_endpoints
from .surface import Surface

# Orchestrator verdict vocabulary (distinct from the judge's VALIDATED/DISPROVED).
VERDICT_CONFIRMED = "CONFIRMED"
VERDICT_DISPROVED = "DISPROVED"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICT_LEAD = "LEAD"
VERDICT_ERROR = "ERROR"

_JUDGE_TO_VERDICT = {
    "VALIDATED": VERDICT_CONFIRMED,
    "DISPROVED": VERDICT_DISPROVED,
    "INCONCLUSIVE": VERDICT_INCONCLUSIVE,
}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def to_verdict_status(judge_status: str) -> str:
    """Translate a pure judge's word (VALIDATED/DISPROVED/INCONCLUSIVE) into the
    orchestrator's verdict vocabulary — the SINGLE VALIDATED→CONFIRMED site. An
    unknown status passes through unchanged. The auth-matrix stage reuses this so
    a matrix-driven ProbeResult becomes a Verdict by the exact same rule a
    single-probe judge does; no verdict is ever minted anywhere else."""
    return _JUDGE_TO_VERDICT.get(judge_status, judge_status)


@dataclass
class SessionMap:
    """Output of the two session-aware behaviours (may both be absent)."""
    cookie_report: object = None      # session.CookieReport | None
    mutations: tuple = ()             # tuple[session.MutationResult]


@dataclass
class Plan:
    surface: Surface
    hypotheses: tuple = ()            # deduped, provable-first, deterministic order
    skills: tuple = ()               # selected KB skill cards
    session: SessionMap = None
    endpoint_selection: object = None  # endpoints.EndpointSelection | None (Stage 2)

    @property
    def provable(self):
        return tuple(h for h in self.hypotheses if h.provable)

    @property
    def leads(self):
        return tuple(h for h in self.hypotheses if not h.provable)


# ---- PLAN: recon → surface → skills → hypotheses ----------------------------

def select_skills(surface, skills_index, *, limit=12):
    """Pick KB skill cards relevant to the observed surface.

    ``skills_index`` is duck-typed: an object exposing ``select_for_surface`` or
    ``select`` (preferred — a real KB index ranks cards by the fingerprint), or a
    plain iterable of cards. ``None`` means "no KB wired" → no cards. Never raises.
    """
    if skills_index is None:
        return ()
    selector = getattr(skills_index, "select_for_surface", None) or getattr(
        skills_index, "select", None
    )
    try:
        if selector is not None:
            try:
                cards = selector(surface)
            except TypeError:
                cards = selector()
        else:
            cards = skills_index
        return tuple(cards)[:limit]
    except Exception:
        return ()  # a flaky KB must never break the loop


def _rank(hyps):
    """Deterministic ordering: provable first, then severity, then technique/url."""
    return tuple(
        sorted(
            hyps,
            key=lambda h: (
                0 if h.provable else 1,
                _SEVERITY_ORDER.get((h.severity or "").upper(), 4),
                h.technique,
                h.url,
                h.param or "",
            ),
        )
    )


def build_plan(recon, findings, *, skills_index=None, use_llm=True, transport=None,
               max_hyps=64, endpoint_budget=None):
    """DISCOVER+SELECT-ENDPOINTS+UNDERSTAND+HYPOTHESIZE: fold live recon into a
    Surface, rank (Stage 2) — and, only when ``endpoint_budget`` is set, prune —
    the surface by injectability, select KB skills, then merge the rule floor with
    qwen breadth into a ranked plan.

    Endpoint ranking reorders which probes are posed first (so a ``max_hyps`` cap
    keeps the most promising ones); with no budget, coverage is unchanged. The
    :class:`~app.autonomous.endpoints.EndpointSelection` is attached to the Plan for
    honest reporting of what was ranked and (if budgeted) what was pruned."""
    surface = Surface.from_recon(recon, findings)
    selection = select_endpoints(surface, budget=endpoint_budget)
    surface.endpoints = selection.endpoints  # best-first; pruned only if budgeted
    skills = select_skills(surface, skills_index)
    hyps = HYP.propose(
        surface, skill_cards=skills, use_llm=use_llm, transport=transport, max_hyps=max_hyps
    )
    return Plan(surface=surface, hypotheses=_rank(hyps), skills=tuple(skills),
                endpoint_selection=selection)


def augment_plan(plan, extra_hypotheses):
    """Fold late-arriving hypotheses (e.g. tool NOMINATIONS) into an existing plan.

    Pure: no I/O. New hypotheses are shape-deduped against what the plan already
    carries — a nomination that merely restates a probe the plan already issues is
    dropped — and the survivors are merged and re-ranked (provable-first). Existing
    hypotheses are never displaced; nominations only ever WIDEN what gets judged.
    The judge still disposes every one downstream — nothing here confirms."""
    if not extra_hypotheses:
        return plan
    seen = {h.shape for h in plan.hypotheses}
    merged = list(plan.hypotheses)
    for h in extra_hypotheses:
        if h.shape in seen:
            continue
        seen.add(h.shape)
        merged.append(h)
    if len(merged) == len(plan.hypotheses):
        return plan
    return replace(plan, hypotheses=_rank(tuple(merged)))


# ---- SESSION-AWARE probing (cookie bisection + locked param mutation) --------

def probe_session(prober, url, cookie_header, *, mutate=(), authed=None, method="GET"):
    """Run both session-aware behaviours against a captured session.

    * bisect the jar → which cookies are load-bearing vs placeholders;
    * for each mutation spec ``{"param","values"[, "url","method"]}`` vary one
      parameter while holding the SAME Cookie header constant.

    Pure delegation to :mod:`app.autonomous.session`; produces evidence only.
    """
    kw = {} if authed is None else {"authed": authed}
    report = SESSION.bisect_cookies(prober, url, cookie_header, method=method, **kw)
    muts = []
    for spec in mutate or ():
        muts.append(
            SESSION.mutate_param(
                prober,
                spec.get("url", url),
                spec["param"],
                spec["values"],
                cookie_header=cookie_header,
                method=spec.get("method", method),
            )
        )
    return SessionMap(cookie_report=report, mutations=tuple(muts))


# ---- ADJUDICATE: provable → judge, everything else → honest LEAD -------------

@dataclass
class Verdict:
    hypothesis: object
    status: str
    detail: str = ""
    evidence: object = None

    @property
    def confirmed(self):
        return self.status == VERDICT_CONFIRMED


def _normalize(res):
    """Accept a judge's return in any of: (status, detail, evidence) tuple, an
    object with .status (+ .reason/.detail), or a bare status string."""
    if isinstance(res, tuple):
        status = res[0] if res else ""
        detail = res[1] if len(res) > 1 else ""
        evidence = res[2] if len(res) > 2 else None
        return str(status), str(detail), evidence
    status = getattr(res, "status", None)
    if status is not None:
        detail = getattr(res, "reason", "") or getattr(res, "detail", "")
        return str(status), str(detail), res
    return str(res), "", None


def adjudicate(hyp, judges, *, prober=None):
    """Route ONE hypothesis. Provable → its injected pure judge; non-provable or
    un-wired → honest LEAD; a judge that raises → ERROR (never crashes the loop).
    A judge's VALIDATED becomes the orchestrator's CONFIRMED — the only place that
    translation is allowed to happen."""
    if not hyp.provable:
        return Verdict(hyp, VERDICT_LEAD, detail="non-differential technique surfaced as lead")
    judge = (judges or {}).get(hyp.technique)
    if judge is None:
        return Verdict(hyp, VERDICT_LEAD, detail=f"no judge wired for '{hyp.technique}'; surfaced as lead")
    try:
        status, detail, evidence = _normalize(judge(hyp, prober))
    except Exception as exc:  # a judge fault is an ERROR verdict, not a CONFIRM
        return Verdict(hyp, VERDICT_ERROR, detail=f"judge raised: {exc}")
    return Verdict(hyp, _JUDGE_TO_VERDICT.get(status, status), detail=detail, evidence=evidence)


# ---- EXECUTE: concurrent adjudication over the whole plan --------------------

def _run_hyps(hyps, judges, *, prober=None, max_workers=8, _executor=None):
    """Adjudicate a list of hypotheses CONCURRENTLY, returning verdicts in the
    SAME order (deterministic) regardless of completion order."""
    hyps = list(hyps)
    if not hyps:
        return []
    workers = max(1, min(max_workers, len(hyps)))

    def work(pair):
        return pair[0], adjudicate(pair[1], judges, prober=prober)

    results = [None] * len(hyps)
    ex = _executor or ThreadPoolExecutor(max_workers=workers)
    try:
        for i, verdict in ex.map(work, list(enumerate(hyps))):
            results[i] = verdict
    finally:
        if _executor is None:
            ex.shutdown(wait=True)
    return results


def run_plan(plan, judges, *, prober=None, max_workers=8, _executor=None):
    """Adjudicate every hypothesis CONCURRENTLY. Leads/un-wired resolve instantly;
    provable ones fan out to their pure judges. The returned verdict order mirrors
    ``plan.hypotheses`` (deterministic) regardless of completion order."""
    return _run_hyps(plan.hypotheses, judges, prober=prober,
                     max_workers=max_workers, _executor=_executor)


# ---- ADAPTIVE EXECUTE: failure-cause → mutated re-probe → judge disposes ------

# Best-per-slot ordering. A measured negative (DISPROVED) beats an unmeasured
# INCONCLUSIVE — learning the technique is absent is more honest than "could not
# measure". CONFIRMED wins outright. LEADs never enter a retryable slot.
_VERDICT_RANK = {
    VERDICT_CONFIRMED: 4, VERDICT_DISPROVED: 3,
    VERDICT_INCONCLUSIVE: 2, VERDICT_ERROR: 1, VERDICT_LEAD: 0,
}


def _verdict_rank(v):
    return _VERDICT_RANK.get(getattr(v, "status", ""), -1)


def run_plan_adaptive(plan, judges, *, prober=None, max_workers=8, max_rounds=2,
                      diagnose=None, propose_extra=None, _executor=None):
    """EXECUTE with a bounded FAILURE-CAUSE + RETRY loop.

    Round 0 adjudicates the whole plan (identical to :func:`run_plan`). Then, for
    up to ``max_rounds - 1`` further rounds, every slot whose best verdict is still
    non-terminal (INCONCLUSIVE / ERROR) is handed to the failure-cause analyzer,
    which proposes differently-shaped re-probes; those variants are adjudicated by
    the SAME pure judges. A variant only ever REPLACES its slot when it ranks
    strictly higher — so counts never inflate and a CONFIRMED still comes solely
    from a judge reproducing a differential. Deterministic: verdict order mirrors
    ``plan.hypotheses`` and identical probe shapes are never re-issued.
    """
    from . import refine as REFINE
    diagnose = diagnose or REFINE.diagnose

    slots = list(run_plan(plan, judges, prober=prober,
                          max_workers=max_workers, _executor=_executor))
    if max_rounds <= 1 or not slots:
        return slots

    tried = {h.shape for h in plan.hypotheses}
    for _ in range(max_rounds - 1):
        batch = []          # (slot_index, mutated_hypothesis)
        for i, v in enumerate(slots):
            for r in diagnose(v, plan.surface, tried=tried, propose_extra=propose_extra):
                tried.add(r.hypothesis.shape)
                batch.append((i, r))
        if not batch:
            break
        verdicts = _run_hyps([r.hypothesis for _i, r in batch], judges,
                             prober=prober, max_workers=max_workers, _executor=_executor)
        for (i, r), nv in zip(batch, verdicts):
            if _verdict_rank(nv) > _verdict_rank(slots[i]):
                note = f"[refined via {r.mutation}] "
                slots[i] = Verdict(nv.hypothesis, nv.status,
                                   detail=note + (nv.detail or ""), evidence=nv.evidence)
    return slots


@dataclass
class Report:
    plan: Plan
    verdicts: tuple = ()

    def _by(self, status):
        return tuple(v for v in self.verdicts if v.status == status)

    @property
    def confirmed(self):
        return self._by(VERDICT_CONFIRMED)

    @property
    def disproved(self):
        return self._by(VERDICT_DISPROVED)

    @property
    def leads(self):
        return self._by(VERDICT_LEAD)


def investigate(recon, findings, judges, *, prober=None, skills_index=None, use_llm=True,
                transport=None, max_workers=8, max_hyps=64, max_rounds=1, propose_extra=None):
    """End-to-end (minus patch/prove + deploy gate, which are the CLI's job):
    build the plan, then adjudicate it concurrently into a tiered report.

    ``max_rounds > 1`` enables the FAILURE-CAUSE + RETRY loop (see
    :func:`run_plan_adaptive`); the default of 1 is a single forward pass."""
    plan = build_plan(
        recon, findings, skills_index=skills_index, use_llm=use_llm,
        transport=transport, max_hyps=max_hyps,
    )
    if max_rounds > 1:
        verdicts = run_plan_adaptive(plan, judges, prober=prober, max_workers=max_workers,
                                     max_rounds=max_rounds, propose_extra=propose_extra)
    else:
        verdicts = run_plan(plan, judges, prober=prober, max_workers=max_workers)
    return Report(plan=plan, verdicts=tuple(verdicts))


