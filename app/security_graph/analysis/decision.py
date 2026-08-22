from ..ai import SecurityReasoningAdvisor
from ..ai.schema import validate_advice_against_candidates
from app.config import AI_ADVISORY_MAX_CANDIDATES
from .research_state import build_research_state
from dataclasses import dataclass
from ..graph import SecurityGraph
from ..models import (
    ResearchCandidate,
    ResearchDecision,
    ResearchEvaluation,
)
from .ranking import score_hypothesis
from .refinement_pressure import (
    evaluate_refinement_pressure,
)



def is_research_novel(
    graph: SecurityGraph,
    *,
    hypothesis_id: str,
    capability_id: str,
    action: str,
) -> bool:
    """
    Return whether an exact research identity is novel.

    Novelty is determined exclusively from explicit research provenance
    recorded by the graph:

        hypothesis_id
        capability_id
        action

    A non-novel research identity remains eligible for consideration.
    This helper does not determine research validity, truth, or priority.
    """
    return not graph.has_research_attempt(
        hypothesis_id=hypothesis_id,
        capability_id=capability_id,
        action=action,
    )


@dataclass(frozen=True)
class ResearchIdentityOutcome:
    """
    Derived epistemic outcome for one exact research identity.

    Identity is matched exclusively through explicit experiment
    provenance. No domain-specific evidence is interpreted here.
    """

    state: str
    attempt_count: int
    decisive_count: int
    inconclusive_count: int


def evaluate_research_identity_outcome(
    graph: SecurityGraph,
    *,
    hypothesis_id: str,
    capability_id: str,
    action: str,
) -> ResearchIdentityOutcome:
    """
    Derive the outcome history for one exact research identity.

    Identity matching is delegated entirely to the graph.

    ValidationJudgment.status is the only source used to classify
    epistemic outcome.
    """
    attempts = graph.research_attempts_for(
        hypothesis_id=hypothesis_id,
        capability_id=capability_id,
        action=action,
    )

    if not attempts:
        return ResearchIdentityOutcome(
            state="NEVER_ATTEMPTED",
            attempt_count=0,
            decisive_count=0,
            inconclusive_count=0,
        )

    judgments_by_experiment = {
        judgment.experiment_id: judgment
        for judgment in graph.validation_judgments.values()
    }

    decisive_count = 0
    inconclusive_count = 0

    for experiment in attempts:
        judgment = judgments_by_experiment.get(experiment.id)

        if judgment is None:
            continue

        if judgment.status == "INCONCLUSIVE":
            inconclusive_count += 1
        else:
            decisive_count += 1

    if decisive_count and inconclusive_count:
        state = "ATTEMPTED_MIXED"
    elif decisive_count:
        state = "ATTEMPTED_DECISIVE"
    elif inconclusive_count:
        state = "ATTEMPTED_INCONCLUSIVE"
    else:
        # The identity was attempted, but no epistemic judgment exists.
        # Preserve that uncertainty conservatively rather than inventing
        # a decisive outcome.
        state = "ATTEMPTED_INCONCLUSIVE"

    return ResearchIdentityOutcome(
        state=state,
        attempt_count=len(attempts),
        decisive_count=decisive_count,
        inconclusive_count=inconclusive_count,
    )


@dataclass(frozen=True)
class ResearchIdentityInformationState:
    """
    Derived information state for one exact research identity.

    This projection describes only whether the identity's existing
    research history still carries unresolved information.

    It does not determine truth, priority, eligibility, retry policy,
    or candidate ranking.
    """

    outcome: ResearchIdentityOutcome
    residual_information: bool


@dataclass(frozen=True)
class ResearchIdentityInformationContext:
    """
    Derived context joining capability evaluation with the exact
    research identity's existing information state.

    This projection does not calculate information value. It only makes
    the epistemic context explicit for later decision-layer reasoning.
    """

    evaluation: ResearchEvaluation
    information_state: ResearchIdentityInformationState
    identity_information_applicable: bool


def evaluate_research_identity_information(
    graph: SecurityGraph,
    *,
    hypothesis_id: str,
    capability_id: str,
    action: str,
) -> ResearchIdentityInformationState:
    """
    Derive residual information from the exact identity outcome.

    Only the existing ResearchIdentityOutcome projection is interpreted.
    No security-domain semantics are inspected.
    """
    outcome = evaluate_research_identity_outcome(
        graph,
        hypothesis_id=hypothesis_id,
        capability_id=capability_id,
        action=action,
    )

    residual_information = outcome.state != "ATTEMPTED_DECISIVE"

    return ResearchIdentityInformationState(
        outcome=outcome,
        residual_information=residual_information,
    )


def score_research_frontier(
    base_value: float,
    refinement_level: str,
) -> float:
    """
    Combine capability value with domain-independent refinement
    urgency.

    Capability evaluation remains the source of research value.
    Refinement pressure contributes bounded urgency only.

    The decision engine does not interpret hypothesis kinds,
    evidence semantics, or security-domain concepts.
    """

    pressure_bonus = {
        "NO_PRESSURE": 0.00,
        "LOW": 0.00,
        "MEDIUM": 0.10,
        "HIGH": 0.20,
    }.get(
        refinement_level,
        0.00,
    )

    return min(
        1.0,
        max(
            0.0,
            base_value + pressure_bonus,
        ),
    )


def generate_research_candidates(
    graph: SecurityGraph,
) -> list[ResearchCandidate]:
    """
    Generate candidates by asking every registered capability
    whether it is applicable.

    The decision engine intentionally contains no knowledge of
    individual hypothesis kinds or concrete security tools.
    """

    from ..capabilities import DEFAULT_RESEARCH_CAPABILITIES

    candidates: list[ResearchCandidate] = []

    for hypothesis in graph.hypotheses.values():
        if hypothesis.status != "OPEN":
            continue

        hypothesis_score = score_hypothesis(
            graph,
            hypothesis,
        )

        if hypothesis_score.score <= 0:
            continue

        for capability in DEFAULT_RESEARCH_CAPABILITIES.all():
            applicable, reasons = (
                capability.check_applicability(
                    graph,
                    hypothesis,
                )
            )

            if not applicable:
                continue

            evaluation = capability.evaluate(
                graph,
                hypothesis,
            )

            refinement_pressure = (
                evaluate_refinement_pressure(
                    graph,
                    hypothesis,
                )
            )

            frontier_score = score_research_frontier(
                evaluation.value,
                refinement_pressure.level,
            )

            research_novel = is_research_novel(
                graph,
                hypothesis_id=hypothesis.id,
                capability_id=capability.id,
                action=capability.action,
            )

            research_outcome = evaluate_research_identity_outcome(
                graph,
                hypothesis_id=hypothesis.id,
                capability_id=capability.id,
                action=capability.action,
            )

            research_information_state = (
                evaluate_research_identity_information(
                    graph,
                    hypothesis_id=hypothesis.id,
                    capability_id=capability.id,
                    action=capability.action,
                )
            )

            identity_information_applicable = (
                capability.identity_information_applicable(
                    graph,
                    hypothesis,
                    research_information_state,
                )
            )

            research_information_context = (
                ResearchIdentityInformationContext(
                    evaluation=evaluation,
                    information_state=research_information_state,
                    identity_information_applicable=(
                        identity_information_applicable
                    ),
                )
            )

            novelty_reason = (
                "research identity is novel"
                if research_novel
                else "research identity has been attempted previously"
            )

            candidates.append(
                ResearchCandidate(
                    id=(
                        f"candidate:{capability.id}:"
                        f"{hypothesis.id}"
                    ),
                    hypothesis_id=hypothesis.id,
                    action=capability.action,
                    capability_id=capability.id,
                    score=frontier_score,
                    rationale=tuple(
                        hypothesis_score.reasons
                        + reasons
                        + evaluation.reasons
                        + refinement_pressure.reasons
                        + (novelty_reason,)
                    ),
                    evaluation=evaluation,
                    refinement_level=(
                        refinement_pressure.level
                    ),
                    refinement_required=(
                        refinement_pressure.required
                    ),
                    refinement_uncertainty=(
                        refinement_pressure.uncertainty
                    ),
                    research_outcome=research_outcome,
                    research_information_state=(
                        research_information_state
                    ),
                    research_information_context=(
                        research_information_context
                    ),
                )
            )

    return sorted(
        candidates,
        key=lambda item: (
            -item.score,
            item.id,
        ),
    )




from .hypothesis_evolution import (
    evaluate_hypothesis_evolution,
)
from .hypothesis_state import (
    build_hypothesis_state,
)


@dataclass(frozen=True)
class ResearchOutcome:
    """
    Read-only projection of the current research state.

    This does not mutate hypothesis lifecycle state and does not
    interpret frontier exhaustion as vulnerability absence.
    """

    hypothesis_id: str
    phase: str
    frontier_status: str
    resolved: bool
    productive_actions_remaining: bool
    residual_uncertainty: float
    reasons: tuple[str, ...] = ()


def evaluate_research_outcome(
    graph: SecurityGraph,
    hypothesis,
) -> ResearchOutcome:
    """
    Project the current research outcome from existing graph state.

    Frontier exhaustion means that no currently applicable
    research action has positive decision value. It does not
    prove or disprove the hypothesis.
    """

    state = build_hypothesis_state(
        graph,
        hypothesis,
    )

    evolution = evaluate_hypothesis_evolution(
        graph,
        hypothesis,
    )

    candidates = generate_research_candidates(
        graph,
    )

    productive = any(
        candidate.hypothesis_id == hypothesis.id
        and candidate.score > 0.0
        for candidate in candidates
    )

    if evolution.resolved:
        frontier_status = "RESOLVED"
    elif productive:
        frontier_status = "ACTIVE"
    else:
        frontier_status = "EXHAUSTED"

    return ResearchOutcome(
        hypothesis_id=hypothesis.id,
        phase=evolution.phase,
        frontier_status=frontier_status,
        resolved=evolution.resolved,
        productive_actions_remaining=productive,
        residual_uncertainty=state.residual_uncertainty,
        reasons=tuple(
            evolution.reasons
            + (
                (
                    "productive research actions remain"
                    if productive
                    else
                    "no currently productive research actions remain"
                ),
            )
        ),
    )



def apply_ai_research_advisory(
    candidates,
    advice,
):
    """
    Apply a bounded AI preference without replacing Sentinel ranking.

    Sentinel's deterministic candidate score remains authoritative.

    The AI receives no authority to:
      - create candidates
      - modify candidate scores
      - modify capability applicability
      - modify actions
      - execute capabilities
      - establish findings

    The advisory signal is intentionally small and is used only as a
    secondary ranking signal.
    """
    if not candidates or advice is None:
        return candidates

    advised_ids = {
        candidate_id
        for candidate_id in advice.candidate_ids
    }

    if not advised_ids:
        return candidates

    # Sentinel's score remains the primary ranking key.
    #
    # AI preference is deliberately represented only as a secondary
    # signal. Therefore a candidate with a higher deterministic score
    # cannot be displaced merely because Qwen prefers another candidate.
    return tuple(
        sorted(
            candidates,
            key=lambda candidate: (
                candidate.score,
                candidate.id in advised_ids,
            ),
            reverse=True,
        )
    )





def build_ai_research_semantic_projection(
    graph: SecurityGraph,
    candidates,
) -> dict:
    """
    Build a deterministic semantic interpretation of ResearchState.

    The semantic layer translates existing ResearchState fields into
    bounded, explicit advisory meaning.

    It does not determine vulnerability truth, execute actions, create
    candidates, or establish findings.

    Raw domain lifecycle status remains separate from derived epistemic
    state.
    """

    projection = []

    candidate_list = list(candidates)[:32]

    hypothesis_ids = {
        candidate.hypothesis_id
        for candidate in candidate_list
    }

    for hypothesis_id in sorted(hypothesis_ids):
        hypothesis = graph.hypotheses.get(
            hypothesis_id
        )

        if hypothesis is None:
            continue

        state = build_research_state(
            graph,
            hypothesis,
        )

        if state.residual_uncertainty > 0.0:
            epistemic_state = "UNCERTAIN"
        elif state.judgment_resolution >= 1.0:
            epistemic_state = "RESOLVED"
        else:
            epistemic_state = "PARTIALLY_RESOLVED"

        if state.judgment_count == 0:
            research_direction = "NEEDS_INITIAL_EVIDENCE"
        elif state.residual_uncertainty > 0.0:
            research_direction = "NEEDS_FURTHER_RESEARCH"
        else:
            research_direction = "STATE_RESOLVED"

        projection.append(
            {
                "hypothesis_id": state.hypothesis_id,
                "domain_status": hypothesis.status,
                "epistemic_state": epistemic_state,
                "research_direction": research_direction,
                "attempts": state.attempts,
                "completed_attempts": state.completed_attempts,
                "observation_count": state.observation_count,
                "judgment_count": state.judgment_count,
                "evidence_count": state.evidence_count,
                "research_depth": state.research_depth,
                "judgment_resolution": state.judgment_resolution,
                "residual_uncertainty": state.residual_uncertainty,
            }
        )

    return {
        "hypotheses": projection,
        "limits": {
            "max_hypothesis_semantics": 32,
        },
    }


def build_ai_research_state_projection(
    graph: SecurityGraph,
    candidates,
) -> dict:
    """
    Build a bounded read-only projection of Sentinel's
    deterministic ResearchState.

    ResearchState remains authoritative.
    The AI receives scalar epistemic metadata only.
    """

    projection = []

    candidate_list = list(candidates)[:32]

    hypothesis_ids = {
        candidate.hypothesis_id
        for candidate in candidate_list
    }

    for hypothesis_id in sorted(hypothesis_ids):
        hypothesis = graph.hypotheses.get(
            hypothesis_id
        )

        if hypothesis is None:
            continue

        state = build_research_state(
            graph,
            hypothesis,
        )

        projection.append(
            {
                "hypothesis_id": state.hypothesis_id,
                "attempts": state.attempts,
                "completed_attempts": (
                    state.completed_attempts
                ),
                "observation_count": (
                    state.observation_count
                ),
                "judgment_count": (
                    state.judgment_count
                ),
                "supporting_judgments": (
                    state.supporting_judgments
                ),
                "contradicting_judgments": (
                    state.contradicting_judgments
                ),
                "inconclusive_judgments": (
                    state.inconclusive_judgments
                ),
                "evidence_count": (
                    state.evidence_count
                ),
                "has_finding": state.has_finding,
                "current_status": state.current_status,
                "has_prior_research": (
                    state.has_prior_research
                ),
                "unresolved": state.unresolved,
                "research_depth": state.research_depth,
                "judgment_resolution": (
                    state.judgment_resolution
                ),
                "residual_uncertainty": (
                    state.residual_uncertainty
                ),
            }
        )

    return {
        "hypotheses": projection,
        "limits": {
            "max_hypothesis_states": 32,
        },
    }


def build_ai_research_context(
    graph: SecurityGraph,
    candidates,
    *,
    max_hypotheses: int = 32,
    max_observations: int = 64,
    focus_hypothesis_ids=None,
    lean: bool = False,
) -> dict:
    """
    Build a bounded, read-only projection of Sentinel research state.

    SecurityGraph stores hypotheses and observations in dictionaries,
    therefore this projection explicitly consumes their values rather
    than dictionary keys.

    ``max_hypotheses`` / ``max_observations`` cap the ambient projection,
    and ``focus_hypothesis_ids`` (when supplied) restricts the hypothesis
    projection to those ids. ``lean`` collapses each hypothesis/candidate
    to only the fields a tiebreak needs and drops the heavy research_state
    / research_semantics projections — this is what keeps the per-cycle
    advisory prompt small enough to fit the model context window. The
    default (all off) preserves the full projection.

    No mutable graph objects or execution interfaces are exposed.
    """

    def scalar(value, default=None):
        if value is None:
            return default

        if isinstance(
            value,
            (str, int, float, bool),
        ):
            return value

        return str(value)

    def bounded_ids(values, limit=32):
        if values is None:
            return []

        return [
            scalar(value)
            for value in list(values)[:limit]
        ]

    hypotheses_store = getattr(
        graph,
        "hypotheses",
        {},
    )

    observations_store = getattr(
        graph,
        "observations",
        {},
    )

    if isinstance(
        hypotheses_store,
        dict,
    ):
        hypotheses = list(
            hypotheses_store.values()
        )
    else:
        hypotheses = list(
            hypotheses_store
        )

    if isinstance(
        observations_store,
        dict,
    ):
        observations = list(
            observations_store.values()
        )
    else:
        observations = list(
            observations_store
        )

    hypothesis_projection = []

    if focus_hypothesis_ids is not None:
        focus = set(focus_hypothesis_ids)
        hypotheses = [
            hypothesis
            for hypothesis in hypotheses
            if getattr(hypothesis, "id", None) in focus
        ]

    for hypothesis in hypotheses[:max_hypotheses]:
        if lean:
            claim = scalar(
                getattr(hypothesis, "claim", None)
            )
            if isinstance(claim, str) and len(claim) > 160:
                claim = claim[:159] + "…"
            hypothesis_projection.append(
                {
                    "id": scalar(
                        getattr(hypothesis, "id", None)
                    ),
                    "kind": scalar(
                        getattr(hypothesis, "kind", None)
                    ),
                    "claim": claim,
                    "confidence": scalar(
                        getattr(hypothesis, "confidence", None)
                    ),
                    "status": scalar(
                        getattr(hypothesis, "status", None)
                    ),
                }
            )
            continue

        hypothesis_projection.append(
            {
                "id": scalar(
                    getattr(
                        hypothesis,
                        "id",
                        None,
                    )
                ),
                "kind": scalar(
                    getattr(
                        hypothesis,
                        "kind",
                        None,
                    )
                ),
                "claim": scalar(
                    getattr(
                        hypothesis,
                        "claim",
                        None,
                    )
                ),
                "confidence": scalar(
                    getattr(
                        hypothesis,
                        "confidence",
                        None,
                    )
                ),
                "evidence_ids": bounded_ids(
                    getattr(
                        hypothesis,
                        "evidence_ids",
                        (),
                    )
                ),
                "identity": scalar(
                    getattr(
                        hypothesis,
                        "identity",
                        None,
                    )
                ),
                "source_ids": bounded_ids(
                    getattr(
                        hypothesis,
                        "source_ids",
                        (),
                    )
                ),
                "status": scalar(
                    getattr(
                        hypothesis,
                        "status",
                        None,
                    )
                ),
            }
        )

    observation_projection = []

    recent_observations = (
        observations[-max_observations:]
        if max_observations > 0
        else []
    )

    for observation in recent_observations:
        data = getattr(
            observation,
            "data",
            None,
        )

        if isinstance(
            data,
            dict,
        ):
            safe_data = {
                str(key): scalar(value)
                for key, value in list(
                    data.items()
                )[:16]
            }
        else:
            safe_data = scalar(data)

        observation_projection.append(
            {
                "id": scalar(
                    getattr(
                        observation,
                        "id",
                        None,
                    )
                ),
                "kind": scalar(
                    getattr(
                        observation,
                        "kind",
                        None,
                    )
                ),
                "subject": scalar(
                    getattr(
                        observation,
                        "subject",
                        None,
                    )
                ),
                "data": safe_data,
                "evidence_ids": bounded_ids(
                    getattr(
                        observation,
                        "evidence_ids",
                        (),
                    )
                ),
            }
        )

    candidate_projection = []

    for candidate in list(
        candidates
    )[:32]:
        if lean:
            candidate_projection.append(
                {
                    "id": scalar(
                        getattr(candidate, "id", None)
                    ),
                    "hypothesis_id": scalar(
                        getattr(candidate, "hypothesis_id", None)
                    ),
                    "action": scalar(
                        getattr(candidate, "action", None)
                    ),
                    "capability_id": scalar(
                        getattr(candidate, "capability_id", None)
                    ),
                    "score": scalar(
                        getattr(candidate, "score", None)
                    ),
                    "rationale": [
                        scalar(reason)
                        for reason in list(
                            getattr(candidate, "rationale", ())
                        )[:2]
                    ],
                }
            )
            continue

        candidate_projection.append(
            {
                "id": scalar(
                    getattr(
                        candidate,
                        "id",
                        None,
                    )
                ),
                "hypothesis_id": scalar(
                    getattr(
                        candidate,
                        "hypothesis_id",
                        None,
                    )
                ),
                "action": scalar(
                    getattr(
                        candidate,
                        "action",
                        None,
                    )
                ),
                "capability_id": scalar(
                    getattr(
                        candidate,
                        "capability_id",
                        None,
                    )
                ),
                "score": scalar(
                    getattr(
                        candidate,
                        "score",
                        None,
                    )
                ),
                "rationale": [
                    scalar(reason)
                    for reason in list(
                        getattr(
                            candidate,
                            "rationale",
                            (),
                        )
                    )[:8]
                ],
                "evaluation": scalar(
                    getattr(
                        candidate,
                        "evaluation",
                        None,
                    )
                ),
                "refinement_level": scalar(
                    getattr(
                        candidate,
                        "refinement_level",
                        None,
                    )
                ),
                "refinement_required": scalar(
                    getattr(
                        candidate,
                        "refinement_required",
                        None,
                    )
                ),
                "refinement_uncertainty": scalar(
                    getattr(
                        candidate,
                        "refinement_uncertainty",
                        None,
                    )
                ),
                "research_outcome": scalar(
                    getattr(
                        candidate,
                        "research_outcome",
                        None,
                    )
                ),
                "research_information_state": scalar(
                    getattr(
                        candidate,
                        "research_information_state",
                        None,
                    )
                ),
                "research_information_context": scalar(
                    getattr(
                        candidate,
                        "research_information_context",
                        None,
                    )
                ),
            }
        )


    if lean:
        # A bounded tiebreak does not need the full research-state /
        # semantics projections: the deterministic engine already handles
        # diminishing returns via score decay, so tied fresh candidates
        # are all the advisor must choose between. Dropping these keeps
        # the prompt inside the model context window.
        research_state_projection = {}
        research_semantic_projection = {}
    else:
        research_state_projection = (
            build_ai_research_state_projection(
                graph,
                candidates,
            )
        )

        research_semantic_projection = (
            build_ai_research_semantic_projection(
                graph,
                candidates,
            )
        )

    return {
        "research_objective": (
            "Prioritize the next existing research "
            "candidate using available evidence and "
            "current research state."
        ),
        "hypotheses": hypothesis_projection,
        "observations": observation_projection,
        "candidates": candidate_projection,
        "limits": {
            "max_hypotheses": max_hypotheses,
            "max_observations": max_observations,
            "max_candidates": 32,
            "max_observation_data_keys": 16,
            "max_evidence_ids": 32,
        },
        "research_state": research_state_projection,
        "research_semantics": research_semantic_projection,
    }


def choose_research_decision(
    graph: SecurityGraph,
) -> ResearchDecision | None:
    """
    Select exactly one research decision.

    Sentinel remains deterministic authority.

    The AI advisor may provide a bounded preference among candidates that
    Sentinel has already generated. AI output cannot create candidates,
    modify candidate scores, create experiments, execute capabilities,
    or establish security findings.

    If the AI advisor fails, deterministic selection continues normally.
    """

    candidates = generate_research_candidates(graph)

    if not candidates:
        return None

    # ------------------------------------------------------------------
    # AI ADVISORY LAYER
    # ------------------------------------------------------------------
    #
    # The advisor is only ever a tiebreak among equally top-scored
    # candidates (see apply_ai_research_advisory: score is the primary
    # key, AI preference only the secondary one). Candidates are already
    # sorted by (-score, id), so when the single highest score is held by
    # exactly one candidate, the advisor cannot change the selection.
    #
    # In that case we skip the LLM round-trip entirely: it keeps the
    # autonomous loop fast and avoids a call that cannot affect the
    # outcome. The advisor is consulted only when a real tie exists.
    # ------------------------------------------------------------------

    top_score = candidates[0].score

    contested = sum(
        1
        for candidate in candidates
        if candidate.score == top_score
    )

    ai_advice = None

    if contested >= 2:
        # The advisor only ever reorders within the top-scored tie, so it
        # only needs to see that tied band — never the full frontier.
        # Bounding the payload to the contested prefix (capped) and to
        # those candidates' own hypotheses, with no ambient observations,
        # keeps each per-cycle prompt small and fast. Correctness is
        # unchanged: lower-scored candidates can never be elevated above
        # the tie, and tied candidates not shown keep their deterministic
        # (-score, id) position behind the selected one.
        advisory_pool = candidates[
            : min(contested, AI_ADVISORY_MAX_CANDIDATES)
        ]

        focus_hypothesis_ids = {
            candidate.hypothesis_id
            for candidate in advisory_pool
        }

        context = build_ai_research_context(
            graph,
            advisory_pool,
            max_hypotheses=AI_ADVISORY_MAX_CANDIDATES,
            max_observations=0,
            focus_hypothesis_ids=focus_hypothesis_ids,
            lean=True,
        )

        # The USER_TEMPLATE renders candidates as a dedicated block, so
        # keeping them inside `context` too would serialize the whole
        # candidate list twice. Move them out to send each candidate
        # exactly once.
        ai_candidates = context.pop("candidates")

        valid_hypothesis_ids = {
            candidate.hypothesis_id
            for candidate in candidates
        }

        valid_candidate_ids = {
            candidate.id
            for candidate in candidates
        }

        try:
            advisor = SecurityReasoningAdvisor()

            ai_advice = advisor.advise(
                context=context,
                candidates=ai_candidates,
            )

            ai_advice = validate_advice_against_candidates(
                ai_advice,
                valid_hypothesis_ids=valid_hypothesis_ids,
                valid_candidate_ids=valid_candidate_ids,
            )

        except Exception:
            # AI is advisory. Sentinel must remain fully functional when
            # the model is unavailable, malformed, slow, or otherwise
            # unusable.
            ai_advice = None

    # ------------------------------------------------------------------
    # DETERMINISTIC AUTHORITY
    # ------------------------------------------------------------------
    #
    # AI may influence candidate ordering only after deterministic
    # candidate generation and validation.
    #
    # The existing candidate score remains unchanged.
    # No AI-created candidate can enter this set.
    # ------------------------------------------------------------------

    ordered_candidates = candidates

    # ------------------------------------------------------------------
    # FINAL DETERMINISTIC SELECTION
    # ------------------------------------------------------------------

    ordered_candidates = apply_ai_research_advisory(
        candidates,
        ai_advice,
    )

    selected = ordered_candidates[0]

    # A technically applicable action may still have no remaining
    # research value. Preserve the existing Sentinel safety gate.
    if selected.score <= 0.0:
        return None

    # Record advisory provenance for display/telemetry only. The advisor
    # is deemed to have influenced this selection when its (validated)
    # preference names the candidate deterministic ranking then placed
    # first. This never changes the score or the choice — it only makes
    # the AI's bounded contribution visible on the decision board.
    ai_influenced = bool(
        ai_advice is not None
        and selected.id in set(ai_advice.candidate_ids)
    )
    ai_confidence = (
        ai_advice.confidence
        if ai_influenced
        else None
    )
    ai_reasoning = (
        ai_advice.reasoning
        if ai_influenced
        else ""
    )

    return ResearchDecision(
        candidate_id=selected.id,
        hypothesis_id=selected.hypothesis_id,
        action=selected.action,
        capability_id=selected.capability_id,
        score=selected.score,
        rationale=selected.rationale,
        rejected_candidate_ids=tuple(
            candidate.id
            for candidate in ordered_candidates[1:]
        ),
        ai_influenced=ai_influenced,
        ai_confidence=ai_confidence,
        ai_reasoning=ai_reasoning,
    )
