"""
PURE deterministic judge for the security-header posture class.

The analogue of :func:`judge_authorization_validation`. Given a hypothesis
and the id of a completed header probe, it selects the single probe evidence,
reads the operator-declared expectation the seeder wrote into the graph, and
compares the observed response header against it. It returns:

  VALIDATED     the observed header CONTRADICTS the declared posture — the
                misconfiguration reproduces (finding-worthy);
  DISPROVED     the observed header SATISFIES the posture — no finding;
  INCONCLUSIVE  the evidence is missing/ambiguous, or no posture is declared.

It has no target knowledge, performs no scoring, and never mutates the graph.
A single unambiguous comparison decides the verdict.
"""

from __future__ import annotations

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment
from .header_policy import HeaderExpectation


def header_posture_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> HeaderExpectation | None:
    """
    Recover the declared header expectation for one hypothesis identity.

    `aspect` is the identity action, ``"{header_lower}:{requirement}"``; it
    keys directly onto the ``requires_header_posture`` relationship the
    seeder emitted. Returns None if no matching posture edge exists.
    """
    target = f"posture:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_header_posture"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            return HeaderExpectation(
                header=meta.get("header", ""),
                requirement=meta.get("requirement", ""),
                value=(meta.get("expected_value") or None),
                severity=meta.get("severity", "MEDIUM"),
            )
    return None


def _probe_evidence(graph: SecurityGraph, experiment):
    """The single HTTP probe evidence backing this experiment, or None."""
    candidates = []
    for evidence_id in experiment.evidence_ids:
        evidence = graph.evidence.get(evidence_id)
        if evidence is None:
            continue
        data = evidence.data
        if (
            isinstance(data, dict)
            and data.get("mode") == "http"
            and isinstance(data.get("response_headers"), dict)
        ):
            candidates.append(evidence)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _observed_value(response_headers: dict, header: str):
    """Case-insensitive header lookup. Returns None when absent."""
    wanted = header.lower()
    for name, value in response_headers.items():
        if str(name).lower() == wanted:
            return str(value)
    return None


def _is_compliant(expectation: HeaderExpectation, observed) -> bool:
    """Deterministic posture check: True iff the header satisfies policy."""
    requirement = expectation.requirement
    present = observed is not None

    if requirement == "must_present":
        return present
    if requirement == "must_absent":
        return not present
    if requirement == "must_equal":
        return present and observed.strip().lower() == (
            (expectation.value or "").strip().lower()
        )
    if requirement == "must_not_equal":
        return not (
            present
            and observed.strip().lower() == (
                (expectation.value or "").strip().lower()
            )
        )
    # Unknown requirement — cannot decide.
    return True


def _reason(expectation: HeaderExpectation, observed, compliant: bool) -> str:
    shown = "absent" if observed is None else f"'{observed}'"
    verb = "satisfies" if compliant else "violates"
    want = expectation.requirement
    if expectation.value:
        want = f"{want} '{expectation.value}'"
    return (
        f"observed {expectation.header}={shown} {verb} declared posture "
        f"({want})"
    )


def judge_header_posture(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    experiment_id: str,
) -> ValidationJudgment:
    """Decide whether the observed header contradicts the declared posture."""

    experiment = graph.experiments.get(experiment_id)
    if experiment is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason="no experiment found for header posture judgment",
            contradiction_kind="security_misconfiguration",
        )

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="security_misconfiguration",
        )

    expectation = header_posture_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.requirement:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason="no declared header posture for this hypothesis",
            contradiction_kind="security_misconfiguration",
        )

    evidence = _probe_evidence(graph, experiment)
    if evidence is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason="expected exactly one HTTP header probe for this experiment",
            contradiction_kind="security_misconfiguration",
        )

    observed = _observed_value(
        evidence.data["response_headers"], expectation.header
    )
    compliant = _is_compliant(expectation, observed)

    # The hypothesis claims a misconfiguration. It is VALIDATED when the
    # observed header CONTRADICTS the required posture (a real violation),
    # DISPROVED when the header satisfies it.
    status = "DISPROVED" if compliant else "VALIDATED"

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=experiment_id,
        status=status,
        reason=_reason(expectation, observed, compliant),
        contradiction_kind="security_misconfiguration",
        expected=True,          # posture required
        observed=compliant,     # posture actually satisfied?
        evidence_ids=(evidence.id,),
    )
