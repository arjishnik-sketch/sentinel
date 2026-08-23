"""
PURE deterministic judge for the injection class.

The analogue of :func:`judge_privilege_escalation`, but it reasons over a
**three-way boolean differential**. Given a hypothesis and the ids of the
probes — a *baseline* probe (the benign declared value), and one or more
length-matched (TRUE, FALSE) probe *pairs* (the benign value + a boolean
tautology vs the same value + a boolean contradiction) — it recovers the
operator-declared injectable surface the seeder wrote into the graph, reads the
observed (status code, response body length) fingerprint of each probe, and
decides:

  VALIDATED     some length-matched pair makes the response track the injected
                boolean — TRUE and FALSE differ, AND one arm reproduces the
                legitimate baseline exactly — so the backend is evaluating the
                injected SQL boolean (a real SQL injection);
  DISPROVED     for EVERY pair the TRUE and FALSE responses are identical — the
                parameter does not influence a SQL boolean (the injection does
                not reproduce; also the post-fix state once the request-guard
                blocks the payloads: TRUE and FALSE both become 403);
  INCONCLUSIVE  the declared benign baseline did not return a legitimate
                response (no anchor to measure against), or probe evidence /
                boundary metadata is missing.

Three things make this sound. First, a status code alone is never the verdict.
Second, each (TRUE, FALSE) pair is length-matched to the character, so a payload
reflected verbatim into the response contributes identical bytes to both arms —
any TRUE≠FALSE difference can therefore only come from the backend evaluating
the boolean, not from the payload being echoed. Third, the verdict requires one
arm to reproduce the legitimate baseline exactly, anchoring the differential to
real query-result variation rather than to two unrelated error pages. The judge
has no target knowledge, performs no scoring, and never mutates the graph.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment


@dataclass(frozen=True)
class InjectionExpectation:
    """The declared injectable surface recovered for one hypothesis identity."""

    method: str
    path: str
    endpoint_url: str
    param: str
    location: str
    baseline_value: str
    success_statuses: tuple[int, ...]
    severity: str


def _decode_statuses(raw: str) -> tuple[int, ...]:
    try:
        data = json.loads(raw) if raw else []
    except (ValueError, TypeError):
        return tuple(range(200, 300))
    out: list[int] = []
    for item in data:
        try:
            out.append(int(item))
        except (ValueError, TypeError):
            continue
    return tuple(out) if out else tuple(range(200, 300))


def injection_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> InjectionExpectation | None:
    """
    Recover the declared injectable surface for one hypothesis identity.

    `aspect` is the identity action; it keys onto the ``requires_no_injection``
    relationship the seeder emitted. Returns None if no matching edge exists.
    """
    target = f"injection:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_no_injection"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            return InjectionExpectation(
                method=meta.get("method", "GET"),
                path=meta.get("path", ""),
                endpoint_url=meta.get("endpoint_url", ""),
                param=meta.get("param", ""),
                location=meta.get("location", "query"),
                baseline_value=meta.get("baseline_value", ""),
                success_statuses=_decode_statuses(meta.get("success_statuses", "")),
                severity=meta.get("severity", "HIGH"),
            )
    return None


def _probe_evidence(graph: SecurityGraph, experiment):
    """The single HTTP probe evidence backing this experiment, or None."""
    if experiment is None:
        return None
    candidates = []
    for evidence_id in experiment.evidence_ids:
        evidence = graph.evidence.get(evidence_id)
        if evidence is None:
            continue
        data = evidence.data
        if (
            isinstance(data, dict)
            and data.get("mode") == "http"
            and "status_code" in data
            and "response_body_length" in data
        ):
            candidates.append(evidence)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _fingerprint(graph: SecurityGraph, experiment_id: str | None):
    """(status_code, response_body_length) for a probe, or None if unreadable."""
    if experiment_id is None:
        return None
    evidence = _probe_evidence(graph, graph.experiments.get(experiment_id))
    if evidence is None:
        return None
    data = evidence.data
    try:
        status = int(data.get("status_code"))
        length = int(data.get("response_body_length"))
    except (TypeError, ValueError):
        return None
    return (status, length), evidence.id


def judge_injection(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    baseline_experiment_id: str,
    pair_experiment_ids: tuple[tuple[str, str], ...],
) -> ValidationJudgment:
    """Decide whether the boolean differential proves a SQL injection.

    ``pair_experiment_ids`` is a tuple of ``(true_experiment_id,
    false_experiment_id)`` pairs; each pair's two probes were built from
    length-matched payloads, so a difference between them cannot come from a
    reflected payload.
    """

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=baseline_experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="injection",
        )

    expectation = injection_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.param:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=baseline_experiment_id,
            status="INCONCLUSIVE",
            reason="no declared injectable surface for this hypothesis",
            contradiction_kind="injection",
        )

    success = set(expectation.success_statuses)

    baseline = _fingerprint(graph, baseline_experiment_id)
    if baseline is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=baseline_experiment_id,
            status="INCONCLUSIVE",
            reason="the baseline probe evidence is missing or unreadable",
            contradiction_kind="injection",
        )
    baseline_fp, baseline_ev = baseline

    # The baseline must be a legitimate response — it is the anchor the whole
    # differential is measured against. If the declared benign value does not
    # return a success, the surface is mis-declared or unreachable and no honest
    # measurement is possible.
    if baseline_fp[0] not in success:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=baseline_experiment_id,
            status="INCONCLUSIVE",
            reason=(
                f"the declared benign value returned {baseline_fp[0]} on "
                f"{expectation.method} {expectation.path} — not a legitimate "
                "response, so the boolean differential has no anchor"
            ),
            contradiction_kind="injection",
        )

    evidence_ids: list[str] = [baseline_ev]
    any_pair_readable = False

    for true_id, false_id in pair_experiment_ids:
        true = _fingerprint(graph, true_id)
        false = _fingerprint(graph, false_id)
        if true is None or false is None:
            continue
        any_pair_readable = True
        true_fp, true_ev = true
        false_fp, false_ev = false

        differs = true_fp != false_fp
        # One arm must reproduce the legitimate baseline EXACTLY: an AND-tautology
        # keeps the original result (baseline == TRUE), an OR-tautology returns a
        # superset while the contradiction keeps it (baseline == FALSE). Either
        # way, anchoring one arm to the baseline ties the difference to real
        # query-result variation, not to two unrelated pages.
        anchored = baseline_fp in (true_fp, false_fp)

        if differs and anchored:
            evidence_ids.extend([true_ev, false_ev])
            reason = (
                f"a length-matched boolean pair on '{expectation.param}' "
                f"({expectation.method} {expectation.path}) toggled the "
                f"response: TRUE={true_fp} vs FALSE={false_fp}, and one arm "
                f"reproduced the legitimate baseline {baseline_fp} — the "
                "backend is evaluating the injected SQL boolean (the payloads "
                "are equal length, so a reflected value cannot explain the "
                "difference)"
            )
            return ValidationJudgment(
                hypothesis_id=hypothesis.id,
                experiment_id=true_id,
                status="VALIDATED",
                reason=reason,
                contradiction_kind="injection",
                expected=False,     # boundary: the param MUST NOT alter the query
                observed=True,      # it did
                evidence_ids=tuple(dict.fromkeys(evidence_ids)),
            )

    if not any_pair_readable:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=baseline_experiment_id,
            status="INCONCLUSIVE",
            reason="no readable TRUE/FALSE probe pair for this hypothesis",
            contradiction_kind="injection",
        )

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=baseline_experiment_id,
        status="DISPROVED",
        reason=(
            f"no boolean payload toggled the response of '{expectation.param}' "
            f"({expectation.method} {expectation.path}) — for every length-"
            "matched pair the TRUE and FALSE responses were identical, so the "
            "parameter does not influence a SQL boolean; no injection"
        ),
        contradiction_kind="injection",
        expected=False,
        observed=False,
        evidence_ids=tuple(dict.fromkeys(evidence_ids)),
    )
