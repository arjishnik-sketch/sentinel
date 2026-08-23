"""
PURE deterministic judge for the privilege-escalation class.

The analogue of :func:`judge_cookie_posture`, but it reasons over a **three-probe
differential** rather than a single observation. Given a hypothesis and the ids
of the probes — a *control* probe (the attacker reaching its OWN object), a
*breach* probe (the attacker reaching the forbidden object/function), and an
optional anonymous *baseline* probe (the SAME breach request replayed with NO
session) — it recovers the operator-declared boundary the seeder wrote into the
graph, reads the observed status code of each probe, and decides:

  VALIDATED     control SUCCEEDED (session is genuinely alive), the breach was
                GRANTED, AND an unauthenticated caller was DENIED that same route
                — a real privilege boundary that only the attacker's identity
                crossed;
  DISPROVED     control SUCCEEDED but the breach was DENIED — the boundary holds
                (the honest differential: no finding);
  INCONCLUSIVE  control did NOT succeed (dead/invalid/expired session, or the
                baseline itself is unreachable); OR the breach was granted but an
                unauthenticated caller was ALSO granted the same route (a public
                route / an app that returns success for everything — the grant is
                not attributable to privilege, so nothing is claimed); also when
                evidence/boundary metadata is missing.

Two things make this sound: a status code alone is never the verdict, and the
verdict never depends on the response body (which would demand target-specific
knowledge). The control probe rules out a dead session; the anonymous negative
control rules out a public route — a breach 2xx only counts when the SAME
session simultaneously proves it is legitimately alive against its own object
AND an unauthenticated caller is refused the very same route. Together they
eliminate the "expired session" and "app returns 200 for everything" confounds.

It has no target knowledge, performs no scoring, and never mutates the graph.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment


@dataclass(frozen=True)
class PrivEscExpectation:
    """The declared privilege boundary recovered for one hypothesis identity."""

    type: str
    attacker: str
    victim: str
    control_method: str
    control_url: str
    breach_method: str
    breach_url: str
    breach_path: str
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


def privesc_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> PrivEscExpectation | None:
    """
    Recover the declared privilege boundary for one hypothesis identity.

    `aspect` is the identity action; it keys onto the
    ``requires_no_privilege_escalation`` relationship the seeder emitted.
    Returns None if no matching boundary edge exists.
    """
    target = f"privesc:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_no_privilege_escalation"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            return PrivEscExpectation(
                type=meta.get("type", ""),
                attacker=meta.get("attacker", ""),
                victim=meta.get("victim", ""),
                control_method=meta.get("control_method", "GET"),
                control_url=meta.get("control_url", ""),
                breach_method=meta.get("breach_method", "GET"),
                breach_url=meta.get("breach_url", ""),
                breach_path=meta.get("breach_path", ""),
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
        ):
            candidates.append(evidence)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _status_of(evidence) -> int | None:
    try:
        return int(evidence.data.get("status_code"))
    except (TypeError, ValueError):
        return None


def judge_privilege_escalation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    control_experiment_id: str,
    breach_experiment_id: str,
    baseline_experiment_id: str | None = None,
) -> ValidationJudgment:
    """Decide whether the three-probe differential proves an escalation.

    ``baseline_experiment_id`` is the anonymous negative control (the breach
    request replayed with no session). The live pipeline always supplies it; a
    direct two-probe call may omit it, in which case the public-route check is
    skipped (the weaker, control-only differential).
    """

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=breach_experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="privilege_escalation",
        )

    expectation = privesc_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.type:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=breach_experiment_id,
            status="INCONCLUSIVE",
            reason="no declared privilege boundary for this hypothesis",
            contradiction_kind="privilege_escalation",
        )

    control_exp = graph.experiments.get(control_experiment_id)
    breach_exp = graph.experiments.get(breach_experiment_id)
    control_ev = _probe_evidence(graph, control_exp)
    breach_ev = _probe_evidence(graph, breach_exp)

    if control_ev is None or breach_ev is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=breach_experiment_id,
            status="INCONCLUSIVE",
            reason=(
                "expected exactly one control probe and one breach probe for "
                "this hypothesis"
            ),
            contradiction_kind="privilege_escalation",
        )

    # Optional anonymous NEGATIVE control: the same breach request replayed with
    # NO attacker session. It is what eliminates the "public route / the app
    # returns success for everything" confound — a breach 2xx counts as an
    # escalation only if an unauthenticated caller is DENIED the very same route,
    # so the grant is attributable to the attacker's identity rather than to a
    # route that is open to everyone. When a caller supplies this probe (the
    # live pipeline always does) its evidence MUST be present; when omitted (a
    # direct two-probe judge call) the check is skipped.
    baseline_provided = baseline_experiment_id is not None
    baseline_ev = None
    if baseline_provided:
        baseline_ev = _probe_evidence(
            graph, graph.experiments.get(baseline_experiment_id)
        )
        if baseline_ev is None:
            return ValidationJudgment(
                hypothesis_id=hypothesis.id,
                experiment_id=breach_experiment_id,
                status="INCONCLUSIVE",
                reason=(
                    "the anonymous negative-control probe is missing, so a "
                    "public route cannot be ruled out — no escalation claimed"
                ),
                contradiction_kind="privilege_escalation",
            )

    success = set(expectation.success_statuses)
    control_status = _status_of(control_ev)
    breach_status = _status_of(breach_ev)
    baseline_status = _status_of(baseline_ev) if baseline_ev is not None else None

    control_ok = control_status is not None and control_status in success
    breach_granted = breach_status is not None and breach_status in success
    baseline_denied = (
        baseline_status is not None and baseline_status not in success
    )

    if not control_ok:
        status = "INCONCLUSIVE"
        reason = (
            f"control probe ({expectation.control_method} "
            f"{expectation.control_url}) returned {control_status}, not a "
            "success — the attacker session is not proven alive, so a breach "
            "result cannot be attributed (no claim made)"
        )
    elif not breach_granted:
        status = "DISPROVED"
        reason = (
            f"with a live session (control {control_status}), the breach "
            f"({expectation.breach_method} {expectation.breach_path}) returned "
            f"{breach_status} — the boundary holds; no escalation"
        )
    elif baseline_provided and not baseline_denied:
        # Attacker was granted, but so was an unauthenticated caller: the route
        # is public (or the app returns success for everything). The grant is
        # NOT attributable to the attacker's privilege, so nothing is claimed.
        status = "INCONCLUSIVE"
        reason = (
            f"attacker '{expectation.attacker}' was granted {breach_status} on "
            f"{expectation.breach_method} {expectation.breach_path}, but an "
            f"unauthenticated caller was ALSO granted {baseline_status} — the "
            "route is public or the app returns success for everything, so the "
            "grant is not attributable to privilege (no escalation claimed)"
        )
    else:
        status = "VALIDATED"
        who = (
            f"{expectation.victim}'s object"
            if expectation.type == "horizontal"
            else "an elevated function"
        )
        denied_note = (
            f" while an unauthenticated caller was denied {baseline_status}"
            if baseline_provided
            else ""
        )
        reason = (
            f"with a live session (control {control_status}), attacker "
            f"'{expectation.attacker}' was GRANTED {breach_status} on {who} "
            f"({expectation.breach_method} {expectation.breach_path}){denied_note}"
            " — the declared privilege boundary was crossed"
        )

    evidence_ids = (control_ev.id, breach_ev.id)
    if baseline_ev is not None:
        evidence_ids = evidence_ids + (baseline_ev.id,)

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=breach_experiment_id,
        status=status,
        reason=reason,
        contradiction_kind="privilege_escalation",
        expected=False,          # boundary: breach MUST NOT be granted
        observed=breach_granted,  # was it actually granted?
        evidence_ids=evidence_ids,
    )
