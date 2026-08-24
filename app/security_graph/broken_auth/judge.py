"""
PURE deterministic judge for the broken-authentication class.

The analogue of :func:`judge_privilege_escalation`: it reasons over the exact
same **three-probe differential**, but the boundary crossed is a token-validation
flaw rather than an object/function boundary. Given a hypothesis and the ids of
the probes — a *control* probe (the GENUINE captured token → MUST succeed), a
*breach* probe (a FORGED token → the validation-flaw probe), and an anonymous
*baseline* probe (NO token → MUST be denied) — it recovers the operator-declared
``requires_authentic_token`` boundary the seeder wrote into the graph, reads the
observed status code of each probe, and decides:

  VALIDATED     control SUCCEEDED (the route is genuinely token-authenticated and
                the session valid), the forged token was ACCEPTED, AND an
                unauthenticated caller was DENIED that same route — the server
                accepted a token Sentinel minted, so it does not authentically
                verify tokens;
  DISPROVED     control SUCCEEDED but the forged token was REJECTED — token
                validation holds (the honest differential: no finding);
  INCONCLUSIVE  control did NOT succeed (the route is not token-authenticated, or
                the captured session is invalid/expired); OR the forged token was
                accepted but an unauthenticated caller was ALSO accepted (a public
                route — the acceptance is not attributable to a validation flaw);
                also when evidence/boundary metadata is missing.

Two things make this sound: a status code alone is never the verdict, and the
verdict never depends on the response body. The control probe (genuine token)
rules out a route that simply is not token-guarded; the anonymous negative
control rules out a public route. Only when the genuine token works, the FORGED
token also works, AND anonymous does not, is the forgery attributable to a real
validation flaw. It has no target knowledge, performs no scoring, and never
mutates the graph.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment

@dataclass(frozen=True)
class BrokenAuthExpectation:
    """The declared token-authentication boundary for one hypothesis identity."""

    forgery: str
    method: str
    breach_url: str
    breach_path: str
    guard_provable: bool
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


def broken_auth_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> BrokenAuthExpectation | None:
    """
    Recover the declared token-authentication boundary for one identity.

    `aspect` is the identity action; it keys onto the ``requires_authentic_token``
    relationship the seeder emitted. Returns None if no matching edge exists.
    """
    target = f"broken_auth:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_authentic_token"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            return BrokenAuthExpectation(
                forgery=meta.get("forgery", ""),
                method=meta.get("breach_method", "GET"),
                breach_url=meta.get("breach_url", ""),
                breach_path=meta.get("breach_path", ""),
                guard_provable=meta.get("guard_provable", "") == "true",
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

def judge_broken_auth(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    control_experiment_id: str,
    breach_experiment_id: str,
    baseline_experiment_id: str | None = None,
) -> ValidationJudgment:
    """Decide whether the three-probe differential proves a token-validation flaw.

    ``baseline_experiment_id`` is the anonymous negative control (the breach
    route with NO token). The live pipeline always supplies it; a direct
    two-probe call may omit it, skipping the public-route check.
    """

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=breach_experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="broken_auth",
        )

    expectation = broken_auth_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.forgery:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=breach_experiment_id,
            status="INCONCLUSIVE",
            reason="no declared token-authentication boundary for this hypothesis",
            contradiction_kind="broken_auth",
        )

    control_ev = _probe_evidence(graph, graph.experiments.get(control_experiment_id))
    breach_ev = _probe_evidence(graph, graph.experiments.get(breach_experiment_id))

    if control_ev is None or breach_ev is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=breach_experiment_id,
            status="INCONCLUSIVE",
            reason=(
                "expected exactly one control probe and one breach probe for "
                "this hypothesis"
            ),
            contradiction_kind="broken_auth",
        )

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
                    "public route cannot be ruled out — no flaw claimed"
                ),
                contradiction_kind="broken_auth",
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
            f"control probe (genuine token on {expectation.method} "
            f"{expectation.breach_path}) returned {control_status}, not a "
            "success — the route is not proven token-authenticated, so a forged "
            "result cannot be attributed (no claim made)"
        )
    elif not breach_granted:
        status = "DISPROVED"
        reason = (
            f"with the genuine token accepted (control {control_status}), the "
            f"forged token ({expectation.forgery}) returned {breach_status} on "
            f"{expectation.method} {expectation.breach_path} — token validation "
            "holds; no flaw"
        )
    elif baseline_provided and not baseline_denied:
        status = "INCONCLUSIVE"
        reason = (
            f"the forged token was accepted ({breach_status}) but an "
            f"unauthenticated caller was ALSO accepted ({baseline_status}) on "
            f"{expectation.method} {expectation.breach_path} — the route is "
            "public, so the acceptance is not attributable to a validation flaw "
            "(no claim made)"
        )
    else:
        denied_note = (
            f" while an unauthenticated caller was denied {baseline_status}"
            if baseline_provided
            else ""
        )
        status = "VALIDATED"
        reason = (
            f"with the genuine token accepted (control {control_status}), a "
            f"FORGED token ({expectation.forgery}) was also ACCEPTED "
            f"{breach_status} on {expectation.method} {expectation.breach_path}"
            f"{denied_note} — the server accepted a token Sentinel minted, so it "
            "does not authentically verify the token signature"
        )

    evidence_ids = (control_ev.id, breach_ev.id)
    if baseline_ev is not None:
        evidence_ids = evidence_ids + (baseline_ev.id,)

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=breach_experiment_id,
        status=status,
        reason=reason,
        contradiction_kind="broken_auth",
        expected=False,           # boundary: a forged token MUST NOT be accepted
        observed=breach_granted,  # was it actually accepted?
        evidence_ids=evidence_ids,
    )



