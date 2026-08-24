"""
PURE deterministic judge for the SSRF class.

The analogue of :func:`judge_open_redirect`, but it reasons over an **out-of-band
callback differential** rather than a response-header one. Given a hypothesis, the
id of a *payload* probe (the fetch parameter set to Sentinel's own loopback
collaborator URL, carrying a fresh nonce) and the id of a *control* anchor probe
(the parameter set to the target's own origin — a benign same-origin fetch that
must NOT reach our collaborator), it recovers the operator-declared surface, reads
the recorded callback facts each probe left behind, and decides:

  VALIDATED     the collaborator recorded a hit on the payload nonce (the target
                made a server-side request of the URL we injected) AND the control
                anchor confirms that same payload nonce was NOT yet hit before we
                injected it (temporal attribution). The fetch is provably
                attacker-controlled: a real SSRF;
  DISPROVED     no hit on the payload nonce — the parameter is not fetched
                server-side, or the fetch was blocked (also the post-fix state once
                the url-allowlist request-guard denies the off-allowlist URL);
  INCONCLUSIVE  the payload callback evidence is missing/unreadable, or the surface
                metadata is missing, or a NEVER-INJECTED control nonce was somehow
                recorded (a spurious/forged collaborator record — attribution
                failed), or the payload was hit but the control anchor did not
                establish the pre-injection baseline.

Three things make this sound. First, a target status code is never the verdict —
only a collaborator hit on our unique nonce is. Second, the nonce is random and
appears ONLY in the payload parameter value, so a recorded request for it cannot
be coincidental or forged — it can only be the target fetching our input. Third, a
separate control nonce that is NEVER injected anywhere must stay un-hit; if it were
recorded, the collaborator's attribution is untrustworthy and the observation is
refused. The judge has no target knowledge, contacts no collaborator, performs no
scoring, and never mutates the graph — it reads booleans out of graph evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment


@dataclass(frozen=True)
class SsrfExpectation:
    """The declared fetch surface for one hypothesis identity."""

    method: str
    path: str
    endpoint_url: str
    param: str
    location: str
    target_host: str
    severity: str


def ssrf_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> SsrfExpectation | None:
    """
    Recover the declared fetch surface for one hypothesis identity.

    `aspect` is the identity action; it keys onto the ``requires_no_ssrf``
    relationship the seeder emitted. Returns None if no matching edge exists.
    """
    target = f"ssrf:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_no_ssrf"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            endpoint_url = meta.get("endpoint_url", "")
            return SsrfExpectation(
                method=meta.get("method", "GET"),
                path=meta.get("path", ""),
                endpoint_url=endpoint_url,
                param=meta.get("param", ""),
                location=meta.get("location", "query"),
                target_host=(urlsplit(endpoint_url).hostname or "").lower(),
                severity=meta.get("severity", "HIGH"),
            )
    return None


def _callback_evidence(graph: SecurityGraph, experiment_id: str | None):
    """
    The single out-of-band callback evidence backing this experiment, or None.

    This is the ``ssrf_callback`` fact the RUNNER wrote from the collaborator's
    hit record — NOT the target's HTTP response. The judge reads only this.
    """
    if experiment_id is None:
        return None
    experiment = graph.experiments.get(experiment_id)
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
            and data.get("mode") == "ssrf_callback"
            and "payload_nonce_hit" in data
            and "control_nonce_hit" in data
        ):
            candidates.append(evidence)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _hit(value) -> bool:
    """Strictly interpret a recorded hit flag as a boolean True."""
    return value is True


def judge_ssrf(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    control_experiment_id: str,
    payload_experiment_id: str,
) -> ValidationJudgment:
    """Decide whether the out-of-band callback differential proves an SSRF."""

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="ssrf",
        )

    expectation = ssrf_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.param:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason="no declared SSRF surface for this hypothesis",
            contradiction_kind="ssrf",
        )

    payload_cb = _callback_evidence(graph, payload_experiment_id)
    if payload_cb is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason="the payload out-of-band callback evidence is missing or unreadable",
            contradiction_kind="ssrf",
        )

    control_cb = _callback_evidence(graph, control_experiment_id)

    evidence_ids = tuple(
        ev.id for ev in (payload_cb, control_cb) if ev is not None
    )

    payload_hit = _hit(payload_cb.data.get("payload_nonce_hit"))

    # A never-injected control nonce recorded anywhere means the collaborator's
    # attribution cannot be trusted — refuse rather than guess.
    spurious = _hit(payload_cb.data.get("control_nonce_hit")) or (
        control_cb is not None and _hit(control_cb.data.get("control_nonce_hit"))
    )
    if spurious:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason=(
                "a never-injected control nonce was recorded by the collaborator "
                "— attribution is untrustworthy, so the observation is refused"
            ),
            contradiction_kind="ssrf",
            evidence_ids=evidence_ids,
        )

    # Temporal attribution: the control anchor must have run and observed the
    # payload nonce NOT yet hit before we injected it.
    attribution_ok = control_cb is not None and not _hit(
        control_cb.data.get("payload_nonce_hit")
    )

    if payload_hit and attribution_ok:
        reason = (
            f"the payload URL on '{expectation.param}' "
            f"({expectation.method} {expectation.path}) was fetched server-side: "
            "Sentinel's loopback collaborator recorded a request for the "
            "unforgeable payload nonce — a nonce that appears ONLY in the URL we "
            "injected — while the control anchor confirmed that nonce was un-hit "
            "before injection: the fetch is attacker-controlled (a real SSRF)"
        )
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="VALIDATED",
            reason=reason,
            contradiction_kind="ssrf",
            expected=False,   # boundary: the param MUST NOT trigger a server fetch
            observed=True,    # it did
            evidence_ids=evidence_ids,
        )

    if payload_hit and not attribution_ok:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason=(
                "the collaborator recorded the payload nonce, but the control "
                "anchor did not establish the pre-injection baseline — the "
                "differential is unestablished, so the observation is refused"
            ),
            contradiction_kind="ssrf",
            evidence_ids=evidence_ids,
        )

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=payload_experiment_id,
        status="DISPROVED",
        reason=(
            f"the payload URL on '{expectation.param}' "
            f"({expectation.method} {expectation.path}) triggered no callback: the "
            "collaborator recorded no request for the payload nonce — the parameter "
            "is not fetched server-side, or the fetch was blocked (also the "
            "post-fix state once the url-allowlist request-guard denies the "
            "off-allowlist URL) — no SSRF"
        ),
        contradiction_kind="ssrf",
        expected=False,
        observed=False,
        evidence_ids=evidence_ids,
    )
