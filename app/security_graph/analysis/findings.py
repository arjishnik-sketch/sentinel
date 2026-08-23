from ..models import (
    FindingMaterialization,
    Hypothesis,
    SecurityFinding,
)


# Coarse default finding severity per hypothesis kind. This is the
# reporting-level default only; class-specific detail (e.g. an operator's
# declared per-header severity) is surfaced by that class's own renderer.
_SEVERITY_BY_KIND = {
    "authorization_policy_violation": "HIGH",
    "security_misconfiguration": "MEDIUM",
    "insecure_cookie": "MEDIUM",
    "privilege_escalation": "HIGH",
}
_DEFAULT_SEVERITY = "HIGH"


def finding_from_hypothesis(
    hypothesis: Hypothesis,
) -> SecurityFinding | None:
    """
    Derive a security finding from a confirmed hypothesis.

    Findings are never created from OPEN, DISPROVED, or
    otherwise unresolved hypotheses.
    """

    if hypothesis.status != "CONFIRMED":
        return None

    return SecurityFinding(
        id=f"finding:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind=hypothesis.kind,
        title=hypothesis.claim,
        claim=hypothesis.claim,
        severity=_SEVERITY_BY_KIND.get(hypothesis.kind, _DEFAULT_SEVERITY),
        confidence=hypothesis.confidence,
        identity=hypothesis.identity,
        evidence_ids=hypothesis.evidence_ids,
        status="OPEN",
    )


def _merge_finding(
    existing: SecurityFinding,
    incoming: SecurityFinding,
) -> SecurityFinding:
    """
    Merge newer validated finding state into an existing finding.

    Finding identity and ownership remain stable.

    Evidence is accumulated rather than replaced.
    Confidence never decreases during evidence accumulation.
    """

    evidence_ids = tuple(
        dict.fromkeys(
            existing.evidence_ids
            + incoming.evidence_ids
        )
    )

    return SecurityFinding(
        id=existing.id,
        hypothesis_id=existing.hypothesis_id,
        kind=existing.kind,
        title=incoming.title,
        claim=incoming.claim,
        severity=incoming.severity,
        confidence=max(
            existing.confidence,
            incoming.confidence,
        ),
        identity=existing.identity,
        evidence_ids=evidence_ids,
        status=existing.status,
    )


def materialize_confirmed_findings(
    graph,
) -> FindingMaterialization:
    """
    Materialize confirmed hypotheses into graph findings.

    This operation is idempotent and evidence-accumulating.

    A semantically equivalent finding is never duplicated.
    New evidence updates the existing finding instead.
    """

    created: list[SecurityFinding] = []
    updated: list[SecurityFinding] = []
    unchanged: list[SecurityFinding] = []

    for hypothesis in graph.hypotheses.values():
        incoming = finding_from_hypothesis(hypothesis)

        if incoming is None:
            continue

        existing = graph.find_equivalent_finding(
            incoming
        )

        if existing is None:
            graph.add_finding(incoming)
            created.append(incoming)
            continue

        merged = _merge_finding(
            existing,
            incoming,
        )

        if merged == existing:
            unchanged.append(existing)
            continue

        graph.add_finding(merged)
        updated.append(merged)

    return FindingMaterialization(
        created=tuple(created),
        updated=tuple(updated),
        unchanged=tuple(unchanged),
    )
