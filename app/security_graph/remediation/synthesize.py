"""
Synthesize the corrective control implied by a confirmed finding.

This is the deterministic bridge from FIND to PATCH. It never re-scores a
finding, never invents authorization semantics, and holds no knowledge of
any particular target: it reads the explicit policy the judge already used
and the durable request provenance of the live probe, and states the one
access-control rule the confirmed contradiction demands.

Only *deny-violations* are shielded — cases where the operator policy says
DENY but the live target ALLOWED. An "allow that was denied" (an
availability regression) cannot be safely corrected by adding a deny at a
gateway, so it yields no plan (the caller reports NOT_APPLICABLE).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..graph import SecurityGraph
from ..models import Experiment, SecurityFinding
from ..policy.authorization import authorization_policy
from .model import AccessControlRule, RemediationPlan


def _originating_probe(
    graph: SecurityGraph,
    hypothesis_id: str,
) -> Experiment | None:
    """
    Recover the completed live HTTP probe that backs this finding.

    All validation attempts for a hypothesis share the same request
    template (URL / method / headers), so a deterministic pick is safe.
    """
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "authorization_http_check"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]


def synthesize_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> RemediationPlan | None:
    """Derive the enforcement plan for one confirmed finding, or None."""

    if finding.kind != "authorization_policy_violation":
        return None

    identity = finding.identity
    if identity is None or not (
        identity.principal_id and identity.resource_id and identity.action
    ):
        return None

    policy = authorization_policy(
        graph,
        principal_id=identity.principal_id,
        resource_id=identity.resource_id,
        action=identity.action,
    )
    # Only a violated *deny* policy is shieldable. `policy.allowed is False`
    # means the operator declared DENY; the finding proves the target
    # allowed it anyway.
    if policy is None or policy.allowed is not False:
        return None

    probe = _originating_probe(graph, finding.hypothesis_id)
    if probe is None or probe.request is None:
        return None

    request = probe.request
    split = urlsplit(request.url)
    if not split.scheme or not split.netloc:
        return None

    principal = graph.principals.get(identity.principal_id)
    principal_name = principal.name if principal is not None else identity.principal_id
    principal_kind = principal.kind if principal is not None else "user"

    rule = AccessControlRule(
        principal_name=principal_name,
        principal_kind=principal_kind,
        method=request.method.strip().upper(),
        path=split.path or "/",
        action=identity.action,
        decision="deny",
        principal_headers=tuple(request.headers),
    )

    upstream_base = f"{split.scheme}://{split.netloc}"

    rationale = (
        f"Operator policy declares {principal_name} MUST be denied "
        f"{identity.action} on {rule.method} {rule.path}.",
        "The live probe observed the target ALLOWED it — a confirmed "
        "authorization contradiction.",
        "The enforcement shield denies exactly this principal at the "
        "gateway and forwards all other traffic to the target unchanged.",
    )

    return RemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        target_url=request.url,
        rationale=rationale,
    )
