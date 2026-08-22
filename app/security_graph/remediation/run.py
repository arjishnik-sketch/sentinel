"""
Orchestrate PATCH + PROVE for one confirmed finding.

This ties the deterministic pieces together: synthesize the corrective
rule, render deployable artifacts, optionally generate a source patch,
stand up the live enforcement shield, and let the pure judge re-decide
through it. The result is a single :class:`RemediationOutcome`.

Honesty is structural: FIX_PROVEN is returned only when
:func:`verify_remediation` reports the judge flipped to DISPROVED under
enforcement. Anything else is FIX_FAILED, NOT_APPLICABLE, or ERROR — never
a manufactured success.
"""

from __future__ import annotations

from ..graph import SecurityGraph
from ..models import SecurityFinding
from .artifacts import render_artifacts
from .enforcer import RemediationEnforcer
from .model import RemediationOutcome
from .source_patch import generate_source_patch
from .synthesize import synthesize_remediation
from .verify import verify_remediation


def remediate_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    source_root: str | None = None,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> RemediationOutcome:
    """Synthesize → enforce → prove a corrective control for one finding."""

    plan = synthesize_remediation(graph, finding)
    if plan is None:
        return RemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed deny-policy violations with recoverable live "
                "probe provenance are shieldable."
            ),
        )

    artifacts = render_artifacts(plan.rule, plan.upstream_base)
    source_patch = generate_source_patch(plan.rule, source_root=source_root)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return RemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            source_patch=source_patch,
            detail="confirmed hypothesis or its identity is missing",
        )

    try:
        if use_enforcer:
            with RemediationEnforcer(
                plan.rule,
                plan.upstream_base,
            ) as enforcer:
                verification = verify_remediation(
                    graph,
                    hypothesis=hypothesis,
                    plan=plan,
                    enforcer_base=enforcer.base_url,
                    before_executor=before_executor,
                    after_executor=after_executor,
                )
        else:
            # Injected-executor path (tests): the after executor supplies the
            # post-enforcement response directly, so no proxy is stood up.
            verification = verify_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — report cleanly, never raise
        return RemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            source_patch=source_patch,
            detail=str(exc),
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return RemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        source_patch=source_patch,
        detail=verification.reason,
    )


def remediate_confirmed_findings(
    graph: SecurityGraph,
    *,
    source_root: str | None = None,
) -> list[RemediationOutcome]:
    """Remediate every OPEN confirmed authorization finding, deterministically."""
    findings = graph.findings_for(
        kind="authorization_policy_violation",
        status="OPEN",
    )
    findings = sorted(findings, key=lambda item: item.id)
    return [
        remediate_and_prove(graph, finding, source_root=source_root)
        for finding in findings
    ]
