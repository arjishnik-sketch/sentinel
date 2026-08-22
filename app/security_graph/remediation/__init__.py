"""
Remediation — the PATCH + PROVE stage.

Public surface for turning a *confirmed* authorization finding into a
corrective control, enforcing it live, and proving (via the same
deterministic judge) that the contradiction no longer reproduces.
"""

from .artifacts import render_artifacts
from .enforcer import RemediationEnforcer, evaluate_request
from .model import (
    AccessControlRule,
    RemediationArtifacts,
    RemediationOutcome,
    RemediationPlan,
    RemediationVerification,
    SourcePatch,
)
from .run import remediate_and_prove, remediate_confirmed_findings
from .source_patch import detect_framework, generate_source_patch
from .synthesize import synthesize_remediation
from .verify import verify_remediation

__all__ = [
    "AccessControlRule",
    "RemediationArtifacts",
    "RemediationOutcome",
    "RemediationPlan",
    "RemediationVerification",
    "SourcePatch",
    "render_artifacts",
    "RemediationEnforcer",
    "evaluate_request",
    "remediate_and_prove",
    "remediate_confirmed_findings",
    "detect_framework",
    "generate_source_patch",
    "synthesize_remediation",
    "verify_remediation",
]
