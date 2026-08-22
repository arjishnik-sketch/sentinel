"""
Post-validation user decision boundary.

This module intentionally does NOT implement remediation.

Once Sentinel has a validated finding, the user decides what
happens next.

The security finding remains authoritative and evidence-backed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class PostValidationAction(str, Enum):
    ATTEMPT_REMEDIATION = "ATTEMPT_REMEDIATION"
    SKIP_REMEDIATION = "SKIP_REMEDIATION"
    GENERATE_REPORT = "GENERATE_REPORT"
    CONTINUE_RESEARCH = "CONTINUE_RESEARCH"


@dataclass(frozen=True)
class PostValidationDecision:
    action: PostValidationAction
    remediation_requested: bool
    report_requested: bool
    continue_research: bool


def choose_post_validation_action(
    choice: str,
) -> PostValidationDecision:
    """
    Convert an explicit user choice into a deterministic action.

    Accepted choices:
        1 -> attempt remediation
        2 -> skip remediation
        3 -> generate report
        4 -> continue research

    No remediation is executed here.
    No finding is changed here.
    No evidence is changed here.
    """

    normalized = str(choice).strip().lower()

    mapping = {
        "1": PostValidationAction.ATTEMPT_REMEDIATION,
        "attempt remediation": PostValidationAction.ATTEMPT_REMEDIATION,
        "2": PostValidationAction.SKIP_REMEDIATION,
        "skip remediation": PostValidationAction.SKIP_REMEDIATION,
        "3": PostValidationAction.GENERATE_REPORT,
        "generate report": PostValidationAction.GENERATE_REPORT,
        "4": PostValidationAction.CONTINUE_RESEARCH,
        "continue research": PostValidationAction.CONTINUE_RESEARCH,
    }

    if normalized not in mapping:
        raise ValueError(
            "Invalid post-validation choice. "
            "Expected 1, 2, 3, or 4."
        )

    action = mapping[normalized]

    return PostValidationDecision(
        action=action,
        remediation_requested=(
            action is PostValidationAction.ATTEMPT_REMEDIATION
        ),
        report_requested=(
            action is PostValidationAction.GENERATE_REPORT
        ),
        continue_research=(
            action is PostValidationAction.CONTINUE_RESEARCH
        ),
    )


def build_evidence_report(finding: Any) -> str:
    """
    Produce a deterministic evidence-backed report from a finding.

    This function intentionally consumes the finding as-is.
    It does not infer a vulnerability that is not already represented
    by the finding.
    """

    finding_id = getattr(finding, "id", "unknown")
    status = getattr(finding, "status", "unknown")
    severity = getattr(finding, "severity", "unknown")
    confidence = getattr(finding, "confidence", "unknown")
    evidence_ids = tuple(
        getattr(finding, "evidence_ids", ()) or ()
    )

    hypothesis_id = getattr(
        finding,
        "hypothesis_id",
        "unknown",
    )

    lines = [
        "============================================================",
        "SENTINEL SECURITY FINDING REPORT",
        "============================================================",
        "",
        f"Finding ID   : {finding_id}",
        f"Hypothesis   : {hypothesis_id}",
        f"Status       : {status}",
        f"Severity     : {severity}",
        f"Confidence   : {confidence}",
        "",
        "Evidence IDs:",
    ]

    if evidence_ids:
        lines.extend(
            f"  - {evidence_id}"
            for evidence_id in evidence_ids
        )
    else:
        lines.append("  - none")

    lines.extend(
        [
            "",
            "Remediation status: NOT REQUESTED",
            "",
            "This report reflects the validated finding and its",
            "recorded evidence. No remediation was executed.",
            "",
            "============================================================",
        ]
    )

    return "\n".join(lines)


def interactive_post_validation_menu() -> PostValidationAction:
    """
    Interactive user decision boundary.

    This is intentionally a pure choice layer. It does not execute
    remediation, network activity, or research by itself.
    """

    print()
    print("============================================================")
    print(" SENTINEL — VALIDATED SECURITY FINDING")
    print("============================================================")
    print()
    print("[1] Attempt remediation")
    print("[2] Skip remediation")
    print("[3] Generate report")
    print("[4] Continue research")
    print()

    while True:
        choice = input("Select action [1-4]: ").strip()

        try:
            decision = choose_post_validation_action(choice)
        except ValueError as exc:
            print(f"Invalid choice: {exc}")
            continue

        print()
        print("Selected:", decision.action.value)

        return decision.action
