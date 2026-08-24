"""
`investigate <target>` — run Sentinel's autonomous authorization
research loop against a live target and render the reasoning.

This command is the end-to-end entry point:

    recon -> hypotheses -> adaptive research cycles -> findings

Every cycle is shown as a "decision board": which research action
Sentinel chose, the alternatives it ranked and rejected, and why.
The renderer never asserts a security verdict of its own — it only
displays what the deterministic engine decided.
"""

import os
import re

from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()


# Cyber palette.
_C_PRIMARY = "bright_cyan"
_C_ACCENT = "bright_magenta"
_C_OK = "bright_green"
_C_WARN = "yellow"
_C_BAD = "bright_red"
_C_DIM = "grey58"

_ENDPOINT_IN_ID = re.compile(r"endpoint:(\S+)")


def _short(text: str, width: int = 88) -> str:
    text = " ".join(str(text).split())
    if len(text) <= width:
        return text
    return text[: width - 1] + "…"


def _endpoint_from_id(identifier: str) -> str:
    """Recover a human-readable endpoint URL from an ID string."""
    match = _ENDPOINT_IN_ID.search(identifier or "")
    if match:
        return match.group(1)
    return identifier or ""


class _Deferred(Exception):
    """Internal signal: the operator declined this class's deploy (skip it)."""


def _gate_remediation(*, class_label, color, proposals):
    """
    Human-in-the-loop deploy gate for one vulnerability class.

    Renders the proposed corrective controls (already synthesized, purely) and
    takes the operator's explicit approval BEFORE any enforcement shield is
    stood up or any fix is proven. Returns True iff the operator approved (or
    the run is pre-authorized via $SENTINEL_ASSUME_YES / non-interactive rules
    in :mod:`app.commands.remediation_gate`). On decline a deferred panel is
    shown and the deployable artifacts remain available to the operator.
    """
    from app.commands.remediation_gate import (
        confirm_deploy,
        deferred_panel,
        proposed_remediation_panel,
    )

    console.print(
        proposed_remediation_panel(
            class_label=class_label,
            color=color,
            proposals=proposals,
        )
    )
    approved, reason = confirm_deploy(
        console,
        class_label=class_label,
        count=len(proposals),
        color=color,
    )
    if not approved:
        console.print(deferred_panel(class_label=class_label, reason=reason))
    return approved


def _banner() -> Panel:
    art = Text()
    art.append("SENTINEL", style=f"bold {_C_PRIMARY}")
    art.append("  //  ", style=_C_DIM)
    art.append("AUTONOMOUS AUTHORIZATION RESEARCH", style=f"bold {_C_ACCENT}")
    art.append("\n")
    art.append(
        "find → reason → prove → patch → prove   ·   evidence-driven   ·   advisory-AI bounded",
        style=_C_DIM,
    )
    return Panel(art, border_style=_C_PRIMARY, padding=(0, 2))


def _recon_panel(result) -> Panel:
    recon = result.recon
    graph = result.graph

    alive = recon.get("alive", []) or []
    crawl = recon.get("crawl", []) or []
    source = recon.get("source", "external_toolchain")

    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row("target", f"[{_C_PRIMARY}]{result.target}[/{_C_PRIMARY}]")
    table.add_row("recon source", source)
    table.add_row("alive hosts", str(len(alive)))
    table.add_row("surface URLs", str(len(crawl)))
    table.add_row("endpoints modeled", str(len(graph.endpoints)))
    table.add_row("recon observations", str(len(graph.observations)))

    return Panel(
        table,
        title=f"[{_C_OK}]▐ RECON[/{_C_OK}]",
        border_style=_C_OK,
        padding=(1, 2),
    )


def _hypotheses_panel(result) -> Panel:
    graph = result.graph

    by_kind: dict[str, int] = {}
    for hypothesis in graph.hypotheses.values():
        by_kind[hypothesis.kind] = by_kind.get(hypothesis.kind, 0) + 1

    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row(
        "total",
        f"[{_C_ACCENT}]{len(graph.hypotheses)}[/{_C_ACCENT}] "
        "authorization hypotheses",
    )
    for kind in sorted(by_kind):
        table.add_row(kind, str(by_kind[kind]))

    note = Text(
        "\nDiscovery is not a vulnerability. Each hypothesis is a "
        "justified reason to test authorization behaviour.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, note),
        title=f"[{_C_ACCENT}]▐ HYPOTHESES[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _cycle_panel(index: int, cycle) -> Panel:
    decision = cycle.research_decision
    status_code = dict(cycle.execution.metadata).get("status_code")

    header = Table.grid(padding=(0, 2))
    header.add_column(style=_C_DIM, justify="right")
    header.add_column()

    if decision is not None:
        target_url = _endpoint_from_id(decision.hypothesis_id)
        header.add_row(
            "action",
            f"[bold {_C_PRIMARY}]{decision.capability_id}[/bold {_C_PRIMARY}]",
        )
        header.add_row(
            "score",
            f"[bold {_C_WARN}]{decision.score:.3f}[/bold {_C_WARN}]",
        )
        header.add_row("probing", f"[white]{_short(target_url)}[/white]")
        header.add_row(
            "outranked",
            f"[{_C_ACCENT}]{len(decision.rejected_candidate_ids)}[/{_C_ACCENT}] "
            "alternative candidate(s)",
        )
        # Smart-selection USP: show when the bounded AI advisor's
        # preference steered this choice within the top-scored tie. It is
        # advisory only — the deterministic score above remains the basis
        # for selection — but making it visible is the whole point.
        if decision.ai_influenced:
            conf = (
                f" [dim](conf {decision.ai_confidence:.2f})[/dim]"
                if decision.ai_confidence is not None
                else ""
            )
            reason = (
                _short(decision.ai_reasoning, 58)
                if decision.ai_reasoning
                else "prioritised this candidate"
            )
            header.add_row(
                "ai advisor",
                f"[bold {_C_ACCENT}]◈ steered[/bold {_C_ACCENT}]{conf}  "
                f"[italic {_C_ACCENT}]{reason}[/italic {_C_ACCENT}]",
            )
    else:
        header.add_row("action", "[dim]no productive research remained[/dim]")

    # Execution outcome — a fact, never a verdict.
    if status_code is not None:
        code = int(status_code)
        code_style = _C_OK if code < 400 else _C_WARN if code < 500 else _C_BAD
        header.add_row(
            "http",
            f"[{code_style}]{code}[/{code_style}]  "
            f"[dim]({cycle.execution.status})[/dim]",
        )

    # Judgment — the deterministic authorization judge, if it ran.
    if cycle.judgment is not None:
        judgment = cycle.judgment
        j_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(judgment.status, _C_WARN)
        header.add_row(
            "judge",
            f"[bold {j_style}]{judgment.status}[/bold {j_style}]  "
            f"[dim]{_short(judgment.reason, 70)}[/dim]",
        )

    blocks = [header]

    # Rationale — the "why this, why now".
    if decision is not None and decision.rationale:
        rationale = Text()
        for reason in decision.rationale[:5]:
            rationale.append("  ▹ ", style=_C_PRIMARY)
            rationale.append(_short(reason, 92) + "\n", style="white")
        blocks.append(Rule(style=_C_DIM))
        blocks.append(rationale)

    # A glimpse of the rejected field — the real endpoints it chose between.
    if decision is not None and decision.rejected_candidate_ids:
        rejected = Text("outranked:  ", style=_C_DIM)
        shown = decision.rejected_candidate_ids[:3]
        for identifier in shown:
            rejected.append(
                _short(_endpoint_from_id(identifier), 40) + "   ",
                style=_C_DIM,
            )
        remaining = len(decision.rejected_candidate_ids) - len(shown)
        if remaining > 0:
            rejected.append(f"(+{remaining} more)", style=_C_DIM)
        blocks.append(rejected)

    # New hypotheses spawned by refinement this cycle.
    if cycle.new_hypothesis_ids:
        blocks.append(
            Text(
                f"↳ refined into {len(cycle.new_hypothesis_ids)} "
                "new hypothesis/hypotheses",
                style=_C_ACCENT,
            )
        )

    return Panel(
        Group(*blocks),
        title=f"[{_C_PRIMARY}]▐ CYCLE {index:02d} · DECISION BOARD[/{_C_PRIMARY}]",
        border_style=_C_PRIMARY,
        padding=(1, 2),
    )


def _findings_panel(result) -> Panel:
    findings = list(result.graph.findings.values())

    if not findings:
        body = Text(
            "No authorization findings were CONFIRMED in this run.\n"
            "Confirmation requires a reproduced authorization "
            "contradiction under the deterministic judge — never an "
            "HTTP status code alone.",
            style=_C_DIM,
        )
        return Panel(
            body,
            title=f"[{_C_DIM}]▐ FINDINGS[/{_C_DIM}]",
            border_style=_C_DIM,
            padding=(1, 2),
        )

    table = Table(
        show_header=True,
        header_style=f"bold {_C_BAD}",
        border_style=_C_BAD,
        expand=True,
    )
    table.add_column("severity")
    table.add_column("title")
    table.add_column("confidence", justify="right")
    table.add_column("status")

    for finding in findings:
        table.add_row(
            f"[{_C_BAD}]{finding.severity}[/{_C_BAD}]",
            _short(finding.title, 60),
            f"{finding.confidence:.2f}",
            finding.status,
        )

    return Panel(
        table,
        title=f"[{_C_BAD}]▐ CONFIRMED FINDINGS[/{_C_BAD}]",
        border_style=_C_BAD,
        padding=(1, 2),
    )


def _outcome_panel(outcome, stopped_reason: str) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    phase_style = {
        "RESOLVED": _C_OK,
        "ACTIVE": _C_PRIMARY,
        "EXHAUSTED": _C_WARN,
        "MIXED": _C_WARN,
        "EMPTY": _C_DIM,
    }.get(outcome.phase, "white")

    table.add_row(
        "frontier phase",
        f"[bold {phase_style}]{outcome.phase}[/bold {phase_style}]",
    )
    table.add_row("stopped", stopped_reason)
    table.add_row("active", str(outcome.active_hypotheses))
    table.add_row("exhausted", str(outcome.exhausted_hypotheses))
    table.add_row("resolved", str(outcome.resolved_hypotheses))

    reasons = Text()
    for reason in outcome.reasons:
        reasons.append("  · ", style=_C_DIM)
        reasons.append(_short(reason, 92) + "\n", style=_C_DIM)

    return Panel(
        Group(table, reasons),
        title=f"[{_C_WARN}]▐ RESEARCH FRONTIER[/{_C_WARN}]",
        border_style=_C_WARN,
        padding=(1, 2),
    )


def _policy_panel(policy, source: str) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row("source", f"[{_C_PRIMARY}]{_short(source, 70)}[/{_C_PRIMARY}]")
    table.add_row(
        "declared rules",
        f"[{_C_ACCENT}]{len(policy.rules)}[/{_C_ACCENT}] "
        "authorization expectation(s)",
    )

    rules = Table.grid(padding=(0, 2))
    rules.add_column(style=_C_DIM)
    for rule in policy.rules[:8]:
        verb = "MUST DENY" if rule.decision == "deny" else "MUST ALLOW"
        verb_style = _C_BAD if rule.decision == "deny" else _C_OK
        rules.add_row(
            f"[{verb_style}]{verb}[/{verb_style}]  "
            f"[white]{rule.principal}[/white] "
            f"[{_C_DIM}]→[/{_C_DIM}] {rule.action} "
            f"[{_C_DIM}]{rule.method} {_short(rule.path, 48)}[/{_C_DIM}]"
        )
    if len(policy.rules) > 8:
        rules.add_row(f"[{_C_DIM}](+{len(policy.rules) - 8} more)[/{_C_DIM}]")

    note = Text(
        "\nGround truth only. A declared expectation is a question for "
        "the judge, never a finding — a contradiction must be reproduced "
        "against the live target.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, Rule(style=_C_DIM), rules, note),
        title=f"[{_C_ACCENT}]▐ ACCESS POLICY ORACLE[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _remediation_panel(outcome) -> Panel:
    """Render the PATCH + PROVE result for one confirmed finding.

    The renderer states only what the deterministic verifier reported. A
    FIX_PROVEN badge is shown solely when the same judge that confirmed the
    finding flipped to DISPROVED under live enforcement — never inferred.
    """

    result = outcome.result
    result_style = {
        "FIX_PROVEN": _C_OK,
        "FIX_FAILED": _C_BAD,
        "NOT_APPLICABLE": _C_DIM,
        "ERROR": _C_BAD,
    }.get(result, _C_WARN)
    badge = {
        "FIX_PROVEN": "✔ FIX PROVEN",
        "FIX_FAILED": "✘ FIX NOT PROVEN",
        "NOT_APPLICABLE": "— NOT APPLICABLE",
        "ERROR": "✘ ERROR",
    }.get(result, result)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row(
        "verdict",
        f"[bold {result_style}]{badge}[/bold {result_style}]",
    )

    plan = outcome.plan
    if plan is not None:
        rule = plan.rule
        table.add_row("strategy", plan.strategy)
        table.add_row(
            "control",
            f"[bold {_C_BAD}]MUST DENY[/bold {_C_BAD}] "
            f"[white]{rule.principal_name}[/white] "
            f"[{_C_DIM}]({rule.principal_kind})[/{_C_DIM}] "
            f"[{_C_DIM}]→[/{_C_DIM}] "
            f"[white]{rule.method} {_short(rule.path, 48)}[/white]",
        )
        table.add_row("upstream", f"[{_C_DIM}]{_short(plan.upstream_base, 60)}[/{_C_DIM}]")

    # The live PROVE — before/after through the enforcement shield.
    verification = outcome.verification
    if verification is not None:
        before_code = verification.before_status_code
        after_code = verification.observed_status_code
        before_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.before_status, _C_WARN)
        after_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.after_status, _C_WARN)
        table.add_row(
            "live prove",
            f"[{_C_DIM}]before[/{_C_DIM}] "
            f"[white]{before_code if before_code is not None else '—'}[/white] "
            f"[bold {before_style}]{verification.before_status}[/bold {before_style}]"
            f"  [{_C_DIM}]→[/{_C_DIM}]  "
            f"[{_C_DIM}]after[/{_C_DIM}] "
            f"[white]{after_code if after_code is not None else '—'}[/white] "
            f"[bold {after_style}]{verification.after_status}[/bold {after_style}]",
        )

    artifacts = outcome.artifacts
    if artifacts is not None:
        table.add_row(
            "artifacts",
            f"[{_C_PRIMARY}]portable-json · nginx · envoy-rbac · caddy[/{_C_PRIMARY}]",
        )

    patch = outcome.source_patch
    if patch is not None:
        patch_style = {
            "GENERATED": _C_OK,
            "ADVISORY": _C_WARN,
            "NOT_PROVIDED": _C_DIM,
        }.get(patch.status, _C_DIM)
        detail = patch.framework if patch.framework != "unknown" else ""
        loc = f" · {patch.file_path}" if patch.file_path else ""
        table.add_row(
            "source patch",
            f"[{patch_style}]{patch.status}[/{patch_style}] "
            f"[{_C_DIM}]{detail}{loc}[/{_C_DIM}]",
        )

    blocks = [table]
    if outcome.detail:
        blocks.append(
            Text(f"\n{_short(outcome.detail, 100)}", style=_C_DIM)
        )

    return Panel(
        Group(*blocks),
        title=f"[{result_style}]▐ REMEDIATION · PATCH + PROVE[/{result_style}]",
        border_style=result_style,
        padding=(1, 2),
    )


def _header_policy_panel(policy, source: str) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    total = sum(len(rule.expectations) for rule in policy.rules)
    table.add_row("source", f"[{_C_PRIMARY}]{_short(source, 70)}[/{_C_PRIMARY}]")
    table.add_row(
        "declared posture",
        f"[{_C_ACCENT}]{total}[/{_C_ACCENT}] header expectation(s) across "
        f"{len(policy.rules)} route(s)",
    )

    rules = Table.grid(padding=(0, 2))
    rules.add_column(style=_C_DIM)
    shown = 0
    for rule in policy.rules:
        for exp in rule.expectations:
            if shown >= 10:
                break
            want = exp.requirement.replace("_", " ").upper()
            if exp.value:
                want = f"{want} '{exp.value}'"
            sev_style = {
                "CRITICAL": _C_BAD,
                "HIGH": _C_BAD,
                "MEDIUM": _C_WARN,
                "LOW": _C_DIM,
            }.get(exp.severity, _C_DIM)
            rules.add_row(
                f"[{sev_style}]{exp.severity:<8}[/{sev_style}] "
                f"[white]{exp.header}[/white] "
                f"[{_C_DIM}]{want}[/{_C_DIM}] "
                f"[{_C_DIM}]· {rule.method} {_short(rule.path, 32)}[/{_C_DIM}]"
            )
            shown += 1

    note = Text(
        "\nGround truth only. A declared header expectation is a question "
        "for the judge — a finding requires the live response to contradict "
        "it. A compliant header yields DISPROVED and no finding.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, Rule(style=_C_DIM), rules, note),
        title=f"[{_C_ACCENT}]▐ HEADER POSTURE ORACLE[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _posture_findings_panel(results) -> Panel:
    """Render every posture probe verdict, including the DISPROVED ones.

    Showing DISPROVED (compliant control ⇒ no finding) beside VALIDATED
    (reproduced misconfiguration ⇒ finding) is the honest differential.
    """
    table = Table(
        show_header=True,
        header_style=f"bold {_C_ACCENT}",
        border_style=_C_ACCENT,
        expand=True,
    )
    table.add_column("verdict")
    table.add_column("severity")
    table.add_column("http", justify="right")
    table.add_column("claim")

    for probe in results:
        v_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(probe.status, _C_WARN)
        label = {
            "VALIDATED": "● FINDING",
            "DISPROVED": "○ no finding",
            "INCONCLUSIVE": "· inconclusive",
        }.get(probe.status, probe.status)
        code = probe.status_code if probe.status_code is not None else "—"
        table.add_row(
            f"[{v_style}]{label}[/{v_style}]",
            f"[{_C_DIM}]{probe.severity}[/{_C_DIM}]",
            f"[white]{code}[/white]",
            _short(probe.reason, 62),
        )

    confirmed = sum(1 for probe in results if probe.status == "VALIDATED")
    note = Text(
        f"\n{confirmed} misconfiguration(s) reproduced against the live "
        f"target and CONFIRMED; compliant controls yield no finding.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, note),
        title=f"[{_C_ACCENT}]▐ POSTURE · DETERMINISTIC JUDGE[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _posture_remediation_panel(outcome) -> Panel:
    """Render the PATCH + PROVE result for one confirmed posture finding."""

    result = outcome.result
    result_style = {
        "FIX_PROVEN": _C_OK,
        "FIX_FAILED": _C_BAD,
        "NOT_APPLICABLE": _C_DIM,
        "ERROR": _C_BAD,
    }.get(result, _C_WARN)
    badge = {
        "FIX_PROVEN": "✔ FIX PROVEN",
        "FIX_FAILED": "✘ FIX NOT PROVEN",
        "NOT_APPLICABLE": "— NOT APPLICABLE",
        "ERROR": "✘ ERROR",
    }.get(result, result)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row(
        "verdict",
        f"[bold {result_style}]{badge}[/bold {result_style}]",
    )

    plan = outcome.plan
    if plan is not None:
        rule = plan.rule
        op_label = {
            "set": "SET",
            "remove": "STRIP",
            "remove_if_equals": "STRIP INSECURE",
        }.get(rule.op, rule.op.upper())
        table.add_row("strategy", plan.strategy)
        detail = f' → "{rule.value}"' if rule.op == "set" and rule.value else ""
        table.add_row(
            "control",
            f"[bold {_C_PRIMARY}]{op_label}[/bold {_C_PRIMARY}] "
            f"[white]{rule.header}[/white]{detail} "
            f"[{_C_DIM}]· {rule.method} {_short(rule.path, 40)}[/{_C_DIM}]",
        )
        table.add_row("upstream", f"[{_C_DIM}]{_short(plan.upstream_base, 60)}[/{_C_DIM}]")

    verification = outcome.verification
    if verification is not None:
        before_code = verification.before_status_code
        after_code = verification.observed_status_code
        before_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.before_status, _C_WARN)
        after_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.after_status, _C_WARN)
        table.add_row(
            "live prove",
            f"[{_C_DIM}]before[/{_C_DIM}] "
            f"[white]{before_code if before_code is not None else '—'}[/white] "
            f"[bold {before_style}]{verification.before_status}[/bold {before_style}]"
            f"  [{_C_DIM}]→[/{_C_DIM}]  "
            f"[{_C_DIM}]after[/{_C_DIM}] "
            f"[white]{after_code if after_code is not None else '—'}[/white] "
            f"[bold {after_style}]{verification.after_status}[/bold {after_style}]",
        )

    if outcome.artifacts is not None:
        table.add_row(
            "artifacts",
            f"[{_C_PRIMARY}]portable-json · nginx · caddy · envoy[/{_C_PRIMARY}]",
        )

    blocks = [table]
    if outcome.detail:
        blocks.append(Text(f"\n{_short(outcome.detail, 100)}", style=_C_DIM))

    return Panel(
        Group(*blocks),
        title=f"[{result_style}]▐ POSTURE REMEDIATION · PATCH + PROVE[/{result_style}]",
        border_style=result_style,
        padding=(1, 2),
    )


def _cookie_policy_panel(policy, source: str) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    total = sum(len(rule.expectations) for rule in policy.rules)
    table.add_row("source", f"[{_C_PRIMARY}]{_short(source, 70)}[/{_C_PRIMARY}]")
    table.add_row(
        "declared posture",
        f"[{_C_ACCENT}]{total}[/{_C_ACCENT}] cookie expectation(s) across "
        f"{len(policy.rules)} route(s)",
    )

    rules = Table.grid(padding=(0, 2))
    rules.add_column(style=_C_DIM)
    shown = 0
    for rule in policy.rules:
        for exp in rule.expectations:
            if shown >= 10:
                break
            want = exp.check.replace("_", " ").upper()
            token = exp.flag or exp.value
            if token:
                want = f"{want} '{token}'"
            sev_style = {
                "CRITICAL": _C_BAD,
                "HIGH": _C_BAD,
                "MEDIUM": _C_WARN,
                "LOW": _C_DIM,
            }.get(exp.severity, _C_DIM)
            cookie_label = exp.cookie_name or "· every cookie"
            rules.add_row(
                f"[{sev_style}]{exp.severity:<8}[/{sev_style}] "
                f"[white]{cookie_label}[/white] "
                f"[{_C_DIM}]{want}[/{_C_DIM}] "
                f"[{_C_DIM}]· {rule.method} {_short(rule.path, 32)}[/{_C_DIM}]"
            )
            shown += 1

    note = Text(
        "\nGround truth only. A declared cookie expectation is a question "
        "for the judge — a finding requires a Set-Cookie the target actually "
        "sets to contradict it. A compliant, or simply unset, cookie yields "
        "DISPROVED and no finding.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, Rule(style=_C_DIM), rules, note),
        title=f"[{_C_ACCENT}]▐ COOKIE POSTURE ORACLE[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _cookie_findings_panel(results) -> Panel:
    """Render every cookie probe verdict, including the DISPROVED ones."""
    table = Table(
        show_header=True,
        header_style=f"bold {_C_ACCENT}",
        border_style=_C_ACCENT,
        expand=True,
    )
    table.add_column("verdict")
    table.add_column("severity")
    table.add_column("http", justify="right")
    table.add_column("claim")

    for probe in results:
        v_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(probe.status, _C_WARN)
        label = {
            "VALIDATED": "● FINDING",
            "DISPROVED": "○ no finding",
            "INCONCLUSIVE": "· inconclusive",
        }.get(probe.status, probe.status)
        code = probe.status_code if probe.status_code is not None else "—"
        table.add_row(
            f"[{v_style}]{label}[/{v_style}]",
            f"[{_C_DIM}]{probe.severity}[/{_C_DIM}]",
            f"[white]{code}[/white]",
            _short(probe.reason, 62),
        )

    confirmed = sum(1 for probe in results if probe.status == "VALIDATED")
    note = Text(
        f"\n{confirmed} insecure cookie(s) reproduced against the live "
        f"target and CONFIRMED; compliant or unset cookies yield no finding.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, note),
        title=f"[{_C_ACCENT}]▐ COOKIES · DETERMINISTIC JUDGE[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _cookie_remediation_panel(outcome) -> Panel:
    """Render the PATCH + PROVE result for one confirmed cookie finding."""

    result = outcome.result
    result_style = {
        "FIX_PROVEN": _C_OK,
        "FIX_FAILED": _C_BAD,
        "NOT_APPLICABLE": _C_DIM,
        "ERROR": _C_BAD,
    }.get(result, _C_WARN)
    badge = {
        "FIX_PROVEN": "✔ FIX PROVEN",
        "FIX_FAILED": "✘ FIX NOT PROVEN",
        "NOT_APPLICABLE": "— NOT APPLICABLE",
        "ERROR": "✘ ERROR",
    }.get(result, result)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row(
        "verdict",
        f"[bold {result_style}]{badge}[/bold {result_style}]",
    )

    plan = outcome.plan
    if plan is not None:
        rule = plan.rule
        op_label = {
            "add_flag": "ADD FLAG",
            "remove_flag": "STRIP FLAG",
            "set_samesite": "SET SAMESITE",
        }.get(rule.op, rule.op.upper())
        detail = f" → '{rule.value}'" if rule.op == "set_samesite" else ""
        token = rule.flag or rule.value
        cookie_label = rule.cookie_name or "every"
        table.add_row("strategy", plan.strategy)
        table.add_row(
            "control",
            f"[bold {_C_PRIMARY}]{op_label}[/bold {_C_PRIMARY}] "
            f"[white]{token}[/white]{detail} "
            f"[{_C_DIM}]on {cookie_label} cookie · "
            f"{rule.method} {_short(rule.path, 32)}[/{_C_DIM}]",
        )
        table.add_row(
            "upstream",
            f"[{_C_DIM}]{_short(plan.upstream_base, 60)}[/{_C_DIM}]",
        )

    verification = outcome.verification
    if verification is not None:
        before_code = verification.before_status_code
        after_code = verification.observed_status_code
        before_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.before_status, _C_WARN)
        after_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.after_status, _C_WARN)
        table.add_row(
            "live prove",
            f"[{_C_DIM}]before[/{_C_DIM}] "
            f"[white]{before_code if before_code is not None else '—'}[/white] "
            f"[bold {before_style}]{verification.before_status}[/bold {before_style}]"
            f"  [{_C_DIM}]→[/{_C_DIM}]  "
            f"[{_C_DIM}]after[/{_C_DIM}] "
            f"[white]{after_code if after_code is not None else '—'}[/white] "
            f"[bold {after_style}]{verification.after_status}[/bold {after_style}]",
        )

    if outcome.artifacts is not None:
        table.add_row(
            "artifacts",
            f"[{_C_PRIMARY}]portable-json · nginx · caddy · envoy[/{_C_PRIMARY}]",
        )

    blocks = [table]
    if outcome.detail:
        blocks.append(Text(f"\n{_short(outcome.detail, 100)}", style=_C_DIM))

    return Panel(
        Group(*blocks),
        title=f"[{result_style}]▐ COOKIE REMEDIATION · PATCH + PROVE[/{result_style}]",
        border_style=result_style,
        padding=(1, 2),
    )


def _privesc_matrix_panel(policy, source: str) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row("source", f"[{_C_PRIMARY}]{_short(source, 70)}[/{_C_PRIMARY}]")
    table.add_row(
        "login matrix",
        f"[{_C_ACCENT}]{len(policy.principals)}[/{_C_ACCENT}] account(s) · "
        f"[{_C_ACCENT}]{len(policy.checks)}[/{_C_ACCENT}] declared boundary(ies)",
    )

    rules = Table.grid(padding=(0, 2))
    rules.add_column(style=_C_DIM)
    for check in policy.checks[:10]:
        sev_style = {
            "CRITICAL": _C_BAD,
            "HIGH": _C_BAD,
            "MEDIUM": _C_WARN,
            "LOW": _C_DIM,
        }.get(check.severity, _C_DIM)
        counterparty = (
            f"{check.victim}'s object"
            if check.type == "horizontal"
            else "elevated function"
        )
        rules.add_row(
            f"[{sev_style}]{check.severity:<8}[/{sev_style}] "
            f"[white]{check.attacker}[/white] "
            f"[{_C_DIM}]MUST NOT reach {counterparty} ·[/{_C_DIM}] "
            f"[{_C_DIM}]{check.type} · {check.breach_method} "
            f"{_short(check.breach_path, 32)}[/{_C_DIM}]"
        )

    note = Text(
        "\nGround truth only. Each boundary is proven by a THREE-PROBE "
        "differential on the live target: the attacker's control probe (its "
        "OWN object) MUST succeed, the breach probe MUST be granted, AND an "
        "anonymous caller MUST be denied that same route before an escalation "
        "is CONFIRMED. The control rules out a dead session; the anonymous "
        "baseline rules out a public route. A bare status code is never the "
        "verdict.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, Rule(style=_C_DIM), rules, note),
        title=f"[{_C_ACCENT}]▐ PRIVILEGE-ESCALATION MATRIX ORACLE[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _privesc_findings_panel(results) -> Panel:
    """Render every privilege-escalation verdict, including DISPROVED ones."""
    table = Table(
        show_header=True,
        header_style=f"bold {_C_ACCENT}",
        border_style=_C_ACCENT,
        expand=True,
    )
    table.add_column("verdict")
    table.add_column("severity")
    table.add_column("control", justify="right")
    table.add_column("breach", justify="right")
    table.add_column("anon", justify="right")
    table.add_column("claim")

    for probe in results:
        v_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(probe.status, _C_WARN)
        label = {
            "VALIDATED": "● FINDING",
            "DISPROVED": "○ boundary holds",
            "INCONCLUSIVE": "· inconclusive",
        }.get(probe.status, probe.status)
        control_code = (
            probe.control_status_code
            if probe.control_status_code is not None
            else "—"
        )
        breach_code = (
            probe.breach_status_code
            if probe.breach_status_code is not None
            else "—"
        )
        baseline_code = (
            probe.baseline_status_code
            if probe.baseline_status_code is not None
            else "—"
        )
        table.add_row(
            f"[{v_style}]{label}[/{v_style}]",
            f"[{_C_DIM}]{probe.severity}[/{_C_DIM}]",
            f"[white]{control_code}[/white]",
            f"[white]{breach_code}[/white]",
            f"[{_C_DIM}]{baseline_code}[/{_C_DIM}]",
            _short(probe.reason, 44),
        )

    confirmed = sum(1 for probe in results if probe.status == "VALIDATED")
    note = Text(
        f"\n{confirmed} privilege boundary(ies) provably crossed by a live "
        f"session (control succeeded + breach granted + anonymous caller "
        f"denied) and CONFIRMED; a held boundary, a dead control session, or a "
        f"route open to anonymous callers yields no finding.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, note),
        title=f"[{_C_ACCENT}]▐ PRIVILEGE ESCALATION · DETERMINISTIC JUDGE[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _privesc_remediation_panel(outcome) -> Panel:
    """Render the PATCH + PROVE result for one confirmed escalation finding."""

    result = outcome.result
    result_style = {
        "FIX_PROVEN": _C_OK,
        "FIX_FAILED": _C_BAD,
        "NOT_APPLICABLE": _C_DIM,
        "ERROR": _C_BAD,
    }.get(result, _C_WARN)
    badge = {
        "FIX_PROVEN": "✔ FIX PROVEN",
        "FIX_FAILED": "✘ FIX NOT PROVEN",
        "NOT_APPLICABLE": "— NOT APPLICABLE",
        "ERROR": "✘ ERROR",
    }.get(result, result)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row(
        "verdict",
        f"[bold {result_style}]{badge}[/bold {result_style}]",
    )

    plan = outcome.plan
    if plan is not None:
        rule = plan.rule
        table.add_row("strategy", plan.strategy)
        table.add_row(
            "control",
            f"[bold {_C_BAD}]DENY[/bold {_C_BAD}] "
            f"[white]{rule.attacker_name}[/white] "
            f"[{_C_DIM}]({rule.type})[/{_C_DIM}] "
            f"[{_C_DIM}]→[/{_C_DIM}] "
            f"[white]{rule.method} {_short(rule.path, 34)}[/white]",
        )
        table.add_row(
            "keeps alive",
            f"[{_C_DIM}]attacker's own control · "
            f"{plan.control_method} {_short(plan.control_url, 44)}[/{_C_DIM}]",
        )
        table.add_row(
            "upstream",
            f"[{_C_DIM}]{_short(plan.upstream_base, 60)}[/{_C_DIM}]",
        )

    verification = outcome.verification
    if verification is not None:
        before_code = verification.before_status_code
        after_code = verification.observed_status_code
        before_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.before_status, _C_WARN)
        after_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.after_status, _C_WARN)
        table.add_row(
            "live prove",
            f"[{_C_DIM}]before[/{_C_DIM}] "
            f"[white]{before_code if before_code is not None else '—'}[/white] "
            f"[bold {before_style}]{verification.before_status}[/bold {before_style}]"
            f"  [{_C_DIM}]→[/{_C_DIM}]  "
            f"[{_C_DIM}]after[/{_C_DIM}] "
            f"[white]{after_code if after_code is not None else '—'}[/white] "
            f"[bold {after_style}]{verification.after_status}[/bold {after_style}]",
        )

    if outcome.artifacts is not None:
        table.add_row(
            "artifacts",
            f"[{_C_PRIMARY}]portable-json · nginx · caddy · envoy[/{_C_PRIMARY}]",
        )

    blocks = [table]
    if outcome.detail:
        blocks.append(Text(f"\n{_short(outcome.detail, 100)}", style=_C_DIM))

    return Panel(
        Group(*blocks),
        title=f"[{result_style}]▐ PRIVESC REMEDIATION · PATCH + PROVE[/{result_style}]",
        border_style=result_style,
        padding=(1, 2),
    )


def _injection_matrix_panel(policy, source: str, *, synthesized: bool = False) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row("source", f"[{_C_PRIMARY}]{_short(source, 70)}[/{_C_PRIMARY}]")
    table.add_row(
        "injection matrix",
        f"[{_C_ACCENT}]{len(policy.checks)}[/{_C_ACCENT}] "
        + (
            "auto-discovered candidate parameter(s)"
            if synthesized
            else "declared injectable surface(s)"
        ),
    )

    rules = Table.grid(padding=(0, 2))
    rules.add_column(style=_C_DIM)
    for check in policy.checks[:10]:
        sev_style = {
            "CRITICAL": _C_BAD,
            "HIGH": _C_BAD,
            "MEDIUM": _C_WARN,
            "LOW": _C_DIM,
        }.get(check.severity, _C_DIM)
        rules.add_row(
            f"[{sev_style}]{check.severity:<8}[/{sev_style}] "
            f"[white]{check.param}[/white] "
            f"[{_C_DIM}]MUST NOT alter the query ·[/{_C_DIM}] "
            f"[{_C_DIM}]{check.location} · {check.method} "
            f"{_short(check.path, 32)}[/{_C_DIM}]"
        )

    note = Text(
        (
            "\nAuto-discovered candidates — derived from live recon, NOT an "
            "operator oracle. Each is still proven by a THREE-WAY BOOLEAN "
            if synthesized
            else "\nGround truth only. Each surface is proven by a THREE-WAY BOOLEAN "
        )
        + "differential on the live target: a benign BASELINE probe (which must "
        "return a legitimate response — the anchor), plus length-matched "
        "(TRUE, FALSE) payload pairs. Because each pair differs by a single "
        "digit, a reflected payload contributes identical bytes to both arms — "
        "so any TRUE≠FALSE difference can only come from the backend evaluating "
        "the injected boolean. A parameter the backend ignores collapses "
        "(TRUE == FALSE) → DISPROVED. A bare status code is never the verdict.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, Rule(style=_C_DIM), rules, note),
        title=(
            f"[{_C_ACCENT}]▐ SQL-INJECTION · AUTO-DISCOVERED SURFACE[/{_C_ACCENT}]"
            if synthesized
            else f"[{_C_ACCENT}]▐ SQL-INJECTION MATRIX ORACLE[/{_C_ACCENT}]"
        ),
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _injection_findings_panel(results) -> Panel:
    """Render every injection verdict, including the DISPROVED ones."""
    table = Table(
        show_header=True,
        header_style=f"bold {_C_ACCENT}",
        border_style=_C_ACCENT,
        expand=True,
    )
    table.add_column("verdict")
    table.add_column("severity")
    table.add_column("param")
    table.add_column("baseline", justify="right")
    table.add_column("claim")

    for probe in results:
        v_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(probe.status, _C_WARN)
        label = {
            "VALIDATED": "● FINDING",
            "DISPROVED": "○ no injection",
            "INCONCLUSIVE": "· inconclusive",
        }.get(probe.status, probe.status)
        code = (
            probe.baseline_status_code
            if probe.baseline_status_code is not None
            else "—"
        )
        table.add_row(
            f"[{v_style}]{label}[/{v_style}]",
            f"[{_C_DIM}]{probe.severity}[/{_C_DIM}]",
            f"[white]{_short(probe.param, 20)}[/white]",
            f"[{_C_DIM}]{code}[/{_C_DIM}]",
            _short(probe.reason, 46),
        )

    confirmed = sum(1 for probe in results if probe.status == "VALIDATED")
    note = Text(
        f"\n{confirmed} SQL injection(s) reproduced against the live target — a "
        f"length-matched boolean payload provably toggled the backend query "
        f"while one arm reproduced the legitimate baseline — and CONFIRMED; a "
        f"parameter that does not influence the query yields no finding.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, note),
        title=f"[{_C_ACCENT}]▐ SQL INJECTION · DETERMINISTIC JUDGE[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _injection_remediation_panel(outcome) -> Panel:
    """Render the PATCH + PROVE result for one confirmed injection finding."""

    result = outcome.result
    result_style = {
        "FIX_PROVEN": _C_OK,
        "FIX_FAILED": _C_BAD,
        "NOT_APPLICABLE": _C_DIM,
        "ERROR": _C_BAD,
    }.get(result, _C_WARN)
    badge = {
        "FIX_PROVEN": "✔ FIX PROVEN",
        "FIX_FAILED": "✘ FIX NOT PROVEN",
        "NOT_APPLICABLE": "— NOT APPLICABLE",
        "ERROR": "✘ ERROR",
    }.get(result, result)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row(
        "verdict",
        f"[bold {result_style}]{badge}[/bold {result_style}]",
    )

    plan = outcome.plan
    if plan is not None:
        rule = plan.rule
        table.add_row("strategy", plan.strategy)
        table.add_row(
            "control",
            f"[bold {_C_BAD}]REQUEST-GUARD[/bold {_C_BAD}] "
            f"[white]{rule.param}[/white] "
            f"[{_C_DIM}]({rule.location})[/{_C_DIM}] "
            f"[{_C_DIM}]→[/{_C_DIM}] "
            f"[white]{rule.method} {_short(rule.path, 34)}[/white]",
        )
        table.add_row(
            "root cause",
            f"[{_C_DIM}]parameterised (prepared) query in the handler[/{_C_DIM}]",
        )
        table.add_row(
            "upstream",
            f"[{_C_DIM}]{_short(plan.upstream_base, 60)}[/{_C_DIM}]",
        )

    verification = outcome.verification
    if verification is not None:
        before_code = verification.before_status_code
        after_code = verification.observed_status_code
        before_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.before_status, _C_WARN)
        after_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.after_status, _C_WARN)
        table.add_row(
            "live prove",
            f"[{_C_DIM}]before[/{_C_DIM}] "
            f"[white]{before_code if before_code is not None else '—'}[/white] "
            f"[bold {before_style}]{verification.before_status}[/bold {before_style}]"
            f"  [{_C_DIM}]→[/{_C_DIM}]  "
            f"[{_C_DIM}]after[/{_C_DIM}] "
            f"[white]{after_code if after_code is not None else '—'}[/white] "
            f"[bold {after_style}]{verification.after_status}[/bold {after_style}]",
        )

    if outcome.artifacts is not None:
        table.add_row(
            "artifacts",
            f"[{_C_PRIMARY}]portable-json · nginx · modsecurity · caddy"
            f"[/{_C_PRIMARY}]",
        )

    blocks = [table]
    if outcome.detail:
        blocks.append(Text(f"\n{_short(outcome.detail, 100)}", style=_C_DIM))

    return Panel(
        Group(*blocks),
        title=f"[{result_style}]▐ INJECTION REMEDIATION · PATCH + PROVE"
        f"[/{result_style}]",
        border_style=result_style,
        padding=(1, 2),
    )


def _ssti_matrix_panel(policy, source: str, *, synthesized: bool = False) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row("source", f"[{_C_PRIMARY}]{_short(source, 70)}[/{_C_PRIMARY}]")
    table.add_row(
        "ssti matrix",
        f"[{_C_ACCENT}]{len(policy.checks)}[/{_C_ACCENT}] "
        + (
            "auto-discovered candidate parameter(s)"
            if synthesized
            else "declared template surface(s)"
        ),
    )

    rules = Table.grid(padding=(0, 2))
    rules.add_column(style=_C_DIM)
    for check in policy.checks[:10]:
        sev_style = {
            "CRITICAL": _C_BAD,
            "HIGH": _C_BAD,
            "MEDIUM": _C_WARN,
            "LOW": _C_DIM,
        }.get(check.severity, _C_DIM)
        rules.add_row(
            f"[{sev_style}]{check.severity:<8}[/{sev_style}] "
            f"[white]{check.param}[/white] "
            f"[{_C_DIM}]MUST NOT be evaluated ·[/{_C_DIM}] "
            f"[{_C_DIM}]{check.location} · {check.method} "
            f"{_short(check.path, 32)}[/{_C_DIM}]"
        )

    note = Text(
        (
            "\nAuto-discovered candidates — derived from live recon, NOT an "
            "operator oracle. Each is still proven by an ARITHMETIC-EVALUATION "
            if synthesized
            else "\nGround truth only. Each surface is proven by an "
            "ARITHMETIC-EVALUATION "
        )
        + "differential on the live target: a CONTROL probe sends the literal "
        "expression a*b with NO template delimiters (which must merely be "
        "reflected — the anchor), plus payload probes wrapping that same a*b in "
        "each common delimiter ({{…}}, ${…}, #{…}, <%= … %>). SSTI is VALIDATED "
        "only when a payload response renders the COMPUTED PRODUCT while the "
        "literal is gone AND the control proved mere reflection — the product "
        "can only have come from the backend evaluating the template. A "
        "parameter that is only reflected collapses → DISPROVED. A bare status "
        "code is never the verdict.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, Rule(style=_C_DIM), rules, note),
        title=(
            f"[{_C_ACCENT}]▐ SSTI · AUTO-DISCOVERED SURFACE[/{_C_ACCENT}]"
            if synthesized
            else f"[{_C_ACCENT}]▐ SSTI MATRIX ORACLE[/{_C_ACCENT}]"
        ),
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _ssti_findings_panel(results) -> Panel:
    """Render every SSTI verdict, including the DISPROVED ones."""
    table = Table(
        show_header=True,
        header_style=f"bold {_C_ACCENT}",
        border_style=_C_ACCENT,
        expand=True,
    )
    table.add_column("verdict")
    table.add_column("severity")
    table.add_column("param")
    table.add_column("control", justify="right")
    table.add_column("claim")

    for probe in results:
        v_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(probe.status, _C_WARN)
        label = {
            "VALIDATED": "● FINDING",
            "DISPROVED": "○ not evaluated",
            "INCONCLUSIVE": "· inconclusive",
        }.get(probe.status, probe.status)
        code = (
            probe.control_status_code
            if probe.control_status_code is not None
            else "—"
        )
        table.add_row(
            f"[{v_style}]{label}[/{v_style}]",
            f"[{_C_DIM}]{probe.severity}[/{_C_DIM}]",
            f"[white]{_short(probe.param, 20)}[/white]",
            f"[{_C_DIM}]{code}[/{_C_DIM}]",
            _short(probe.reason, 46),
        )

    confirmed = sum(1 for probe in results if probe.status == "VALIDATED")
    note = Text(
        f"\n{confirmed} template injection(s) reproduced against the live "
        f"target — a template-wrapped payload provably rendered the computed "
        f"product while the control merely reflected the literal — and "
        f"CONFIRMED; a parameter the backend only reflects yields no finding.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, note),
        title=f"[{_C_ACCENT}]▐ SSTI · DETERMINISTIC JUDGE[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _ssti_remediation_panel(outcome) -> Panel:
    """Render the PATCH + PROVE result for one confirmed SSTI finding."""

    result = outcome.result
    result_style = {
        "FIX_PROVEN": _C_OK,
        "FIX_FAILED": _C_BAD,
        "NOT_APPLICABLE": _C_DIM,
        "ERROR": _C_BAD,
    }.get(result, _C_WARN)
    badge = {
        "FIX_PROVEN": "✔ FIX PROVEN",
        "FIX_FAILED": "✘ FIX NOT PROVEN",
        "NOT_APPLICABLE": "— NOT APPLICABLE",
        "ERROR": "✘ ERROR",
    }.get(result, result)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row(
        "verdict",
        f"[bold {result_style}]{badge}[/bold {result_style}]",
    )

    plan = outcome.plan
    if plan is not None:
        rule = plan.rule
        table.add_row("strategy", plan.strategy)
        table.add_row(
            "control",
            f"[bold {_C_BAD}]REQUEST-GUARD[/bold {_C_BAD}] "
            f"[white]{rule.param}[/white] "
            f"[{_C_DIM}]({rule.location})[/{_C_DIM}] "
            f"[{_C_DIM}]→[/{_C_DIM}] "
            f"[white]{rule.method} {_short(rule.path, 34)}[/white]",
        )
        table.add_row(
            "root cause",
            f"[{_C_DIM}]render untrusted input as data, never as template "
            f"source[/{_C_DIM}]",
        )
        table.add_row(
            "upstream",
            f"[{_C_DIM}]{_short(plan.upstream_base, 60)}[/{_C_DIM}]",
        )

    verification = outcome.verification
    if verification is not None:
        before_code = verification.before_status_code
        after_code = verification.observed_status_code
        before_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.before_status, _C_WARN)
        after_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.after_status, _C_WARN)
        table.add_row(
            "live prove",
            f"[{_C_DIM}]before[/{_C_DIM}] "
            f"[white]{before_code if before_code is not None else '—'}[/white] "
            f"[bold {before_style}]{verification.before_status}[/bold {before_style}]"
            f"  [{_C_DIM}]→[/{_C_DIM}]  "
            f"[{_C_DIM}]after[/{_C_DIM}] "
            f"[white]{after_code if after_code is not None else '—'}[/white] "
            f"[bold {after_style}]{verification.after_status}[/bold {after_style}]",
        )

    if outcome.artifacts is not None:
        table.add_row(
            "artifacts",
            f"[{_C_PRIMARY}]portable-json · nginx · modsecurity · caddy"
            f"[/{_C_PRIMARY}]",
        )

    blocks = [table]
    if outcome.detail:
        blocks.append(Text(f"\n{_short(outcome.detail, 100)}", style=_C_DIM))

    return Panel(
        Group(*blocks),
        title=f"[{result_style}]▐ SSTI REMEDIATION · PATCH + PROVE"
        f"[/{result_style}]",
        border_style=result_style,
        padding=(1, 2),
    )


def _open_redirect_matrix_panel(
    policy, source: str, *, synthesized: bool = False
) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row("source", f"[{_C_PRIMARY}]{_short(source, 70)}[/{_C_PRIMARY}]")
    table.add_row(
        "redirect matrix",
        f"[{_C_ACCENT}]{len(policy.checks)}[/{_C_ACCENT}] "
        + (
            "auto-discovered candidate parameter(s)"
            if synthesized
            else "declared redirect surface(s)"
        ),
    )

    rules = Table.grid(padding=(0, 2))
    rules.add_column(style=_C_DIM)
    for check in policy.checks[:10]:
        sev_style = {
            "CRITICAL": _C_BAD,
            "HIGH": _C_BAD,
            "MEDIUM": _C_WARN,
            "LOW": _C_DIM,
        }.get(check.severity, _C_DIM)
        rules.add_row(
            f"[{sev_style}]{check.severity:<8}[/{sev_style}] "
            f"[white]{check.param}[/white] "
            f"[{_C_DIM}]MUST NOT redirect off-origin ·[/{_C_DIM}] "
            f"[{_C_DIM}]{check.location} · {check.method} "
            f"{_short(check.path, 32)}[/{_C_DIM}]"
        )

    note = Text(
        (
            "\nAuto-discovered candidates — derived from live recon, NOT an "
            "operator oracle. Each is still proven by a TWO-PROBE HOST "
            if synthesized
            else "\nGround truth only. Each surface is proven by a TWO-PROBE HOST "
        )
        + "differential on the live target: a same-origin CONTROL anchor sets the "
        "parameter to the target's own origin (which a genuine redirector honours "
        "on-origin — the anchor), plus an off-origin PAYLOAD probe setting it to a "
        "URL on a random, unroutable nonce host (sentinel-<nonce>.example). Open "
        "redirect is VALIDATED only when the payload response's Location header "
        "resolves to the NONCE HOST — a host that could only have come from our "
        "parameter value — AND the control anchored on-origin. A parameter that is "
        "ignored, sanitized, or forced on-origin collapses → DISPROVED. The nonce "
        "host is never contacted (no-follow); a bare 3xx is never the verdict.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, Rule(style=_C_DIM), rules, note),
        title=(
            f"[{_C_ACCENT}]▐ OPEN REDIRECT · AUTO-DISCOVERED SURFACE[/{_C_ACCENT}]"
            if synthesized
            else f"[{_C_ACCENT}]▐ OPEN-REDIRECT MATRIX ORACLE[/{_C_ACCENT}]"
        ),
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _open_redirect_findings_panel(results) -> Panel:
    """Render every open-redirect verdict, including the DISPROVED ones."""
    table = Table(
        show_header=True,
        header_style=f"bold {_C_ACCENT}",
        border_style=_C_ACCENT,
        expand=True,
    )
    table.add_column("verdict")
    table.add_column("severity")
    table.add_column("param")
    table.add_column("payload", justify="right")
    table.add_column("claim")

    for probe in results:
        v_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(probe.status, _C_WARN)
        label = {
            "VALIDATED": "● FINDING",
            "DISPROVED": "○ on-origin only",
            "INCONCLUSIVE": "· inconclusive",
        }.get(probe.status, probe.status)
        code = (
            probe.payload_status_code
            if probe.payload_status_code is not None
            else "—"
        )
        table.add_row(
            f"[{v_style}]{label}[/{v_style}]",
            f"[{_C_DIM}]{probe.severity}[/{_C_DIM}]",
            f"[white]{_short(probe.param, 20)}[/white]",
            f"[{_C_DIM}]{code}[/{_C_DIM}]",
            _short(probe.reason, 46),
        )

    confirmed = sum(1 for probe in results if probe.status == "VALIDATED")
    note = Text(
        f"\n{confirmed} open redirect(s) reproduced against the live target — an "
        f"off-origin payload provably redirected to the unforgeable nonce host "
        f"while the same-origin control anchored on-origin — and CONFIRMED; a "
        f"parameter forced on-origin or ignored yields no finding.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, note),
        title=f"[{_C_ACCENT}]▐ OPEN REDIRECT · DETERMINISTIC JUDGE[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _open_redirect_remediation_panel(outcome) -> Panel:
    """Render the PATCH + PROVE result for one confirmed open-redirect finding."""

    result = outcome.result
    result_style = {
        "FIX_PROVEN": _C_OK,
        "FIX_FAILED": _C_BAD,
        "NOT_APPLICABLE": _C_DIM,
        "ERROR": _C_BAD,
    }.get(result, _C_WARN)
    badge = {
        "FIX_PROVEN": "✔ FIX PROVEN",
        "FIX_FAILED": "✘ FIX NOT PROVEN",
        "NOT_APPLICABLE": "— NOT APPLICABLE",
        "ERROR": "✘ ERROR",
    }.get(result, result)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row(
        "verdict",
        f"[bold {result_style}]{badge}[/bold {result_style}]",
    )

    plan = outcome.plan
    if plan is not None:
        rule = plan.rule
        table.add_row("strategy", plan.strategy)
        table.add_row(
            "control",
            f"[bold {_C_BAD}]REQUEST-GUARD[/bold {_C_BAD}] "
            f"[white]{rule.param}[/white] "
            f"[{_C_DIM}]({rule.location})[/{_C_DIM}] "
            f"[{_C_DIM}]→[/{_C_DIM}] "
            f"[white]{rule.method} {_short(rule.path, 34)}[/white]",
        )
        table.add_row(
            "allowlist",
            f"[{_C_DIM}]forward only same-host redirect targets · "
            f"{_short(rule.allow_host, 40)}[/{_C_DIM}]",
        )
        table.add_row(
            "root cause",
            f"[{_C_DIM}]never build a redirect target from raw user input "
            f"(server-side allowlist / relative paths)[/{_C_DIM}]",
        )
        table.add_row(
            "upstream",
            f"[{_C_DIM}]{_short(plan.upstream_base, 60)}[/{_C_DIM}]",
        )

    verification = outcome.verification
    if verification is not None:
        before_code = verification.before_status_code
        after_code = verification.observed_status_code
        before_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.before_status, _C_WARN)
        after_style = {
            "VALIDATED": _C_BAD,
            "DISPROVED": _C_OK,
            "INCONCLUSIVE": _C_DIM,
        }.get(verification.after_status, _C_WARN)
        table.add_row(
            "live prove",
            f"[{_C_DIM}]before[/{_C_DIM}] "
            f"[white]{before_code if before_code is not None else '—'}[/white] "
            f"[bold {before_style}]{verification.before_status}[/bold {before_style}]"
            f"  [{_C_DIM}]→[/{_C_DIM}]  "
            f"[{_C_DIM}]after[/{_C_DIM}] "
            f"[white]{after_code if after_code is not None else '—'}[/white] "
            f"[bold {after_style}]{verification.after_status}[/bold {after_style}]",
        )

    if outcome.artifacts is not None:
        table.add_row(
            "artifacts",
            f"[{_C_PRIMARY}]portable-json · nginx · modsecurity · caddy"
            f"[/{_C_PRIMARY}]",
        )

    blocks = [table]
    if outcome.detail:
        blocks.append(Text(f"\n{_short(outcome.detail, 100)}", style=_C_DIM))

    return Panel(
        Group(*blocks),
        title=f"[{result_style}]▐ OPEN-REDIRECT REMEDIATION · PATCH + PROVE"
        f"[/{result_style}]",
        border_style=result_style,
        padding=(1, 2),
    )


def _parse_args(arg: str) -> tuple[str, int, str | None, str | None]:
    parts = arg.split()
    target = parts[0]
    max_cycles = 10
    policy_path: str | None = None
    source_root: str | None = None
    for token in parts[1:]:
        if token.isdigit():
            max_cycles = max(1, min(100, int(token)))
        elif os.path.isdir(token):
            # An existing directory is the target's source repository,
            # enabling the optional root-cause source patch.
            source_root = token
        else:
            policy_path = token
    if policy_path is None:
        policy_path = os.environ.get("SENTINEL_ACCESS_POLICY") or None
    if source_root is None:
        source_root = os.environ.get("SENTINEL_SOURCE_ROOT") or None
    return target, max_cycles, policy_path, source_root


def run(arg, *, discover_mode=False):
    """
    Run the autonomous research + prove loop against a live target.

    ``discover_mode`` flips Sentinel from an operator-oracle *verifier* into a
    *discoverer* for the one class whose ground truth is internal — SQL
    injection. When set and no operator ``injection_matrix`` is supplied, the
    injectable surface is SYNTHESIZED from live reconnaissance (observed query
    parameters + a fixed, target-agnostic generic-parameter list on query-
    surface endpoints) via
    :func:`app.security_graph.injection.discover.synthesize_injection_policy`,
    and every synthesized candidate is decided by the SAME pure boolean-
    differential judge. No verdict is manufactured: a parameter the backend
    ignores collapses (TRUE == FALSE) → DISPROVED → no finding. The header and
    cookie passes already run zero-config off the secure baseline, so a bare URL
    yields real, proven discovery across three classes.
    """
    if not arg or not arg.strip():
        console.print(
            f"[{_C_BAD}]Usage:[/{_C_BAD}] investigate <target> [cycles] "
            f"[access_policy.json] [source_repo_dir]\n"
            f"[dim]e.g. investigate http://127.0.0.1:3000 12 "
            f"samples/juice_shop_access_policy.json[/dim]\n"
            f"[dim]a policy path may also be set via "
            f"$SENTINEL_ACCESS_POLICY, a source repo via "
            f"$SENTINEL_SOURCE_ROOT[/dim]\n"
            f"[dim]header-posture rules live in a 'header_rules' section of "
            f"the same file, or via $SENTINEL_HEADER_POLICY[/dim]\n"
            f"[dim]insecure-cookie rules live in a 'cookie_rules' section of "
            f"the same file, or via $SENTINEL_COOKIE_POLICY[/dim]\n"
            f"[dim]privilege-escalation (login matrix) lives in a "
            f"'privesc_matrix' section, or via $SENTINEL_PRIVESC_POLICY[/dim]\n"
            f"[dim]sql-injection (boolean differential) lives in an "
            f"'injection_matrix' section, or via $SENTINEL_INJECTION_POLICY[/dim]\n"
            f"[dim]with no policy, header + cookie passes run off a built-in "
            f"secure baseline; set $SENTINEL_NO_BASELINE=1 to disable it[/dim]\n"
            f"[dim]set $SENTINEL_SKIP_REMEDIATION=1 to skip the "
            f"PATCH + PROVE stage[/dim]"
        )
        return

    # Imported lazily so the REPL starts fast and unrelated commands
    # do not pay for the research engine import.
    from app.security_graph.orchestration.target import (
        TargetResearchPipeline,
        evaluate_target_research_outcome,
    )

    target, max_cycles, policy_path, source_root = _parse_args(arg.strip())

    console.print()
    console.print(_banner())

    if discover_mode:
        console.print(
            Panel(
                Text(
                    "DISCOVER MODE — no operator oracle required. Point Sentinel "
                    "at a URL and it derives its own injectable surface from live "
                    "reconnaissance, then proves every candidate with the same "
                    "pure boolean differential. Header + cookie posture already "
                    "run off the built-in secure baseline. Nothing is "
                    "manufactured: an ignored parameter collapses to DISPROVED.",
                    style=_C_DIM,
                ),
                title=f"[bold {_C_ACCENT}]▐ ZERO-ORACLE DISCOVERY[/bold {_C_ACCENT}]",
                border_style=_C_ACCENT,
                padding=(0, 2),
            )
        )

    # policy fails loud rather than silently running without it.
    access_policy = None
    if policy_path:
        from app.security_graph.policy import load_access_policy

        try:
            access_policy = load_access_policy(policy_path)
        except Exception as exc:  # noqa: BLE001 — surface cleanly
            console.print(
                Panel(
                    Text(
                        f"Failed to load access policy "
                        f"'{policy_path}': {exc}",
                        style=_C_BAD,
                    ),
                    title=f"[{_C_BAD}]access policy error[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )
            return

    try:
        with console.status(
            f"[{_C_PRIMARY}]reconnaissance + autonomous research "
            f"({max_cycles} cycle budget)…[/{_C_PRIMARY}]",
            spinner="dots",
        ):
            result = TargetResearchPipeline().run(
                target,
                max_cycles=max_cycles,
                access_policy=access_policy,
            )
    except Exception as exc:  # noqa: BLE001 — surface any failure cleanly
        console.print(
            Panel(
                Text(str(exc), style=_C_BAD),
                title=f"[{_C_BAD}]investigation failed[/{_C_BAD}]",
                border_style=_C_BAD,
            )
        )
        return

    outcome = evaluate_target_research_outcome(result)

    console.print()
    console.print(_recon_panel(result))
    if access_policy is not None:
        console.print(_policy_panel(access_policy, policy_path))
    console.print(_hypotheses_panel(result))

    console.print()
    console.print(
        Rule(
            f"[bold {_C_PRIMARY}]AUTONOMOUS RESEARCH · "
            f"{len(result.cycles)} CYCLE(S)[/bold {_C_PRIMARY}]",
            style=_C_PRIMARY,
        )
    )

    for index, cycle in enumerate(result.cycles, start=1):
        console.print(_cycle_panel(index, cycle))

    console.print()
    console.print(_findings_panel(result))

    # --- PATCH + PROVE ----------------------------------------------------
    # For every CONFIRMED authorization finding, autonomously synthesize a
    # corrective control, enforce it on a live loopback shield, and prove
    # the contradiction no longer reproduces under the same deterministic
    # judge. Opt-out via $SENTINEL_SKIP_REMEDIATION.
    skip_remediation = bool(os.environ.get("SENTINEL_SKIP_REMEDIATION"))
    confirmed = result.graph.findings_for(
        kind="authorization_policy_violation", status="OPEN"
    )
    if confirmed and not skip_remediation:
        console.print()
        console.print(
            Rule(
                f"[bold {_C_OK}]REMEDIATION · PATCH + PROVE · "
                f"{len(confirmed)} FINDING(S)[/bold {_C_OK}]",
                style=_C_OK,
            )
        )
        if source_root:
            console.print(
                Text(
                    f"  source repo provided → root-cause patch enabled "
                    f"({_short(source_root, 60)})",
                    style=_C_DIM,
                )
            )
        try:
            from app.commands.remediation_gate import RemediationProposal
            from app.security_graph.remediation import (
                remediate_confirmed_findings,
                synthesize_remediation,
            )

            # Show the proposed controls and take the operator's approval
            # BEFORE any shield is stood up or any fix is proven.
            proposals = []
            for finding in confirmed:
                plan = synthesize_remediation(result.graph, finding)
                if plan is None:
                    control = "route-level deny (no shieldable plan derived)"
                else:
                    control = (
                        f"deny {plan.rule.principal_name} → "
                        f"{plan.rule.method} {plan.rule.path}"
                    )
                proposals.append(
                    RemediationProposal(
                        title=finding.title,
                        severity=finding.severity,
                        control=control,
                    )
                )

            if not _gate_remediation(
                class_label="authorization",
                color=_C_OK,
                proposals=proposals,
            ):
                raise _Deferred()

            with console.status(
                f"[{_C_OK}]synthesizing controls + proving fixes live…"
                f"[/{_C_OK}]",
                spinner="dots",
            ):
                outcomes = remediate_confirmed_findings(
                    result.graph, source_root=source_root
                )
            for remediation in outcomes:
                console.print(_remediation_panel(remediation))
        except _Deferred:
            pass
        except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
            console.print(
                Panel(
                    Text(str(exc), style=_C_BAD),
                    title=f"[{_C_BAD}]remediation stage failed[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )

    # --- SECURITY MISCONFIGURATION · HEADER POSTURE -----------------------
    # A second, independent vulnerability class: does the target ship the
    # browser-level protections the operator declared? This runs as an
    # isolated pass on the same graph — it never perturbs the authorization
    # decision engine above — and obeys the identical epistemic contract: an
    # oracle declares posture, the live probe observes, a PURE judge decides,
    # and a finding materialises only on a reproduced contradiction. A header
    # policy may live in the same policy file (a `header_rules` section) or
    # be pointed at via $SENTINEL_HEADER_POLICY.
    # Zero-config: when the operator declares no posture, Sentinel falls back
    # to a built-in secure baseline so both browser-facing classes still run.
    # An operator-authored policy always wins; $SENTINEL_NO_BASELINE=1 disables
    # the fallback (operator-only mode).
    baseline_enabled = not os.environ.get("SENTINEL_NO_BASELINE")

    header_policy = None
    header_source = os.environ.get("SENTINEL_HEADER_POLICY") or policy_path
    if header_source:
        from app.security_graph.posture import load_header_policy

        try:
            header_policy = load_header_policy(header_source)
        except Exception as exc:  # noqa: BLE001 — surface cleanly
            console.print(
                Panel(
                    Text(
                        f"Failed to load header policy "
                        f"'{header_source}': {exc}",
                        style=_C_BAD,
                    ),
                    title=f"[{_C_BAD}]header policy error[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )
            header_policy = None

    if (header_policy is None or not header_policy.rules) and baseline_enabled:
        from app.security_graph.baseline import (
            BASELINE_HEADER_SOURCE,
            default_header_policy,
        )

        header_policy = default_header_policy()
        header_source = BASELINE_HEADER_SOURCE

    if header_policy is not None and header_policy.rules:
        console.print()
        console.print(
            Rule(
                f"[bold {_C_ACCENT}]SECURITY MISCONFIGURATION · "
                f"HEADER POSTURE[/bold {_C_ACCENT}]",
                style=_C_ACCENT,
            )
        )
        console.print(_header_policy_panel(header_policy, header_source))
        try:
            from app.security_graph.posture import run_posture_investigation

            with console.status(
                f"[{_C_ACCENT}]probing header posture + judging live…"
                f"[/{_C_ACCENT}]",
                spinner="dots",
            ):
                posture_results = run_posture_investigation(
                    result.graph,
                    header_policy,
                    target_base=result.target,
                )
            if posture_results:
                console.print(_posture_findings_panel(posture_results))

            posture_confirmed = result.graph.findings_for(
                kind="security_misconfiguration", status="OPEN"
            )
            if posture_confirmed and not skip_remediation:
                console.print()
                console.print(
                    Rule(
                        f"[bold {_C_OK}]POSTURE REMEDIATION · PATCH + PROVE · "
                        f"{len(posture_confirmed)} FINDING(S)[/bold {_C_OK}]",
                        style=_C_OK,
                    )
                )
                from app.security_graph.posture import (
                    remediate_header_findings,
                    synthesize_header_remediation,
                )
                from app.commands.remediation_gate import RemediationProposal

                proposals = []
                for finding in posture_confirmed:
                    plan = synthesize_header_remediation(result.graph, finding)
                    if plan is None:
                        control = "response-header correction (no plan derived)"
                    else:
                        detail = plan.rule.value or plan.rule.declared_value
                        control = (
                            f"{plan.rule.op} '{plan.rule.header}'"
                            + (f" = {detail}" if detail else "")
                            + f"  ({plan.rule.method} {plan.rule.path})"
                        )
                    proposals.append(
                        RemediationProposal(
                            title=finding.title,
                            severity=finding.severity,
                            control=control,
                        )
                    )

                if _gate_remediation(
                    class_label="header posture",
                    color=_C_OK,
                    proposals=proposals,
                ):
                    with console.status(
                        f"[{_C_OK}]injecting corrective headers + proving live…"
                        f"[/{_C_OK}]",
                        spinner="dots",
                    ):
                        posture_outcomes = remediate_header_findings(result.graph)
                    for remediation in posture_outcomes:
                        console.print(_posture_remediation_panel(remediation))
        except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
            console.print(
                Panel(
                    Text(str(exc), style=_C_BAD),
                    title=f"[{_C_BAD}]header posture stage failed[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )

    # --- INSECURE COOKIES -------------------------------------------------
    # A third, independent vulnerability class: are the cookies this endpoint
    # issues safe to hold a session in (HttpOnly / Secure / a non-permissive
    # SameSite)? A weak session cookie is the classic pivot for chaining. This
    # runs as an isolated pass on the same graph and obeys the identical
    # epistemic contract: an operator cookie oracle declares posture, the live
    # probe observes the real Set-Cookie, a PURE judge decides, and a finding
    # materialises only on a Set-Cookie the target actually sets contradicting
    # it. The oracle lives in a `cookie_rules` section of the policy file, or
    # via $SENTINEL_COOKIE_POLICY.
    cookie_policy = None
    cookie_source = os.environ.get("SENTINEL_COOKIE_POLICY") or policy_path
    if cookie_source:
        from app.security_graph.cookies import load_cookie_policy

        try:
            cookie_policy = load_cookie_policy(cookie_source)
        except Exception as exc:  # noqa: BLE001 — surface cleanly
            console.print(
                Panel(
                    Text(
                        f"Failed to load cookie policy "
                        f"'{cookie_source}': {exc}",
                        style=_C_BAD,
                    ),
                    title=f"[{_C_BAD}]cookie policy error[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )
            cookie_policy = None

    if (cookie_policy is None or not cookie_policy.rules) and baseline_enabled:
        from app.security_graph.baseline import (
            BASELINE_COOKIE_SOURCE,
            default_cookie_policy,
        )

        cookie_policy = default_cookie_policy()
        cookie_source = BASELINE_COOKIE_SOURCE

    if cookie_policy is not None and cookie_policy.rules:
        console.print()
        console.print(
            Rule(
                f"[bold {_C_ACCENT}]INSECURE COOKIES · "
                f"SESSION SAFETY[/bold {_C_ACCENT}]",
                style=_C_ACCENT,
            )
        )
        console.print(_cookie_policy_panel(cookie_policy, cookie_source))
        try:
            from app.security_graph.cookies import run_cookie_investigation

            with console.status(
                f"[{_C_ACCENT}]probing Set-Cookie + judging live…"
                f"[/{_C_ACCENT}]",
                spinner="dots",
            ):
                cookie_results = run_cookie_investigation(
                    result.graph,
                    cookie_policy,
                    target_base=result.target,
                )
            if cookie_results:
                console.print(_cookie_findings_panel(cookie_results))

            cookie_confirmed = result.graph.findings_for(
                kind="insecure_cookie", status="OPEN"
            )
            if cookie_confirmed and not skip_remediation:
                console.print()
                console.print(
                    Rule(
                        f"[bold {_C_OK}]COOKIE REMEDIATION · PATCH + PROVE · "
                        f"{len(cookie_confirmed)} FINDING(S)[/bold {_C_OK}]",
                        style=_C_OK,
                    )
                )
                from app.security_graph.cookies import (
                    remediate_cookie_findings,
                    synthesize_cookie_remediation,
                )
                from app.commands.remediation_gate import RemediationProposal

                proposals = []
                for finding in cookie_confirmed:
                    plan = synthesize_cookie_remediation(result.graph, finding)
                    if plan is None:
                        control = "Set-Cookie hardening (no plan derived)"
                    else:
                        detail = plan.rule.flag or plan.rule.value
                        name = plan.rule.cookie_name or "every Set-Cookie"
                        control = (
                            f"{plan.rule.op} {detail} on '{name}'  "
                            f"({plan.rule.method} {plan.rule.path})"
                        )
                    proposals.append(
                        RemediationProposal(
                            title=finding.title,
                            severity=finding.severity,
                            control=control,
                        )
                    )

                if _gate_remediation(
                    class_label="insecure cookies",
                    color=_C_OK,
                    proposals=proposals,
                ):
                    with console.status(
                        f"[{_C_OK}]hardening Set-Cookie + proving live…"
                        f"[/{_C_OK}]",
                        spinner="dots",
                    ):
                        cookie_outcomes = remediate_cookie_findings(result.graph)
                    for remediation in cookie_outcomes:
                        console.print(_cookie_remediation_panel(remediation))
        except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
            console.print(
                Panel(
                    Text(str(exc), style=_C_BAD),
                    title=f"[{_C_BAD}]insecure cookie stage failed[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )

    # A fourth, authenticated vulnerability class (Tier 2): privilege
    # escalation via an operator LOGIN MATRIX. Where the classes above reason
    # about an anonymous/declared caller, this asks the question that only
    # becomes reachable once you hold a real session: can one logged-in account
    # cross a privilege boundary it was never granted — reading another user's
    # object (horizontal / IDOR / BOLA) or reaching an elevated function
    # (vertical)? It is a THREE-PROBE differential (control + breach + anonymous
    # baseline) so a bare status code is never the verdict. There is
    # deliberately NO secure-baseline fallback: proving escalation needs real
    # accounts and boundaries only the operator can supply, so an undeclared
    # matrix simply means "skip". The matrix lives in a `privesc_matrix` section
    # of the policy file, or in a dedicated file via $SENTINEL_PRIVESC_POLICY.
    privesc_policy = None
    privesc_source = os.environ.get("SENTINEL_PRIVESC_POLICY") or None
    if privesc_source is None and policy_path:
        # A combined policy file drives this class only if it carries a matrix;
        # otherwise parsing the anonymous access policy as a matrix would fail.
        import json

        try:
            with open(policy_path, encoding="utf-8") as handle:
                combined = json.load(handle)
            if isinstance(combined, dict) and combined.get("privesc_matrix"):
                privesc_source = policy_path
        except Exception:  # noqa: BLE001 — a malformed file is reported elsewhere
            privesc_source = None

    if privesc_source:
        from app.security_graph.privesc import load_privesc_policy

        try:
            privesc_policy = load_privesc_policy(privesc_source)
        except Exception as exc:  # noqa: BLE001 — surface cleanly
            console.print(
                Panel(
                    Text(
                        f"Failed to load privilege-escalation matrix "
                        f"'{privesc_source}': {exc}",
                        style=_C_BAD,
                    ),
                    title=f"[{_C_BAD}]privesc matrix error[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )
            privesc_policy = None

    if privesc_policy is not None and privesc_policy.checks:
        console.print()
        console.print(
            Rule(
                f"[bold {_C_ACCENT}]PRIVILEGE ESCALATION · "
                f"LOGIN MATRIX[/bold {_C_ACCENT}]",
                style=_C_ACCENT,
            )
        )
        console.print(_privesc_matrix_panel(privesc_policy, privesc_source))
        try:
            from app.security_graph.privesc import run_privesc_investigation

            with console.status(
                f"[{_C_ACCENT}]running control+breach differential + "
                f"judging live…[/{_C_ACCENT}]",
                spinner="dots",
            ):
                privesc_results = run_privesc_investigation(
                    result.graph,
                    privesc_policy,
                    target_base=result.target,
                )
            if privesc_results:
                console.print(_privesc_findings_panel(privesc_results))

            privesc_confirmed = result.graph.findings_for(
                kind="privilege_escalation", status="OPEN"
            )
            if privesc_confirmed and not skip_remediation:
                console.print()
                console.print(
                    Rule(
                        f"[bold {_C_OK}]PRIVESC REMEDIATION · PATCH + PROVE · "
                        f"{len(privesc_confirmed)} FINDING(S)[/bold {_C_OK}]",
                        style=_C_OK,
                    )
                )
                from app.security_graph.privesc import (
                    remediate_privesc_findings,
                    synthesize_privesc_remediation,
                )
                from app.commands.remediation_gate import RemediationProposal

                proposals = []
                for finding in privesc_confirmed:
                    plan = synthesize_privesc_remediation(result.graph, finding)
                    if plan is None:
                        control = "deny escalation (no plan derived)"
                    else:
                        control = (
                            f"deny {plan.rule.attacker_name} → "
                            f"{plan.rule.method} {plan.rule.path}  "
                            f"({plan.rule.type})"
                        )
                    proposals.append(
                        RemediationProposal(
                            title=finding.title,
                            severity=finding.severity,
                            control=control,
                        )
                    )

                if _gate_remediation(
                    class_label="privilege escalation",
                    color=_C_OK,
                    proposals=proposals,
                ):
                    with console.status(
                        f"[{_C_OK}]standing up the shield + proving the "
                        f"boundary holds…[/{_C_OK}]",
                        spinner="dots",
                    ):
                        privesc_outcomes = remediate_privesc_findings(
                            result.graph
                        )
                    for remediation in privesc_outcomes:
                        console.print(_privesc_remediation_panel(remediation))
        except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
            console.print(
                Panel(
                    Text(str(exc), style=_C_BAD),
                    title=(
                        f"[{_C_BAD}]privilege escalation stage failed"
                        f"[/{_C_BAD}]"
                    ),
                    border_style=_C_BAD,
                )
            )

    # --- SQL INJECTION (BOOLEAN DIFFERENTIAL) -----------------------------
    # A fifth, server-side vulnerability class (Tier 2): does an
    # attacker-controlled parameter reach the backend query? Where the classes
    # above reason about who may reach a resource and what a response ships,
    # this asks the classic injection question — and answers it with a THREE-WAY
    # BOOLEAN differential (a benign baseline + length-matched TRUE/FALSE payload
    # pairs) so a bare status/error is never the verdict: injection is CONFIRMED
    # only when a length-matched pair makes the response track the injected
    # boolean while one arm still reproduces the legitimate baseline. Like the
    # privesc class there is deliberately NO secure-baseline fallback — proving
    # injection needs a declared injectable surface (endpoint + parameter + a
    # benign value) only the operator can supply, so an undeclared matrix simply
    # means "skip". The matrix lives in an `injection_matrix` section of the
    # policy file, or in a dedicated file via $SENTINEL_INJECTION_POLICY.
    injection_policy = None
    injection_source = os.environ.get("SENTINEL_INJECTION_POLICY") or None
    if injection_source is None and policy_path:
        # A combined policy file drives this class only if it carries a matrix;
        # otherwise parsing the anonymous access policy as an injection matrix
        # would yield an empty (no-check) policy and silently skip anyway.
        import json

        try:
            with open(policy_path, encoding="utf-8") as handle:
                combined = json.load(handle)
            if isinstance(combined, dict) and combined.get("injection_matrix"):
                injection_source = policy_path
        except Exception:  # noqa: BLE001 — a malformed file is reported elsewhere
            injection_source = None

    if injection_source:
        from app.security_graph.injection import load_injection_policy

        try:
            injection_policy = load_injection_policy(injection_source)
        except Exception as exc:  # noqa: BLE001 — surface cleanly
            console.print(
                Panel(
                    Text(
                        f"Failed to load injection matrix "
                        f"'{injection_source}': {exc}",
                        style=_C_BAD,
                    ),
                    title=f"[{_C_BAD}]injection matrix error[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )
            injection_policy = None

    # DISCOVER MODE: with no operator-declared matrix, SYNTHESIZE the injectable
    # surface from live recon. This is honest because injection's ground truth is
    # internal — the boolean differential is self-anchoring, so the operator only
    # ever needed to supply *where to look*, which recon observed for us. Every
    # synthesized candidate is decided by the SAME pure judge below; an ignored
    # parameter collapses to DISPROVED and never becomes a finding.
    injection_synthesized = False
    if (
        discover_mode
        and (injection_policy is None or not injection_policy.checks)
    ):
        from app.security_graph.injection.discover import (
            synthesize_injection_policy,
        )

        discovery = synthesize_injection_policy(result.graph)
        if discovery.policy.checks:
            injection_policy = discovery.policy
            injection_source = f"synthesized · live-recon ({discovery.note})"
            injection_synthesized = True

    if injection_policy is not None and injection_policy.checks:
        console.print()
        console.print(
            Rule(
                f"[bold {_C_ACCENT}]SQL INJECTION · "
                f"BOOLEAN DIFFERENTIAL[/bold {_C_ACCENT}]",
                style=_C_ACCENT,
            )
        )
        console.print(
            _injection_matrix_panel(
                injection_policy,
                injection_source,
                synthesized=injection_synthesized,
            )
        )
        try:
            from app.security_graph.injection import run_injection_investigation

            with console.status(
                f"[{_C_ACCENT}]running baseline + boolean-pair differential + "
                f"judging live…[/{_C_ACCENT}]",
                spinner="dots",
            ):
                injection_results = run_injection_investigation(
                    result.graph,
                    injection_policy,
                    target_base=result.target,
                )
            if injection_results:
                console.print(_injection_findings_panel(injection_results))

            injection_confirmed = result.graph.findings_for(
                kind="injection", status="OPEN"
            )
            if injection_confirmed and not skip_remediation:
                console.print()
                console.print(
                    Rule(
                        f"[bold {_C_OK}]INJECTION REMEDIATION · PATCH + PROVE · "
                        f"{len(injection_confirmed)} FINDING(S)[/bold {_C_OK}]",
                        style=_C_OK,
                    )
                )
                from app.security_graph.injection import (
                    remediate_injection_findings,
                    synthesize_injection_remediation,
                )
                from app.commands.remediation_gate import RemediationProposal

                proposals = []
                for finding in injection_confirmed:
                    plan = synthesize_injection_remediation(result.graph, finding)
                    if plan is None:
                        control = "request-guard virtual patch (no plan derived)"
                    else:
                        control = (
                            f"request-guard {plan.rule.param} "
                            f"({plan.rule.location}) → "
                            f"{plan.rule.method} {plan.rule.path}"
                        )
                    proposals.append(
                        RemediationProposal(
                            title=finding.title,
                            severity=finding.severity,
                            control=control,
                        )
                    )

                if _gate_remediation(
                    class_label="sql injection",
                    color=_C_OK,
                    proposals=proposals,
                ):
                    with console.status(
                        f"[{_C_OK}]standing up the request-guard shield + "
                        f"proving the injection no longer reproduces…[/{_C_OK}]",
                        spinner="dots",
                    ):
                        injection_outcomes = remediate_injection_findings(
                            result.graph
                        )
                    for remediation in injection_outcomes:
                        console.print(_injection_remediation_panel(remediation))
        except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
            console.print(
                Panel(
                    Text(str(exc), style=_C_BAD),
                    title=f"[{_C_BAD}]sql injection stage failed[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )

    # --- SERVER-SIDE TEMPLATE INJECTION (ARITHMETIC-EVALUATION DIFFERENTIAL) ---
    # Sixth class. Like injection, SSTI's ground truth is INTERNAL — the
    # arithmetic-evaluation differential is self-anchoring (a literal a*b control
    # plus template-wrapped payloads), so the operator only ever needed to supply
    # WHERE to look. The matrix lives in an `ssti_matrix` section of the policy
    # file, or in a dedicated file via $SENTINEL_SSTI_POLICY; in discover mode it
    # is synthesized from live recon. The SAME pure judge decides every check.
    ssti_policy = None
    ssti_source = os.environ.get("SENTINEL_SSTI_POLICY") or None
    if ssti_source is None and policy_path:
        import json

        try:
            with open(policy_path, encoding="utf-8") as handle:
                combined = json.load(handle)
            if isinstance(combined, dict) and combined.get("ssti_matrix"):
                ssti_source = policy_path
        except Exception:  # noqa: BLE001 — a malformed file is reported elsewhere
            ssti_source = None

    if ssti_source:
        from app.security_graph.ssti import load_ssti_policy

        try:
            ssti_policy = load_ssti_policy(ssti_source)
        except Exception as exc:  # noqa: BLE001 — surface cleanly
            console.print(
                Panel(
                    Text(
                        f"Failed to load ssti matrix '{ssti_source}': {exc}",
                        style=_C_BAD,
                    ),
                    title=f"[{_C_BAD}]ssti matrix error[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )
            ssti_policy = None

    # DISCOVER MODE: with no operator matrix, SYNTHESIZE the template surface from
    # live recon. Honest because SSTI's ground truth is internal — the operator
    # only ever needed to supply *where to look*, which recon observed for us.
    ssti_synthesized = False
    if discover_mode and (ssti_policy is None or not ssti_policy.checks):
        from app.security_graph.ssti import synthesize_ssti_policy

        ssti_discovery = synthesize_ssti_policy(result.graph)
        if ssti_discovery.policy.checks:
            ssti_policy = ssti_discovery.policy
            ssti_source = f"synthesized · live-recon ({ssti_discovery.note})"
            ssti_synthesized = True

    if ssti_policy is not None and ssti_policy.checks:
        console.print()
        console.print(
            Rule(
                f"[bold {_C_ACCENT}]SERVER-SIDE TEMPLATE INJECTION · "
                f"ARITHMETIC DIFFERENTIAL[/bold {_C_ACCENT}]",
                style=_C_ACCENT,
            )
        )
        console.print(
            _ssti_matrix_panel(
                ssti_policy,
                ssti_source,
                synthesized=ssti_synthesized,
            )
        )
        try:
            from app.security_graph.ssti import run_ssti_investigation

            with console.status(
                f"[{_C_ACCENT}]running control + template-payload differential + "
                f"judging live…[/{_C_ACCENT}]",
                spinner="dots",
            ):
                ssti_results = run_ssti_investigation(
                    result.graph,
                    ssti_policy,
                    target_base=result.target,
                )
            if ssti_results:
                console.print(_ssti_findings_panel(ssti_results))

            ssti_confirmed = result.graph.findings_for(
                kind="template_injection", status="OPEN"
            )
            if ssti_confirmed and not skip_remediation:
                console.print()
                console.print(
                    Rule(
                        f"[bold {_C_OK}]SSTI REMEDIATION · PATCH + PROVE · "
                        f"{len(ssti_confirmed)} FINDING(S)[/bold {_C_OK}]",
                        style=_C_OK,
                    )
                )
                from app.security_graph.ssti import (
                    remediate_ssti_findings,
                    synthesize_ssti_remediation,
                )
                from app.commands.remediation_gate import RemediationProposal

                proposals = []
                for finding in ssti_confirmed:
                    plan = synthesize_ssti_remediation(result.graph, finding)
                    if plan is None:
                        control = "request-guard virtual patch (no plan derived)"
                    else:
                        control = (
                            f"request-guard {plan.rule.param} "
                            f"({plan.rule.location}) → "
                            f"{plan.rule.method} {plan.rule.path}"
                        )
                    proposals.append(
                        RemediationProposal(
                            title=finding.title,
                            severity=finding.severity,
                            control=control,
                        )
                    )

                if _gate_remediation(
                    class_label="template injection",
                    color=_C_OK,
                    proposals=proposals,
                ):
                    with console.status(
                        f"[{_C_OK}]standing up the request-guard shield + "
                        f"proving the template no longer evaluates…[/{_C_OK}]",
                        spinner="dots",
                    ):
                        ssti_outcomes = remediate_ssti_findings(result.graph)
                    for remediation in ssti_outcomes:
                        console.print(_ssti_remediation_panel(remediation))
        except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
            console.print(
                Panel(
                    Text(str(exc), style=_C_BAD),
                    title=f"[{_C_BAD}]ssti stage failed[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )

    # Ninth class. Open redirect's ground truth is a TWO-PROBE HOST differential
    # against the live target — a same-origin control anchor plus an off-origin
    # payload pointing at a random, unroutable nonce host — so the operator only
    # ever needed to supply WHERE to look. The matrix lives in an
    # `open_redirect_matrix` section of the policy file, or in a dedicated file via
    # $SENTINEL_OPEN_REDIRECT_POLICY; in discover mode it is synthesized from live
    # recon. The SAME pure judge decides every check; the nonce host is unforgeable
    # and (no-follow) never contacted.
    open_redirect_policy = None
    open_redirect_source = os.environ.get("SENTINEL_OPEN_REDIRECT_POLICY") or None
    if open_redirect_source is None and policy_path:
        import json

        try:
            with open(policy_path, encoding="utf-8") as handle:
                combined = json.load(handle)
            if isinstance(combined, dict) and combined.get("open_redirect_matrix"):
                open_redirect_source = policy_path
        except Exception:  # noqa: BLE001 — a malformed file is reported elsewhere
            open_redirect_source = None

    if open_redirect_source:
        from app.security_graph.open_redirect import load_open_redirect_policy

        try:
            open_redirect_policy = load_open_redirect_policy(open_redirect_source)
        except Exception as exc:  # noqa: BLE001 — surface cleanly
            console.print(
                Panel(
                    Text(
                        f"Failed to load open-redirect matrix "
                        f"'{open_redirect_source}': {exc}",
                        style=_C_BAD,
                    ),
                    title=f"[{_C_BAD}]open-redirect matrix error[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )
            open_redirect_policy = None

    # DISCOVER MODE: with no operator matrix, SYNTHESIZE the redirect surface from
    # live recon. Honest because open redirect's ground truth is a live differential
    # — the operator only ever needed to supply *where to look*, which recon
    # observed for us; the judge still proves every candidate on the live target.
    open_redirect_synthesized = False
    if discover_mode and (
        open_redirect_policy is None or not open_redirect_policy.checks
    ):
        from app.security_graph.open_redirect import synthesize_open_redirect_policy

        open_redirect_discovery = synthesize_open_redirect_policy(result.graph)
        if open_redirect_discovery.policy.checks:
            open_redirect_policy = open_redirect_discovery.policy
            open_redirect_source = (
                f"synthesized · live-recon ({open_redirect_discovery.note})"
            )
            open_redirect_synthesized = True

    if open_redirect_policy is not None and open_redirect_policy.checks:
        console.print()
        console.print(
            Rule(
                f"[bold {_C_ACCENT}]OPEN REDIRECT · TWO-PROBE HOST "
                f"DIFFERENTIAL[/bold {_C_ACCENT}]",
                style=_C_ACCENT,
            )
        )
        console.print(
            _open_redirect_matrix_panel(
                open_redirect_policy,
                open_redirect_source,
                synthesized=open_redirect_synthesized,
            )
        )
        try:
            from app.security_graph.open_redirect import (
                run_open_redirect_investigation,
            )

            with console.status(
                f"[{_C_ACCENT}]running same-origin control + off-origin nonce "
                f"payload differential + judging live…[/{_C_ACCENT}]",
                spinner="dots",
            ):
                open_redirect_results = run_open_redirect_investigation(
                    result.graph,
                    open_redirect_policy,
                    target_base=result.target,
                )
            if open_redirect_results:
                console.print(
                    _open_redirect_findings_panel(open_redirect_results)
                )

            open_redirect_confirmed = result.graph.findings_for(
                kind="open_redirect", status="OPEN"
            )
            if open_redirect_confirmed and not skip_remediation:
                console.print()
                console.print(
                    Rule(
                        f"[bold {_C_OK}]OPEN-REDIRECT REMEDIATION · PATCH + PROVE · "
                        f"{len(open_redirect_confirmed)} FINDING(S)[/bold {_C_OK}]",
                        style=_C_OK,
                    )
                )
                from app.security_graph.open_redirect import (
                    remediate_open_redirect_findings,
                    synthesize_open_redirect_remediation,
                )
                from app.commands.remediation_gate import RemediationProposal

                proposals = []
                for finding in open_redirect_confirmed:
                    plan = synthesize_open_redirect_remediation(
                        result.graph, finding
                    )
                    if plan is None:
                        control = "request-guard virtual patch (no plan derived)"
                    else:
                        control = (
                            f"request-guard {plan.rule.param} "
                            f"({plan.rule.location}) → allow-host "
                            f"{plan.rule.allow_host}"
                        )
                    proposals.append(
                        RemediationProposal(
                            title=finding.title,
                            severity=finding.severity,
                            control=control,
                        )
                    )

                if _gate_remediation(
                    class_label="open redirect",
                    color=_C_OK,
                    proposals=proposals,
                ):
                    with console.status(
                        f"[{_C_OK}]standing up the url-allowlist request-guard "
                        f"shield + proving the payload no longer reaches the nonce "
                        f"host…[/{_C_OK}]",
                        spinner="dots",
                    ):
                        open_redirect_outcomes = remediate_open_redirect_findings(
                            result.graph
                        )
                    for remediation in open_redirect_outcomes:
                        console.print(
                            _open_redirect_remediation_panel(remediation)
                        )
        except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
            console.print(
                Panel(
                    Text(str(exc), style=_C_BAD),
                    title=f"[{_C_BAD}]open-redirect stage failed[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )

    console.print(_outcome_panel(outcome, result.stopped_reason))
    console.print()
