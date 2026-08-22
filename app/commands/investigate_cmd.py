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


def _banner() -> Panel:
    art = Text()
    art.append("SENTINEL", style=f"bold {_C_PRIMARY}")
    art.append("  //  ", style=_C_DIM)
    art.append("AUTONOMOUS AUTHORIZATION RESEARCH", style=f"bold {_C_ACCENT}")
    art.append("\n")
    art.append(
        "find → reason → prove   ·   evidence-driven   ·   advisory-AI bounded",
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


def _parse_args(arg: str) -> tuple[str, int, str | None]:
    parts = arg.split()
    target = parts[0]
    max_cycles = 10
    policy_path: str | None = None
    for token in parts[1:]:
        if token.isdigit():
            max_cycles = max(1, min(100, int(token)))
        else:
            policy_path = token
    if policy_path is None:
        policy_path = os.environ.get("SENTINEL_ACCESS_POLICY") or None
    return target, max_cycles, policy_path


def run(arg):
    if not arg or not arg.strip():
        console.print(
            f"[{_C_BAD}]Usage:[/{_C_BAD}] investigate <target> [cycles] "
            f"[access_policy.json]\n"
            f"[dim]e.g. investigate http://127.0.0.1:3000 12 "
            f"samples/juice_shop_access_policy.json[/dim]\n"
            f"[dim]a policy path may also be set via "
            f"$SENTINEL_ACCESS_POLICY[/dim]"
        )
        return

    # Imported lazily so the REPL starts fast and unrelated commands
    # do not pay for the research engine import.
    from app.security_graph.orchestration.target import (
        TargetResearchPipeline,
        evaluate_target_research_outcome,
    )

    target, max_cycles, policy_path = _parse_args(arg.strip())

    console.print()
    console.print(_banner())

    # Load the operator-supplied access-policy oracle, if any. A bad
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
    console.print(_outcome_panel(outcome, result.stopped_reason))
    console.print()
