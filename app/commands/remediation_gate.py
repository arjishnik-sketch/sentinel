"""
Human-in-the-loop remediation gate.

The epistemic contract makes Sentinel honest about *what is wrong*. This module
makes it honest about *what it is about to change*: after findings are
confirmed, the proposed corrective control is shown to the operator and their
explicit approval is taken **before** any enforcement shield is stood up or any
fix is proven.

Nothing here decides a verdict or synthesizes a control — it only renders a
preview of controls the class-specific ``synthesize_*`` functions already
produced (purely), and returns a boolean approval. The PATCH+PROVE step runs
only when this gate returns ``True``.

Interaction model (deliberately safe for CI / capture / tests):

  * ``SENTINEL_ASSUME_YES`` truthy  → auto-approve (headless capture, tests, CI);
  * a non-interactive stdin (no TTY) → **decline** with an actionable note, so
    an unattended run can never hang waiting for input;
  * otherwise prompt ``[y/N]`` (default No); EOF / Ctrl-C → decline.

This coexists with ``SENTINEL_SKIP_REMEDIATION`` (which skips remediation
entirely, before this gate is ever reached).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

_TRUTHY = {"1", "true", "yes", "y", "on"}

# Kept local (not imported from investigate_cmd) so this module has no import
# cycle with the command that imports it.
_C_OK = "bright_green"
_C_DIM = "grey58"
_C_WARN = "yellow"


def _short(text: str, width: int = 60) -> str:
    text = "" if text is None else str(text)
    return text if len(text) <= width else text[: width - 1] + "…"


def assume_yes() -> bool:
    """True when the operator pre-authorized deployment for this run."""
    return (os.environ.get("SENTINEL_ASSUME_YES") or "").strip().lower() in _TRUTHY


@dataclass(frozen=True)
class RemediationProposal:
    """One row in the approval preview — a fix that is NOT yet deployed."""

    title: str
    severity: str
    control: str


def proposed_remediation_panel(
    *,
    class_label: str,
    color: str,
    proposals: list[RemediationProposal],
    artifact_formats: tuple[str, ...] = ("portable-json", "nginx", "caddy", "envoy"),
) -> Panel:
    """
    Render the corrective controls the operator is being asked to approve.

    This is a *preview*: no shield has been stood up and no fix has been
    proven yet. The deployable artifacts are ready regardless of the answer.
    """
    table = Table(
        show_header=True,
        header_style=f"bold {color}",
        border_style=color,
        expand=True,
    )
    table.add_column("#", justify="right", style=_C_DIM, width=3)
    table.add_column("finding")
    table.add_column("sev", justify="center", width=8)
    table.add_column("proposed corrective control")

    for index, proposal in enumerate(proposals, start=1):
        sev = (proposal.severity or "").upper()
        sev_style = {
            "HIGH": "bright_red",
            "MEDIUM": _C_WARN,
            "LOW": _C_DIM,
        }.get(sev, _C_DIM)
        table.add_row(
            str(index),
            _short(proposal.title, 46),
            f"[{sev_style}]{sev or '—'}[/{sev_style}]",
            _short(proposal.control, 58),
        )

    note = Text.assemble(
        (
            "\nNothing above has been deployed. On approval, Sentinel stands up "
            "an ephemeral loopback enforcement shield and re-runs the "
            "deterministic judge to PROVE each fix (VALIDATED → DISPROVED). ",
            _C_DIM,
        ),
        (
            "Deployable artifacts (" + " · ".join(artifact_formats) + ") are "
            "ready to apply to your own infrastructure regardless of your choice.",
            _C_DIM,
        ),
    )

    return Panel(
        Group(table, note),
        title=f"[{color}]▐ PROPOSED REMEDIATION · AWAITING APPROVAL · {class_label}[/{color}]",
        border_style=color,
        padding=(1, 2),
    )


def deferred_panel(*, class_label: str, reason: str, color: str = _C_WARN) -> Panel:
    """Rendered when the operator declines (or a non-TTY run auto-declines)."""
    body = Text.assemble(
        (f"Deployment deferred for {class_label} — {reason}.\n\n", color),
        (
            "No enforcement shield was stood up and no fix was proven. The "
            "confirmed findings and their deployable remediation artifacts "
            "remain available above for you to apply and verify yourself.",
            _C_DIM,
        ),
    )
    return Panel(
        body,
        title=f"[{color}]▐ REMEDIATION DEFERRED · {class_label}[/{color}]",
        border_style=color,
        padding=(1, 2),
    )


def confirm_deploy(
    console,
    *,
    class_label: str,
    count: int,
    color: str = _C_OK,
) -> tuple[bool, str]:
    """
    Take the operator's approval before deploying + proving a class's fixes.

    Returns ``(approved, reason)``. Never raises on interrupt/EOF — those are
    treated as an explicit decline so the run continues cleanly.
    """
    if assume_yes():
        return True, "auto-approved via SENTINEL_ASSUME_YES"

    stdin = getattr(sys, "stdin", None)
    is_tty = bool(stdin is not None and getattr(stdin, "isatty", lambda: False)())
    if not is_tty:
        return (
            False,
            "non-interactive session (set SENTINEL_ASSUME_YES=1 to auto-approve "
            "deployment)",
        )

    prompt = (
        f"[{color}]Deploy + prove {count} fix(es) for {class_label}? "
        f"[y/N] › [/{color}]"
    )
    try:
        answer = console.input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False, "cancelled by operator"

    if answer in ("y", "yes"):
        return True, "approved by operator"
    return False, "declined by operator"
