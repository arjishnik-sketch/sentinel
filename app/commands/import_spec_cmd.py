"""
`import-spec <openapi.json|swagger.yaml> [out.json]` — translate an API
description into a CANDIDATE Sentinel policy the operator reviews and confirms.

The importer reads only the spec's explicitly DECLARED authorization intent
(each operation's `security` requirement) and attaches Sentinel's built-in
secure header + cookie baseline. It decides no security question of its own:
every emitted rule is a candidate, and Sentinel still only reports a finding
when a live probe contradicts a rule the operator keeps.
"""

import json
import os

from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()

_C_PRIMARY = "bright_cyan"
_C_ACCENT = "bright_magenta"
_C_OK = "bright_green"
_C_WARN = "yellow"
_C_BAD = "bright_red"
_C_DIM = "grey58"


def _default_out(spec_path: str) -> str:
    base = os.path.basename(spec_path)
    stem = os.path.splitext(base)[0] or "spec"
    return f"{stem}.sentinel.candidate.json"


def _summary_panel(summary, spec_path: str, out_path: str) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row("spec", f"[{_C_PRIMARY}]{spec_path}[/{_C_PRIMARY}]")
    table.add_row("format", summary.spec_kind)
    if summary.base_path:
        table.add_row("base path", summary.base_path)
    table.add_row("operations", str(summary.total_operations))
    table.add_row(
        "deny candidates",
        f"[{_C_BAD}]{summary.deny_candidates}[/{_C_BAD}] "
        f"[{_C_DIM}](spec declares auth required)[/{_C_DIM}]",
    )
    table.add_row(
        "allow candidates",
        f"[{_C_OK}]{summary.allow_candidates}[/{_C_OK}] "
        f"[{_C_DIM}](spec declares public)[/{_C_DIM}]",
    )
    table.add_row(
        "silent (skipped)",
        f"[{_C_DIM}]{summary.silent_operations} "
        f"(no declaration — never guessed)[/{_C_DIM}]",
    )
    table.add_row(
        "secure baseline",
        f"[{_C_ACCENT}]{summary.header_expectations}[/{_C_ACCENT}] header + "
        f"[{_C_ACCENT}]{summary.cookie_expectations}[/{_C_ACCENT}] cookie "
        f"expectation(s)",
    )
    table.add_row("written", f"[{_C_OK}]{out_path}[/{_C_OK}]")

    note = Text(
        "\nCANDIDATE only. These rules translate the spec's declared intent — "
        "they are NOT findings and NOT confirmed. Review them, delete any you "
        "disagree with, then run:\n",
        style=_C_DIM,
    )
    cmd = Text(f"  investigate <target> {out_path}\n", style=_C_PRIMARY)
    tail = Text(
        "Sentinel re-probes the live target and only CONFIRMS a finding when "
        "observed behaviour contradicts a rule you kept.",
        style=_C_DIM,
    )

    return Panel(
        Group(table, note, cmd, tail),
        title=f"[{_C_ACCENT}]▐ SPEC IMPORT · CANDIDATE POLICY[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def run(arg):
    parts = (arg or "").split()
    if not parts:
        console.print(
            f"[{_C_BAD}]Usage:[/{_C_BAD}] import-spec "
            f"<openapi.json|swagger.yaml> [out.json]\n"
            f"[dim]e.g. import-spec samples/petstore.openapi.json[/dim]\n"
            f"[dim]reads the spec's declared `security` intent → a CANDIDATE "
            f"combined policy (authz + secure baseline) for you to confirm"
            f"[/dim]"
        )
        return

    spec_path = parts[0]
    out_path = parts[1] if len(parts) > 1 else _default_out(spec_path)

    from app.security_graph.spec_import import import_spec_file

    try:
        document, summary = import_spec_file(spec_path)
    except FileNotFoundError:
        console.print(
            Panel(
                Text(f"No such spec file: '{spec_path}'", style=_C_BAD),
                title=f"[{_C_BAD}]spec import error[/{_C_BAD}]",
                border_style=_C_BAD,
            )
        )
        return
    except Exception as exc:  # noqa: BLE001 — surface cleanly
        console.print(
            Panel(
                Text(str(exc), style=_C_BAD),
                title=f"[{_C_BAD}]spec import error[/{_C_BAD}]",
                border_style=_C_BAD,
            )
        )
        return

    try:
        with open(out_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
    except OSError as exc:
        console.print(
            Panel(
                Text(f"Could not write '{out_path}': {exc}", style=_C_BAD),
                title=f"[{_C_BAD}]spec import error[/{_C_BAD}]",
                border_style=_C_BAD,
            )
        )
        return

    console.print()
    console.print(
        Rule(
            f"[bold {_C_ACCENT}]OPENAPI / SWAGGER → CANDIDATE POLICY"
            f"[/bold {_C_ACCENT}]",
            style=_C_ACCENT,
        )
    )
    console.print(_summary_panel(summary, spec_path, out_path))
    if "rules" not in document:
        console.print(
            Text(
                "  note: the spec declared no authorization intent, so the "
                "candidate carries only the secure header/cookie baseline.",
                style=_C_WARN,
            )
        )
    console.print()
