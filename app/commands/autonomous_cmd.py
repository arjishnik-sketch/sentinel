"""`autonomous <target>` — Sentinel's dynamic, tool-wielding autonomous pentester.

This is the fusion brain. One URL in, and Sentinel runs the whole loop itself:

    DISCOVER   live recon (subfinder/httpx/katana, builtin-crawler fallback)
    SELECT ENDPOINTS  rank the surface by injectability; prune only if a budget is
               set ($SENTINEL_ENDPOINT_BUDGET) — otherwise full coverage, reordered
    UNDERSTAND rank the 817-skill KB against the observed surface (breadth hints)
    HYPOTHESIZE qwen proposes techniques-at-places; a deterministic rule floor
               guarantees coverage even with the LLM entirely off
    NOMINATE   opt-in proof-assist tools (sqlmap…) run as PROPOSERS and widen the
               plan with source="tool" hypotheses (OFF unless $SENTINEL_ENABLE_TOOLS)
    PLAN EXECUTION  derive the execution shape (judge/lead assignment, concurrency,
               retry-round budget, in-scope tools) — annotation + knobs, never a gate
    EXECUTE    adjudicate every hypothesis CONCURRENTLY, then REFINE: a
               non-terminal (INCONCLUSIVE/ERROR) verdict is diagnosed and re-posed
               with a different probe shape and re-judged (bounded, deterministic);
               optional session-aware stage (cookie bisection + param mutation)
    PROVE      pure differential judges dispose — VALIDATED becomes CONFIRMED
    PATCH+PROVE synthesize a corrective control, take the operator's approval,
               stand up a live loopback shield, and re-run the SAME judge to
               prove the contradiction no longer reproduces (VALIDATED→DISPROVED)
    REPORT     assemble the proof-carrying deliverable (markdown + json) from the
               proven graph + remediation outcomes; an optional advisory LLM
               exec-summary garnishes it but contributes no fact

EXECUTE is a bounded adaptive loop (see app.autonomous.refine): a wrong probe
shape gets one or more re-tries, but a variant only supersedes its slot when it
ranks strictly higher, so counts never inflate. The NOMINATE stage is opt-in and
approval-gated (see app.tools.nominate): a tool never confirms — its nomination
is a LEAD until the SAME pure judge reproduces it.

Epistemic contract, preserved end-to-end: the LLM and tools only ever PROPOSE; a
pure judge DISPOSES. A CONFIRMED finding is never a bare status — it is a
reproduced differential. FIX_PROVEN is the same judge flipping under enforcement.
Nothing is deployed before the human deploy gate approves it. Non-differential or
un-wired techniques are surfaced as honest LEADs, never dressed up as confirmed.

The heavy edges (recon, live judges, the KB) are injectable seams so the whole
command is exercised offline in tests with zero network / Ollama / tools.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from rich.console import Group
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from app.autonomous import judges as J
from app.autonomous import orchestrator as O
from app.autonomous import report as R

console = Console()

# Cyber palette — consistent with `investigate`/`discover`.
_C_PRIMARY = "bright_cyan"
_C_ACCENT = "bright_magenta"
_C_OK = "bright_green"
_C_WARN = "yellow"
_C_BAD = "bright_red"
_C_DIM = "grey58"
_C_LEAD = "bright_blue"

_TRUTHY = {"1", "true", "yes", "y", "on"}


def _short(text, width: int = 64) -> str:
    text = " ".join(str(text if text is not None else "").split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _truthy_env(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in _TRUTHY


def _refine_rounds() -> int:
    """Total EXECUTE passes: 1 = single forward pass, ≥2 enables the
    failure-cause + retry loop. Tunable via $SENTINEL_REFINE_ROUNDS (default 2)."""
    raw = (os.environ.get("SENTINEL_REFINE_ROUNDS") or "").strip()
    try:
        return max(1, int(raw)) if raw else 2
    except ValueError:
        return 2


def _positive_env(name: str):
    """Read a positive-int env knob, or ``None`` when unset / ≤0 / malformed."""
    raw = (os.environ.get(name) or "").strip()
    try:
        n = int(raw) if raw else 0
    except ValueError:
        return None
    return n if n > 0 else None


def _endpoint_budget():
    """Optional keep-count for Stage 2 SELECT ENDPOINTS. Unset/≤0 → rank-only (full
    coverage). $SENTINEL_ENDPOINT_BUDGET focuses proof budget on the top-N most
    injectable endpoints — an explicit, recorded prune, never a silent one."""
    return _positive_env("SENTINEL_ENDPOINT_BUDGET")


def _worker_budget():
    """Optional concurrency ceiling for EXECUTE (Stage 5 PLAN EXECUTION). Unset/≤0 →
    the built-in cap. $SENTINEL_MAX_WORKERS lets an operator be gentler on a fragile
    target; it caps parallelism only, never coverage."""
    return _positive_env("SENTINEL_MAX_WORKERS")


# ---- NOMINATE stage (opt-in) — proof-assist tools widen the plan ------------
# "tool-wielding" made real: with $SENTINEL_ENABLE_TOOLS set, curated proof-assist
# tools (sqlmap first) run as NOMINATORS. Their output becomes source="tool"
# hypotheses folded into the plan — the SAME pure judge then disposes each. OFF by
# default: a normal run executes no external exploitation tool. Install stays
# approval-gated; auto-install only with $SENTINEL_ASSUME_YES (headless-safe).

def _approve_install(tool, recipe):
    """Approve a tool auto-install only under an explicit pre-approval. Never
    installs silently: without $SENTINEL_ASSUME_YES the install is declined and
    the tool is simply skipped (a pre-installed tool still runs)."""
    approved = _truthy_env("SENTINEL_ASSUME_YES")
    console.print(Text(
        f"tool install {'approved' if approved else 'declined'}: "
        f"{getattr(recipe, 'display', tool)}",
        style=_C_DIM if approved else _C_WARN))
    return approved


def _nominate_panel(extra) -> Panel:
    table = Table(show_header=True, header_style=f"bold {_C_ACCENT}",
                  border_style=_C_ACCENT, expand=True)
    table.add_column("technique")
    table.add_column("where")
    table.add_column("param")
    table.add_column("nomination", ratio=2, style=_C_DIM)
    for h in extra[:12]:
        table.add_row(_short(h.technique, 18), _short(h.url, 40),
                      _short(h.param or "—", 14), _short(h.rationale, 48))
    note = Text(
        f"\n{len(extra)} tool nomination(s) folded into the plan. A tool only "
        "PROPOSES — every nomination is a LEAD until the SAME pure differential "
        "judge reproduces it. sqlmap/dalfox never confirm.",
        style=_C_DIM,
    )
    return Panel(
        Group(table, note),
        title=f"[{_C_ACCENT}]▐ NOMINATE · {len(extra)} TOOL PROPOSAL(S)[/{_C_ACCENT}]",
        border_style=_C_ACCENT, padding=(1, 2),
    )


def _nominate_stage(plan, *, nominate=None):
    """Run the opt-in proof-assist nominators and augment the plan with their
    proposals. Returns the (possibly-augmented) plan. Never raises: a tool hiccup
    degrades to the un-augmented plan."""
    if nominate is None:
        from app.tools.nominate import nominate as _nom
        nominate = _nom
    try:
        extra = nominate(plan, approve=_approve_install)
    except Exception:  # the nominator is best-effort; never sink the run
        extra = []
    if not extra:
        return plan
    console.print()
    console.print(Rule(f"[bold {_C_ACCENT}]NOMINATE (tools propose)[/bold {_C_ACCENT}]",
                       style=_C_ACCENT))
    augmented = O.augment_plan(plan, extra)
    console.print(_nominate_panel(extra))
    return augmented


# ---- PATCH→PROVE registry: technique → how to remediate its CONFIRMED class --
# Each CONFIRMED verdict carries the graph its pure judge proved on (see
# judges.JudgeEvidence), which already holds the OPEN finding — so we remediate +
# re-prove on THAT graph, never re-opening a socket. Control-line recipes mirror
# the ones the `discover`/`investigate` renderer uses verbatim, per class shape.

def _ctl_request_guard(plan) -> str:
    rule = plan.rule
    return f"request-guard {rule.param} ({rule.location}) → {rule.method} {rule.path}"


def _ctl_open_redirect(plan) -> str:
    rule = plan.rule
    return f"request-guard {rule.param} ({rule.location}) → allow-host {rule.allow_host}"


def _ctl_cors(plan) -> str:
    rule = plan.rule
    return f"strip ACAO/ACAC on {rule.method} {rule.path}"


def _ctl_ssrf(plan) -> str:
    rule = plan.rule
    return f"deny off-allowlist fetch on {rule.method} {rule.path} ?{rule.param}"


@dataclass(frozen=True)
class _RemSpec:
    kind: str                    # SecurityFinding.kind for findings_for(...)
    label: str                   # human class label for the deploy gate
    synth: Callable              # synthesize_<class>_remediation(graph, finding)
    remediate: Callable          # remediate_<class>_findings(graph) -> [outcome]
    control: Callable            # (plan) -> one-line control string
    fallback_control: str        # shown when synth returns None


def _load_registry() -> dict:
    """Lazily import the seven per-class remediation entrypoints. Keyed by the
    Hypothesis.technique the wired judges use, so a CONFIRMED verdict maps
    straight to its patch+prove path. Imported lazily to keep CLI start-up light
    and avoid any import cycle with the security_graph packages."""
    from app.security_graph.injection.remediation import (
        remediate_injection_findings, synthesize_injection_remediation)
    from app.security_graph.xss.remediation import (
        remediate_xss_findings, synthesize_xss_remediation)
    from app.security_graph.path_traversal.remediation import (
        remediate_path_traversal_findings, synthesize_path_traversal_remediation)
    from app.security_graph.ssti.remediation import (
        remediate_ssti_findings, synthesize_ssti_remediation)
    from app.security_graph.open_redirect.remediation import (
        remediate_open_redirect_findings, synthesize_open_redirect_remediation)
    from app.security_graph.cors.remediation import (
        remediate_cors_findings, synthesize_cors_remediation)
    from app.security_graph.ssrf.remediation import (
        remediate_ssrf_findings, synthesize_ssrf_remediation)

    guard_fallback = "request-guard virtual patch (no plan derived)"
    return {
        "sql_injection": _RemSpec(
            "injection", "sql injection", synthesize_injection_remediation,
            remediate_injection_findings, _ctl_request_guard, guard_fallback),
        "xss": _RemSpec(
            "reflected xss", "xss", synthesize_xss_remediation,
            remediate_xss_findings, _ctl_request_guard, guard_fallback),
        "path_traversal": _RemSpec(
            "path_traversal", "path traversal", synthesize_path_traversal_remediation,
            remediate_path_traversal_findings, _ctl_request_guard, guard_fallback),
        "ssti": _RemSpec(
            "template_injection", "template injection", synthesize_ssti_remediation,
            remediate_ssti_findings, _ctl_request_guard, guard_fallback),
        "open_redirect": _RemSpec(
            "open_redirect", "open redirect", synthesize_open_redirect_remediation,
            remediate_open_redirect_findings, _ctl_open_redirect,
            "request-guard allow-host (no plan derived)"),
        "cors": _RemSpec(
            "cors_misconfig", "cors", synthesize_cors_remediation,
            remediate_cors_findings, _ctl_cors,
            "strip ACAO/ACAC response-rewrite (no plan derived)"),
        "ssrf": _RemSpec(
            "ssrf", "ssrf", synthesize_ssrf_remediation,
            remediate_ssrf_findings, _ctl_ssrf,
            "egress allowlist guard (no plan derived)"),
    }


# ---- DISCOVER seam ----------------------------------------------------------

def _live_recon(target: str):
    """Run the real recon toolchain and derive the orchestrator's recon/findings
    dicts. ReconEngine already falls back to a dependency-free crawler when the
    external binaries are absent, so this works on any host with no provisioning.

    ReconEngine.normalize() reduces the target to its scheme://host origin before
    crawling, so an operator-supplied deep URL — its path and, crucially, its
    query params — would otherwise be silently dropped. We honor it: the exact URL
    the operator pointed us at IS a discovered surface, and its query parameters
    are first-class injectable inputs. This is fully generic (any target with a
    path/query benefits), not target-specific, and it is what lets Sentinel test a
    param on an SPA whose root crawl reveals nothing on its own."""
    from urllib.parse import urlsplit
    from app.recon_engine import ReconEngine

    engine = ReconEngine()
    recon = engine.run_pipeline(target)

    seed = (target or "").strip()
    if seed and "://" not in seed:
        seed = "http://" + seed
    parts = urlsplit(seed) if seed else None
    if parts is not None and (parts.query or (parts.path and parts.path != "/")):
        crawl = list(recon.get("crawl") or [])
        if seed not in crawl:
            crawl.insert(0, seed)
            recon["crawl"] = crawl

    findings = engine.extract(recon)
    return recon, findings


# ---- deploy gate (inlined; no dependency on the 4k-line investigate module) --

def _gate(class_label: str, proposals) -> bool:
    """Show the proposed corrective controls and take the operator's approval
    BEFORE any shield is stood up. Reuses the shared, CI-safe gate."""
    from app.commands.remediation_gate import (
        confirm_deploy, deferred_panel, proposed_remediation_panel)

    console.print(proposed_remediation_panel(
        class_label=class_label, color=_C_OK, proposals=proposals))
    approved, reason = confirm_deploy(
        console, class_label=class_label, count=len(proposals), color=_C_OK)
    if not approved:
        console.print(deferred_panel(class_label=class_label, reason=reason))
    return approved


# ---- reasoning boards -------------------------------------------------------

def _banner(target: str) -> Panel:
    art = Text()
    art.append("SENTINEL", style=f"bold {_C_PRIMARY}")
    art.append("  //  ", style=_C_DIM)
    art.append("AUTONOMOUS PENTEST", style=f"bold {_C_ACCENT}")
    art.append("\n")
    art.append(
        "discover → understand → hypothesize → prove → patch → prove   ·   "
        "LLM/tools propose · a pure judge disposes",
        style=_C_DIM,
    )
    art.append(f"\ntarget  {target}", style=_C_PRIMARY)
    return Panel(art, border_style=_C_PRIMARY, padding=(0, 2))


def _surface_panel(surface, recon) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=_C_DIM, justify="right")
    grid.add_column(style="white")

    flags = []
    for label, on in (
        ("login", surface.has_login), ("graphql", surface.has_graphql),
        ("swagger", surface.has_swagger), ("uploads", surface.has_uploads),
        ("spa", surface.is_spa),
    ):
        if on:
            flags.append(label)

    grid.add_row("host", f"[{_C_PRIMARY}]{surface.host or '—'}[/{_C_PRIMARY}]")
    grid.add_row("recon source", str(recon.get("source", "external_toolchain")))
    grid.add_row("surface URLs", str(len(recon.get("crawl", []) or [])))
    grid.add_row("endpoints", str(len(surface.endpoints)))
    grid.add_row("parameters", str(len(surface.params)))
    grid.add_row("tech", ", ".join(surface.techs) if surface.techs else "—")
    grid.add_row("signals", "  ".join(flags) if flags else "—")

    return Panel(
        grid, title=f"[{_C_OK}]▐ SURFACE[/{_C_OK}]",
        border_style=_C_OK, padding=(1, 2),
    )


def _endpoints_panel(selection) -> Panel:
    """Stage 2 — the injectability ranking (and, if budgeted, what was pruned)."""
    table = Table(show_header=True, header_style=f"bold {_C_OK}",
                  border_style=_C_OK, expand=True)
    table.add_column("#", width=3, justify="right", style=_C_DIM)
    table.add_column("score", width=5, justify="right")
    table.add_column("endpoint", ratio=3)
    table.add_column("loc", width=6, style=_C_DIM)
    table.add_column("why it ranks", ratio=3, style=_C_DIM)
    kept = selection.kept
    for i, s in enumerate(kept[:15], start=1):
        ep = s.endpoint
        table.add_row(str(i), str(s.score),
                      _short(getattr(ep, "url", ""), 46),
                      _short(getattr(ep, "location", "query"), 6),
                      _short(", ".join(s.reasons) or "—", 44))
    if selection.pruned:
        note = Text(
            f"\nranked {selection.total} endpoint(s); kept {len(kept)}, pruned "
            f"{len(selection.dropped)} to the budget. Pruning focuses proof "
            "budget — explicit + recorded here, never silent.",
            style=_C_DIM)
    else:
        note = Text(
            f"\nranked {selection.total} endpoint(s); full coverage (no budget). "
            "Ranking only reorders which probes are posed first.",
            style=_C_DIM)
    return Panel(
        Group(table, note),
        title=f"[{_C_OK}]▐ SELECT ENDPOINTS · {len(kept)}/{selection.total}[/{_C_OK}]",
        border_style=_C_OK, padding=(1, 2),
    )


def _execplan_panel(execplan) -> Panel:
    """Stage 5 — the concrete execution shape: slots, concurrency, rounds, tools."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=_C_DIM, justify="right")
    grid.add_column(style="white")
    grid.add_row("work slots", str(len(execplan.slots)))
    grid.add_row("→ judged",
                 f"[{_C_OK}]{len(execplan.judged)}[/{_C_OK}]  "
                 f"[{_C_DIM}]{', '.join(execplan.techniques) or '—'}[/{_C_DIM}]")
    grid.add_row("→ leads",
                 f"[{_C_LEAD}]{len(execplan.leads) + len(execplan.unwired_leads)}"
                 f"[/{_C_LEAD}]  "
                 f"[{_C_DIM}]{len(execplan.unwired_leads)} provable-but-unwired"
                 f"[/{_C_DIM}]")
    grid.add_row("concurrency", f"{execplan.max_workers} worker(s)")
    grid.add_row("retry rounds", str(execplan.max_rounds))
    if execplan.tools_enabled:
        grid.add_row("proof-assist tools",
                     f"[{_C_ACCENT}]{', '.join(execplan.tools) or '—'}[/{_C_ACCENT}]")
    else:
        grid.add_row("proof-assist tools",
                     f"[{_C_DIM}]disabled ($SENTINEL_ENABLE_TOOLS off)[/{_C_DIM}]")
    note = Text(
        "\nExecution shape only — every hypothesis keeps its slot. Concurrency and "
        "rounds are knobs, not gates; the pure judges still dispose each probe.",
        style=_C_DIM,
    )
    return Panel(
        Group(grid, note),
        title=f"[{_C_PRIMARY}]▐ PLAN EXECUTION[/{_C_PRIMARY}]",
        border_style=_C_PRIMARY, padding=(1, 2),
    )


def _skills_panel(skills) -> Panel:
    table = Table(show_header=True, header_style=f"bold {_C_ACCENT}",
                  border_style=_C_ACCENT, expand=True)
    table.add_column("skill", ratio=2)
    table.add_column("subdomain", ratio=1, style=_C_DIM)
    table.add_column("what it covers", ratio=3, style=_C_DIM)
    for card in skills[:10]:
        table.add_row(
            _short(getattr(card, "name", ""), 34),
            _short(getattr(card, "subdomain", ""), 20),
            _short(getattr(card, "description", ""), 60),
        )
    note = Text(
        "\nKB hints only — breadth for the planner. Skills never become "
        "findings; the rule floor and the pure judges remain the guarantees.",
        style=_C_DIM,
    )
    return Panel(
        Group(table, note),
        title=f"[{_C_ACCENT}]▐ KNOWLEDGE · {len(skills)} SKILL HINT(S)[/{_C_ACCENT}]",
        border_style=_C_ACCENT, padding=(1, 2),
    )


_SEV_STYLE = {"CRITICAL": "bright_red", "HIGH": "bright_red",
              "MEDIUM": _C_WARN, "LOW": _C_DIM}


def _hyp_rows(table, hyps, *, wired):
    for h in hyps:
        judge_mark = ""
        if h.provable:
            judge_mark = (f"[{_C_OK}]judge[/{_C_OK}]" if h.technique in wired
                          else f"[{_C_WARN}]lead*[/{_C_WARN}]")
        else:
            judge_mark = f"[{_C_LEAD}]lead[/{_C_LEAD}]"
        sev = (h.severity or "").upper()
        table.add_row(
            f"[{_SEV_STYLE.get(sev, _C_DIM)}]{sev or '—':<8}[/]",
            _short(h.technique, 18),
            _short(h.url, 40),
            _short(h.param or "—", 14),
            f"[{_C_DIM}]{h.source}[/{_C_DIM}]",
            judge_mark,
        )


def _hypotheses_panel(plan) -> Panel:
    wired = set(J.WIRED_TECHNIQUES)
    table = Table(show_header=True, header_style=f"bold {_C_PRIMARY}",
                  border_style=_C_PRIMARY, expand=True)
    table.add_column("sev", width=8)
    table.add_column("technique")
    table.add_column("where")
    table.add_column("param")
    table.add_column("src", width=5)
    table.add_column("route", width=6)

    _hyp_rows(table, plan.provable, wired=wired)
    if plan.provable and plan.leads:
        table.add_section()
    _hyp_rows(table, plan.leads, wired=wired)

    note = Text(
        f"\n{len(plan.provable)} provable · {len(plan.leads)} lead(s).  "
        "A hypothesis is a justified test, never a finding. "
        "`judge` = a pure differential will decide it; "
        "`lead*` = provable class with no single-probe judge (needs a matrix); "
        "`lead` = non-differential, surfaced honestly.",
        style=_C_DIM,
    )
    return Panel(
        Group(table, note),
        title=f"[{_C_PRIMARY}]▐ HYPOTHESES · {len(plan.hypotheses)}[/{_C_PRIMARY}]",
        border_style=_C_PRIMARY, padding=(1, 2),
    )


_VERDICT_STYLE = {
    O.VERDICT_CONFIRMED: _C_BAD,        # a proven vuln is bad news, shown loud
    O.VERDICT_DISPROVED: _C_OK,         # tested and safe
    O.VERDICT_INCONCLUSIVE: _C_WARN,
    O.VERDICT_LEAD: _C_LEAD,
    O.VERDICT_ERROR: _C_WARN,
}
_VERDICT_ORDER = (O.VERDICT_CONFIRMED, O.VERDICT_DISPROVED,
                  O.VERDICT_INCONCLUSIVE, O.VERDICT_LEAD, O.VERDICT_ERROR)


def _verdicts_panel(verdicts) -> Panel:
    counts = {status: 0 for status in _VERDICT_ORDER}
    for verdict in verdicts:
        counts[verdict.status] = counts.get(verdict.status, 0) + 1

    table = Table(show_header=True, header_style="bold white",
                  border_style=_C_DIM, expand=True)
    table.add_column("verdict", width=13)
    table.add_column("technique")
    table.add_column("where")
    table.add_column("why", ratio=2)

    ordered = sorted(
        verdicts,
        key=lambda v: (_VERDICT_ORDER.index(v.status)
                       if v.status in _VERDICT_ORDER else 99),
    )
    for verdict in ordered:
        style = _VERDICT_STYLE.get(verdict.status, _C_DIM)
        hyp = verdict.hypothesis
        table.add_row(
            f"[bold {style}]{verdict.status}[/bold {style}]",
            _short(hyp.technique, 18),
            _short(hyp.param or hyp.url, 34),
            _short(verdict.detail, 52),
        )

    tally = "  ".join(
        f"[{_VERDICT_STYLE[s]}]{s} {counts[s]}[/{_VERDICT_STYLE[s]}]"
        for s in _VERDICT_ORDER if counts.get(s)
    )
    note = Text.from_markup(
        f"\n{tally}\n" if tally else "\n",
    )
    footer = Text(
        "Only a reproduced differential is CONFIRMED. LEADs are honest, "
        "evidence-backed directions — never conflated with a proof.",
        style=_C_DIM,
    )
    return Panel(
        Group(table, note, footer),
        title=f"[{_C_PRIMARY}]▐ VERDICTS · {len(verdicts)}[/{_C_PRIMARY}]",
        border_style=_C_PRIMARY, padding=(1, 2),
    )


def _outcome_panel(label: str, outcome) -> Panel:
    result = getattr(outcome, "result", "ERROR")
    proven = result == "FIX_PROVEN"
    color = _C_OK if proven else (_C_WARN if result == "NOT_APPLICABLE" else _C_BAD)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=_C_DIM, justify="right")
    grid.add_column(style="white")
    grid.add_row("result", f"[bold {color}]{result}[/bold {color}]")

    verification = getattr(outcome, "verification", None)
    if verification is not None:
        before = getattr(verification, "before_status", "?")
        after = getattr(verification, "after_status", "?")
        b_style = {"VALIDATED": _C_BAD, "DISPROVED": _C_OK}.get(before, _C_WARN)
        a_style = {"VALIDATED": _C_BAD, "DISPROVED": _C_OK}.get(after, _C_WARN)
        grid.add_row(
            "judge",
            f"[bold {b_style}]{before}[/bold {b_style}] "
            f"[{_C_DIM}]→[/{_C_DIM}] "
            f"[bold {a_style}]{after}[/bold {a_style}]  "
            f"[{_C_DIM}](same pure judge, under live enforcement)[/{_C_DIM}]",
        )
        before_code = getattr(verification, "before_status_code", None)
        after_code = getattr(verification, "observed_status_code", None)
        if before_code is not None or after_code is not None:
            grid.add_row("http", f"{before_code} → {after_code}")

    if getattr(outcome, "detail", ""):
        grid = Group(grid, Text(f"\n{_short(outcome.detail, 100)}", style=_C_DIM))

    return Panel(
        grid,
        title=f"[{color}]▐ FIX · {label} · {getattr(outcome, 'finding_id', '')}[/{color}]",
        border_style=color, padding=(1, 2),
    )


# ---- SESSION-AWARE stage (opt-in) -------------------------------------------
# "while testing login, if it finds a param, mutate it holding cookies constant,
# and bisect the cookies to see which are load-bearing vs placeholders." This is
# live, so it is strictly opt-in: it runs only when the operator supplies a
# captured session via $SENTINEL_SESSION_COOKIE (never persisted, never logged).

def _session_stage(surface, plan, *, cookie=None, session_url=None, prober=None):
    cookie = cookie if cookie is not None else os.environ.get("SENTINEL_SESSION_COOKIE")
    if not cookie:
        return None
    session_url = (session_url or os.environ.get("SENTINEL_SESSION_URL")
                   or surface.target)
    if session_url and "://" not in session_url:
        session_url = "http://" + session_url

    mutate = []
    for h in plan.provable:
        if h.param:
            mutate.append({"param": h.param, "values": ["1", "2"], "url": h.url})
            break

    if prober is None:
        from app.autonomous.probe import HttpProber
        host = surface.host
        prober = HttpProber(allowed_hosts={host} if host else None)

    try:
        return O.probe_session(prober, session_url, cookie, mutate=mutate)
    except Exception:  # a live-session hiccup must never break the loop
        return None


def _session_panel(session_map) -> Panel:
    report = getattr(session_map, "cookie_report", None)
    blocks = []

    if report is not None:
        cookie_tbl = Table.grid(padding=(0, 2))
        cookie_tbl.add_column(style=_C_DIM, justify="right")
        cookie_tbl.add_column(style="white")
        cookie_tbl.add_row("session alive", "yes" if report.alive else "no")
        if report.alive:
            lb = ", ".join(report.load_bearing) or "—"
            ph = ", ".join(report.placeholders) or "—"
            cookie_tbl.add_row("load-bearing", f"[{_C_BAD}]{lb}[/{_C_BAD}]")
            cookie_tbl.add_row("placeholders", f"[{_C_DIM}]{ph}[/{_C_DIM}]")
        elif report.note:
            cookie_tbl.add_row("note", report.note)
        blocks.append(cookie_tbl)

    for mutation in getattr(session_map, "mutations", ()) or ():
        mut_tbl = Table(show_header=True, header_style=f"bold {_C_ACCENT}",
                        border_style=_C_DIM, expand=True)
        mut_tbl.add_column(f"param '{mutation.param}' = value")
        mut_tbl.add_column("status", width=8)
        base = mutation.baseline
        mut_tbl.add_row("· baseline",
                        str(getattr(base, "status", "—")))
        for value, probe in mutation.mutations:
            mut_tbl.add_row(_short(value, 40), str(getattr(probe, "status", "—")))
        blocks.append(mut_tbl)

    footer = Text(
        "\nEvidence only — the session map holds cookies constant and observes. "
        "It never declares a vulnerability; the judges dispose.",
        style=_C_DIM,
    )
    blocks.append(footer)
    return Panel(
        Group(*blocks),
        title=f"[{_C_ACCENT}]▐ SESSION-AWARE PROBING[/{_C_ACCENT}]",
        border_style=_C_ACCENT, padding=(1, 2),
    )


# ---- OPERATOR STEER (checkpoint before EXECUTE) -----------------------------
# The operator is a THIRD proposer, alongside the LLM and the proof-assist tools.
# Before the judges run, we pause and let the operator type suggestions: new test
# hypotheses (folded via orchestrator.augment_plan — the SAME pure judge still
# disposes each) and/or auth context (a captured bearer token / a matrix path)
# that lights up the broken_auth + privilege_escalation matrix stage. The operator
# can NEVER confirm — a suggestion only earns the judge another honest measurement.
# Auto-OFF when there is no TTY, in CI, or under $SENTINEL_ASSUME_YES; a
# non-interactive $SENTINEL_STEER string steers headlessly. The token is a secret:
# captured into the directive, held in memory, NEVER echoed here.

_STEER_END = frozenset({"", "go", "done", "continue", "run", "proceed", "ok"})


def _steer_enabled() -> bool:
    """Interactive steering is opt-out-safe: silent in CI / headless / pre-approved
    runs, and only prompts when a real TTY is attached."""
    if _truthy_env("SENTINEL_ASSUME_YES") or _truthy_env("CI") or _truthy_env(
            "SENTINEL_NO_STEER"):
        return False
    try:
        import sys
        return bool(sys.stdin and sys.stdin.isatty())
    except Exception:
        return False


def _prompt_operator(surface) -> str:
    """Read a short free-form steer from the operator (one directive per line,
    ended by a blank line / go / done). Never blocks a headless run — the caller
    only invokes this when a TTY is present."""
    host = getattr(surface, "host", "") or "the target"
    console.print(Panel(
        Text.assemble(
            ("steer Sentinel before it proves — you are a proposer, never a judge\n\n",
             f"bold {_C_ACCENT}"),
            (f"  test <technique> </path|url> [param] [loc] [sev]   add a probe (scoped to {host})\n",
             _C_DIM),
            ("  token <bearer-jwt>                                 genuine session token (secret)\n",
             _C_DIM),
            ("  matrix <path.json>                                 broken_auth / privesc oracle\n",
             _C_DIM),
            ("  (blank line | go | done)                           run\n", _C_DIM),
        ),
        title=f"[{_C_ACCENT}]▐ OPERATOR STEER[/{_C_ACCENT}]",
        border_style=_C_ACCENT, padding=(1, 2)))
    lines = []
    while True:
        try:
            line = console.input(f"[{_C_ACCENT}]steer>[/{_C_ACCENT}] ")
        except (EOFError, KeyboardInterrupt):
            break
        if line.strip().lower() in _STEER_END:
            break
        lines.append(line)
    return "\n".join(lines)


def _steer_panel(directive, *, folded) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=_C_DIM, justify="right")
    grid.add_column(style="white")
    grid.add_row("hypotheses folded",
                 f"[{_C_OK}]{folded}[/{_C_OK}]" if folded else f"[{_C_DIM}]0[/{_C_DIM}]")
    # A token is a secret — report only its PRESENCE, never its value.
    grid.add_row("session token",
                 f"[{_C_OK}]captured[/{_C_OK}]" if directive.token
                 else f"[{_C_DIM}]—[/{_C_DIM}]")
    grid.add_row("matrix path",
                 f"[{_C_PRIMARY}]{_short(directive.matrix_path, 48)}[/{_C_PRIMARY}]"
                 if directive.matrix_path else f"[{_C_DIM}]—[/{_C_DIM}]")
    if directive.ignored:
        grid.add_row("ignored",
                     f"[{_C_WARN}]{_short('; '.join(directive.ignored), 60)}[/{_C_WARN}]")
    note = Text(
        "\nThe operator only PROPOSES — folded hypotheses are re-ranked into the "
        "plan and the SAME pure judge disposes each. Auth context (token/matrix) "
        "feeds the broken_auth/privesc stage; the token value is never echoed.",
        style=_C_DIM)
    return Panel(
        Group(grid, note),
        title=f"[{_C_ACCENT}]▐ OPERATOR STEER · {folded} FOLDED[/{_C_ACCENT}]",
        border_style=_C_ACCENT, padding=(1, 2))


def _operator_stage(plan, *, steer_text=None, prompt_fn=None, parse=None):
    """Checkpoint before EXECUTE: gather an operator steer, fold its hypotheses into
    the plan, and hand back the parsed directive (auth context for the matrix stage).
    Returns ``(plan, directive_or_None)``. Never raises; auto-off when headless."""
    from app.autonomous.steer import parse_operator_suggestion
    parse = parse or parse_operator_suggestion

    text = steer_text
    if text is None:
        text = os.environ.get("SENTINEL_STEER")
    if text is None:
        if prompt_fn is None and not _steer_enabled():
            return plan, None
        prompt_fn = prompt_fn or _prompt_operator
        try:
            text = prompt_fn(plan.surface)
        except Exception:  # a prompt hiccup must never sink the loop
            return plan, None
    if not (text or "").strip():
        return plan, None

    directive = parse(text, plan.surface)
    before = len(plan.hypotheses)
    augmented = O.augment_plan(plan, directive.hypotheses) if directive.hypotheses else plan
    folded = len(augmented.hypotheses) - before

    if directive.is_empty and not directive.ignored:
        return augmented, directive
    console.print()
    console.print(Rule(f"[bold {_C_ACCENT}]OPERATOR STEER (you propose)[/bold {_C_ACCENT}]",
                       style=_C_ACCENT))
    console.print(_steer_panel(directive, folded=folded))
    return augmented, directive


# ---- AUTH MATRIX (broken_auth / privilege_escalation, after EXECUTE) --------
# These two classes are MATRIX-driven, not single-probe — deliberately absent from
# the wired judges. They prove HERE, gated on operator-supplied context: broken_auth
# needs a forgery matrix AND a genuine bearer token (no token → honestly skipped,
# never a blind run); privesc needs a ≥1-check login matrix. The stage OWNS no
# verdict — it runs the SAME pure judges the security_graph classes ship and adapts
# each ProbeResult through the single VALIDATED→CONFIRMED site, carrying the proven
# graph so the report renders full steps-to-reproduce, exactly like a wired class.

def _authmatrix_panel(context, verdicts) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=_C_DIM, justify="right")
    grid.add_column(style="white")
    for note in context.notes or ("no broken_auth / privesc matrix supplied",):
        grid.add_row("context", note)  # notes are token-SAFE (presence, never value)

    counts = {}
    for v in verdicts:
        counts[v.status] = counts.get(v.status, 0) + 1
    tally = "  ".join(
        f"[{_VERDICT_STYLE.get(s, _C_DIM)}]{s} {counts[s]}[/{_VERDICT_STYLE.get(s, _C_DIM)}]"
        for s in _VERDICT_ORDER if counts.get(s)) or f"[{_C_DIM}]no verdicts[/{_C_DIM}]"
    note = Text(
        "\nThe SAME pure judges that back the wired classes run here on a fresh "
        "graph; the operator only supplies the matrix/token the class honestly "
        "needs. broken_auth without a genuine token is skipped, never guessed.",
        style=_C_DIM)
    return Panel(
        Group(grid, Text.from_markup(f"\n{tally}"), note),
        title=f"[{_C_ACCENT}]▐ AUTH MATRIX · {len(verdicts)} VERDICT(S)[/{_C_ACCENT}]",
        border_style=_C_ACCENT, padding=(1, 2))


def _authmatrix_stage(target, directive, *, resolve=None, run_matrix=None):
    """Resolve broken_auth/privesc context (operator directive + env) and, when it
    is active, run the matrix judges and adapt their ProbeResults into Verdicts that
    join the main pool. Returns a list of Verdicts (empty when no context). Never
    raises: a judge fault degrades to a note, never a manufactured pass or a crash."""
    from app.autonomous import authmatrix as AM
    resolve = resolve or AM.resolve_auth_context
    run_matrix = run_matrix or AM.run_auth_matrix

    try:
        context = resolve(directive)
    except Exception:  # resolution is best-effort; a bad file must not sink the run
        return []
    if not context.active:
        # Surface honest notes only when the operator DID supply context that
        # resolved to nothing (e.g. a matrix that failed to load, token-but-no-matrix).
        if context.notes:
            console.print()
            console.print(Rule(f"[bold {_C_ACCENT}]AUTH MATRIX[/bold {_C_ACCENT}]",
                               style=_C_ACCENT))
            console.print(_authmatrix_panel(context, []))
        return []

    console.print()
    console.print(Rule(f"[bold {_C_ACCENT}]AUTH MATRIX (matrix classes prove)[/bold {_C_ACCENT}]",
                       style=_C_ACCENT))
    try:
        with console.status(
                f"[{_C_ACCENT}]running the broken_auth / privilege-escalation "
                f"matrix judges live…[/{_C_ACCENT}]", spinner="dots"):
            verdicts = list(run_matrix(target, context))
    except Exception as exc:  # a genuinely broken judge → a note, never a crash
        console.print(Text(
            f"auth-matrix stage degraded ({_short(str(exc), 80)})", style=_C_WARN))
        verdicts = []
    console.print(_authmatrix_panel(context, verdicts))
    return verdicts


# ---- PATCH → PROVE (human deploy gate) --------------------------------------

def _group_confirmed(verdicts):
    """CONFIRMED verdicts grouped by technique, first-seen order preserved."""
    order, groups = [], {}
    for verdict in verdicts:
        if verdict.status != O.VERDICT_CONFIRMED:
            continue
        technique = verdict.hypothesis.technique
        if technique not in groups:
            groups[technique] = []
            order.append(technique)
        groups[technique].append(verdict)
    return [(technique, groups[technique]) for technique in order]


def _remediate_confirmed(verdicts, *, registry=None, gate=None):
    """For every CONFIRMED class: synthesize the corrective control, take the
    operator's approval, then remediate + re-prove on the SAME graph the judge
    proved on. Returns the outcomes (for rendering / tests). Never raises."""
    from app.commands.remediation_gate import RemediationProposal

    if _truthy_env("SENTINEL_SKIP_REMEDIATION"):
        if any(v.status == O.VERDICT_CONFIRMED for v in verdicts):
            console.print(Text(
                "remediation skipped ($SENTINEL_SKIP_REMEDIATION set)", style=_C_DIM))
        return []

    grouped = _group_confirmed(verdicts)
    if not grouped:
        return []

    registry = registry if registry is not None else _load_registry()
    gate = gate or _gate
    all_outcomes = []

    for technique, group in grouped:
        spec = registry.get(technique)
        if spec is None:                    # only wired techniques ever CONFIRM
            continue

        proposals, graphs = [], []
        for verdict in group:
            graph = getattr(verdict.evidence, "graph", None)
            if graph is None:
                continue
            findings = graph.findings_for(kind=spec.kind, status="OPEN")
            if not findings:
                continue
            for finding in findings:
                try:
                    plan = spec.synth(graph, finding)
                except Exception:           # a synth hiccup → generic control line
                    plan = None
                control = spec.control(plan) if plan is not None else spec.fallback_control
                proposals.append(RemediationProposal(
                    title=finding.title, severity=finding.severity, control=control))
            graphs.append(graph)

        if not proposals:
            continue

        console.print()
        console.print(Rule(
            f"[bold {_C_OK}]REMEDIATION · PATCH + PROVE · {spec.label.upper()} · "
            f"{len(proposals)} FINDING(S)[/bold {_C_OK}]", style=_C_OK))

        if not gate(spec.label, proposals):
            continue                         # gate already printed the deferred panel

        class_outcomes = []
        with console.status(
            f"[{_C_OK}]standing up the loopback enforcement shield + re-proving "
            f"{spec.label} live…[/{_C_OK}]", spinner="dots"):
            for graph in graphs:
                try:
                    class_outcomes.extend(spec.remediate(graph))
                except Exception as exc:     # surface cleanly, never crash the loop
                    console.print(Panel(
                        Text(str(exc), style=_C_BAD),
                        title=f"[{_C_BAD}]{spec.label} remediation failed[/{_C_BAD}]",
                        border_style=_C_BAD))

        for outcome in class_outcomes:
            console.print(_outcome_panel(spec.label, outcome))
        all_outcomes.extend(class_outcomes)

    return all_outcomes


# ---- REPORT — assemble + persist the proof-carrying deliverable -------------

def _narration_seam(use_llm):
    """Return a ``complete(prompt) -> str`` seam for the advisory exec-summary,
    or ``None`` when narration is disabled/offline. The narrator only ever sees a
    metadata-only digest (see ``report._digest``) and its prose is fenced as
    advisory; the LLM proposes, it never disposes. Any failure degrades to no
    summary, so the report always renders without depending on a model."""
    if not use_llm:
        return None

    def complete(prompt):
        from app.autonomous.llm import ask_json
        res = ask_json(
            "You are a penetration-test report writer. Reply with ONLY a JSON "
            'object of the form {"summary": "<plain prose, no markdown>"}.',
            prompt,
            num_predict=400,
        )
        if res.ok and isinstance(res.data, dict):
            return str(res.data.get("summary", "") or "")
        return ""

    return complete


def _report_panel(artifacts, model) -> Panel:
    c = model.counts
    body = Text.assemble(
        ("proof-carrying report written\n\n", f"bold {_C_OK}"),
        ("  markdown  ", "white"), (f"{artifacts.markdown_path}\n", _C_PRIMARY),
        ("  json      ", "white"), (f"{artifacts.json_path}\n\n", _C_PRIMARY),
        (f"  {c['confirmed']} confirmed", _C_BAD if c["confirmed"] else _C_DIM),
        (f" · {c['fix_proven']} fix-proven", _C_OK if c["fix_proven"] else _C_DIM),
        (f" · {c['leads']} leads", _C_LEAD if c["leads"] else _C_DIM),
        (f" · {c['disproved']} disproved · {c['inconclusive']} inconclusive · "
         f"{c['errors']} errors", _C_DIM),
    )
    return Panel(body, title=f"[bold {_C_OK}]▐ REPORT[/bold {_C_OK}]",
                 border_style=_C_OK)


def _emit_report(report, outcomes, *, target, use_llm, out_dir="reports"):
    """Stage 10 — build the pure report model from the proven graph + remediation
    outcomes, attach an optional advisory exec-summary, and persist md+json. Every
    fact comes from the judges; the narrator only garnishes. Never raises: a
    reporting hiccup must not sink an otherwise-successful run. Returns the written
    :class:`report.ReportArtifacts`, or ``None`` if reporting was skipped."""
    console.print()
    console.print(Rule(f"[bold {_C_OK}]REPORT[/bold {_C_OK}]", style=_C_OK))
    try:
        model = R.build_report(report, outcomes=tuple(outcomes or ()), target=target)
        narrative = R.narrate(model, complete=_narration_seam(use_llm))
        artifacts = R.write_report(model, out_dir=out_dir, narrative=narrative)
    except Exception as exc:  # reporting is best-effort; never crash the loop
        console.print(Text(f"report generation skipped ({_short(str(exc), 80)})",
                           style=_C_WARN))
        return None
    console.print(_report_panel(artifacts, model))
    return artifacts


# ---- entrypoint -------------------------------------------------------------

def _usage() -> Panel:
    body = Text.assemble(
        ("autonomous <target>\n\n", f"bold {_C_PRIMARY}"),
        ("Point Sentinel at a URL and let it run the whole loop: live recon → "
         "KB-informed qwen hypotheses → concurrent pure-judge proof → gated "
         "patch+prove. Works on any http/https target; nothing off-scope is "
         "ever probed.\n\n", _C_DIM),
        ("optional environment:\n", "white"),
        ("  SENTINEL_LLM_PROVIDER     ollama (default, offline) | anthropic | "
         "openai | compatible\n", _C_DIM),
        ("  ANTHROPIC_API_KEY / OPENAI_API_KEY   key for a hosted model "
         "(env or one-time getpass; never stored)\n", _C_DIM),
        ("  SENTINEL_LLM_MODEL        override the model id (e.g. claude-opus-5)\n", _C_DIM),
        ("  SENTINEL_LLM_URL          base URL for a self-hosted / compatible "
         "gateway\n", _C_DIM),
        ("  SENTINEL_SESSION_COOKIE   run the session-aware stage against a "
         "captured jar\n", _C_DIM),
        ("  SENTINEL_SESSION_URL      URL for the session stage (default: target)\n", _C_DIM),
        ("  SENTINEL_STEER            non-interactive operator steer (test/token/"
         "matrix lines)\n", _C_DIM),
        ("  SENTINEL_NO_STEER=1       never prompt for an operator steer (headless)\n", _C_DIM),
        ("  SENTINEL_SESSION_TOKEN    genuine bearer token for the broken_auth "
         "matrix (secret)\n", _C_DIM),
        ("  SENTINEL_BROKEN_AUTH_POLICY / SENTINEL_PRIVESC_POLICY / "
         "SENTINEL_ACCESS_POLICY   matrix files\n", _C_DIM),
        ("  SENTINEL_ENABLE_TOOLS=1   run opt-in proof-assist tools (sqlmap…) as "
         "nominators\n", _C_DIM),
        ("  SENTINEL_ASSUME_YES=1     pre-approve the deploy gate + tool "
         "auto-install (CI/headless)\n", _C_DIM),
        ("  SENTINEL_SKIP_REMEDIATION skip patch+prove entirely\n", _C_DIM),
    )
    return Panel(body, title=f"[{_C_PRIMARY}]▐ AUTONOMOUS[/{_C_PRIMARY}]",
                 border_style=_C_PRIMARY, padding=(1, 2))


def _provider_line(use_llm: bool) -> Text:
    """One dim line naming the active proposal backend — provider · model — so
    the operator always knows what is generating hypotheses. Never prints a key,
    and never raises: a misconfigured provider degrades to the rule floor."""
    if not use_llm:
        return Text(
            "model   LLM disabled — deterministic rule floor only",
            style=_C_DIM,
        )
    try:
        from app.autonomous.llm import resolve_provider
        provider = resolve_provider()
    except Exception as exc:  # missing key / bad config → honest fallback note
        return Text(
            f"model   LLM misconfigured ({_short(str(exc), 60)}) — "
            "falling back to the deterministic rule floor",
            style=_C_WARN,
        )
    return Text(
        f"model   {provider.name} · {provider.model}   "
        "(proposes only — a pure judge disposes)",
        style=_C_DIM,
    )


def run(arg, *, _recon=None, _index=None, _judges=None, _nominate=None,
        _steer=None, _authmatrix=None, use_llm=True):
    """`autonomous <target>` — the dynamic autonomous pentest loop.

    Seams (`_recon`, `_index`, `_judges`, `_nominate`, `_steer`, `_authmatrix`,
    `use_llm`) let the whole command run offline in tests; live use takes their
    real defaults."""
    target = (arg or "").strip().split()[0] if (arg or "").strip() else ""
    if not target:
        console.print(_usage())
        return None

    console.print(_banner(target))
    console.print(_provider_line(use_llm))

    # DISCOVER — live recon → orchestrator recon/findings dicts.
    with console.status(f"[{_C_OK}]running live recon…[/{_C_OK}]", spinner="dots"):
        recon, findings = (_recon or _live_recon)(target)

    # UNDERSTAND — rank the KB against the surface (optional; never fatal).
    if _index is not None:
        index = _index
    else:
        from app.knowledge.skill_index import SkillIndex
        index = SkillIndex.load()

    # HYPOTHESIZE — qwen proposes over a deterministic rule floor. Stage 2 SELECT
    # ENDPOINTS runs inside build_plan: it ranks the surface by injectability and,
    # only when $SENTINEL_ENDPOINT_BUDGET is set, prunes the tail (explicit, recorded).
    with console.status(
            f"[{_C_ACCENT}]fingerprinting surface + generating hypotheses…"
            f"[/{_C_ACCENT}]", spinner="dots"):
        plan = O.build_plan(recon, findings, skills_index=index, use_llm=use_llm,
                            endpoint_budget=_endpoint_budget())

    console.print(_surface_panel(plan.surface, recon))
    if plan.endpoint_selection is not None and plan.endpoint_selection.total:
        console.print(_endpoints_panel(plan.endpoint_selection))
    if plan.skills:
        console.print(_skills_panel(plan.skills))
    console.print(_hypotheses_panel(plan))

    # NOMINATE — opt-in proof-assist tools (sqlmap…) widen the plan as PROPOSERS.
    # OFF unless $SENTINEL_ENABLE_TOOLS; the pure judge still disposes each.
    plan = _nominate_stage(plan, nominate=_nominate)

    # SESSION-AWARE — opt-in (needs a captured jar).
    session_map = _session_stage(plan.surface, plan)
    if session_map is not None:
        console.print(_session_panel(session_map))

    # OPERATOR STEER — checkpoint before EXECUTE: the operator proposes extra probes
    # (folded via augment_plan; the SAME pure judge disposes each) and/or auth
    # context (token / matrix) that the AUTH MATRIX stage below consumes. Auto-off
    # when headless; $SENTINEL_STEER steers non-interactively. Never echoes a token.
    plan, directive = (_steer or _operator_stage)(plan)

    # PLAN EXECUTION (Stage 5) — derive the concrete execution shape from the final
    # plan: work slots, judge/lead assignment, real concurrency, retry-round budget,
    # and in-scope proof-assist tools. Pure annotation + knobs — never a coverage
    # gate: every hypothesis keeps its slot; the pure judges still dispose each.
    from app.autonomous import execplan as EXEC
    rounds = _refine_rounds()
    tools_on = _truthy_env("SENTINEL_ENABLE_TOOLS")
    try:
        from app.tools.selector import select_tools
        tool_plan = select_tools(plan.surface, plan.hypotheses)
        execplan = EXEC.plan_execution(
            plan, wired_techniques=J.WIRED_TECHNIQUES, tool_plan=tool_plan,
            tools_enabled=tools_on, max_workers=8, max_rounds=rounds,
            budget=_worker_budget())
        console.print()
        console.print(Rule(f"[bold {_C_PRIMARY}]PLAN EXECUTION[/bold {_C_PRIMARY}]",
                           style=_C_PRIMARY))
        console.print(_execplan_panel(execplan))
    except Exception:  # planning is annotation; a hiccup falls back to plain knobs
        execplan = EXEC.plan_execution(
            plan, wired_techniques=J.WIRED_TECHNIQUES, max_rounds=rounds,
            budget=_worker_budget())

    # EXECUTE + PROVE — concurrent adjudication by the pure judges, with a bounded
    # FAILURE-CAUSE + RETRY loop: a non-terminal verdict is re-posed with a
    # different probe shape and re-judged (the judge still disposes each variant).
    judges = _judges if _judges is not None else J.default_judges()
    console.print()
    console.print(Rule(f"[bold {_C_PRIMARY}]EXECUTE + PROVE[/bold {_C_PRIMARY}]",
                       style=_C_PRIMARY))
    with console.status(
            f"[{_C_PRIMARY}]adjudicating hypotheses concurrently — live "
            f"differential judges…[/{_C_PRIMARY}]", spinner="dots"):
        verdicts = list(O.run_plan_adaptive(plan, judges, max_workers=execplan.max_workers,
                                            max_rounds=execplan.max_rounds))

    # AUTH MATRIX — broken_auth / privilege_escalation prove from operator-supplied
    # context (directive + env). Its verdicts join the SAME pool: the two classes
    # confirm only when the matrix judges reproduce the differential, and they are
    # not in the remediation registry, so they render honestly without a FIX_PROVEN.
    verdicts += list((_authmatrix or _authmatrix_stage)(target, directive))

    console.print(_verdicts_panel(verdicts))

    # PATCH + PROVE — gated on the operator's approval.
    outcomes = _remediate_confirmed(verdicts)

    report = O.Report(plan=plan, verdicts=tuple(verdicts))

    # REPORT — persist the proof-carrying deliverable (markdown + json).
    _emit_report(report, outcomes, target=target, use_llm=use_llm)

    return report






