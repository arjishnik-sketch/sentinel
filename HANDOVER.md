# Sentinel — Session Handover

**Date:** 2026-08-26 · **Branch:** `sentinel-2` · **HEAD:** `ee2b222` · **Suite:** 453 passed, 1 skipped (network-free, ~31s)

> Read `ROADMAP.md` first — it is canonical. This handover is the *"you are here"*
> pin on that map plus the exact next action. The invariant contract (`ROADMAP.md` §1)
> governs every line of code below; violating it is worse than shipping nothing.

---

## The one rule that governs everything

**Tools and the LLM PROPOSE; a pure deterministic judge DISPOSES.** A `CONFIRMED`
finding materializes only when a pure `judge_X(graph, ...)` reproduces a *differential
with an explicit anchor* — never from a bare status code, a tool hit, or an LLM claim.
`FIX_PROVEN` requires the **same** judge to flip `VALIDATED → DISPROVED` under live
enforcement on an isolated scratch graph. A tool/LLM output is a **LEAD** until a judge
confirms it. Manufacturing a verdict — or shipping capability we cannot prove — is the
one forbidden act.

---

## Where we are

- **Part I — the proof-carrying core: COMPLETE.** All 12 vulnerability classes
  (`injection`, `template_injection`, `xss`, `path_traversal`, `open_redirect`,
  `cors_misconfig`, `ssrf`, `broken_auth`, plus the four baseline/oracle classes) **and**
  the provable 2-link chaining capstone are shipped, tested, and CLI-wired. Five close
  the full find→reason→prove→patch→prove loop against live targets.
- **Part II — the autonomous pentester: IN PROGRESS.**
  - ✅ Curated tool-selection module (`app/tools/selector.py`, §11) — tools propose only.
  - ✅ Pluggable LLM providers (`SENTINEL_LLM_PROVIDER=ollama|anthropic|openai|compatible`).
  - ✅ **Report generator (stage 10, §13) — shipped THIS session** as a standalone,
    fully-tested module. **Not yet wired into the `autonomous` CLI command** (see next step).
  - 🔨 Remaining: CLI-wire the report, then stages 2/5/8 (endpoint-select, exec-plan,
    failure-cause+retry), §12 KB deepening, Tier-B classes.

---

## What just shipped (this session — commit `ee2b222`)

`app/autonomous/report.py` + `tests/test_autonomous_report.py` (13 tests, green):

- `build_report(report, *, outcomes=(), target=None, generated_at=None) -> ReportModel`
  — **pure**: turns an `orchestrator.Report` (plan + tiered verdicts) plus optional
  remediation outcomes into a proof-carrying model. Sorts deterministically, opens no
  socket, invents no fact.
- Per CONFIRMED finding it lifts, straight from graph evidence: **steps-to-reproduce**
  (the literal probes the judge issued, sensitive header *values* masked), **proof**
  (judge name + status + verbatim reason + differential anchor + evidence ids), and
  **remediation** (the `VALIDATED→DISPROVED` flip + rendered deployable configs).
- `render_markdown` / `render_json` / `write_report(model, out_dir="reports")` →
  `reports/<host>.md` + `.json`.
- `narrate(model, *, complete=...)` — optional LLM executive summary. Advisory-only,
  fenced as such, returns `""` when no seam or on any error; contributes zero facts.

Everything asserts nothing beyond what a pure judge already proved.

---

## ▶ Immediate next step — wire the report into the CLI

The generator is proven in isolation but the `autonomous` command still discards its
own result. Close the loop in `app/commands/autonomous_cmd.py`:

1. In `run()` (ends ~L687–689), capture the outcomes:
   `outcomes = _remediate_confirmed(verdicts)` (it already `return`s `all_outcomes`).
2. Build the orchestrator report `report = O.Report(plan=plan, verdicts=tuple(verdicts))`,
   then `model = report_mod.build_report(report, outcomes=outcomes, target=target)`.
3. `narrative = report_mod.narrate(model, complete=<seam>) if use_llm else ""` — reuse
   the same provider seam the hypothesis stage uses (`resolve_provider`); keep it behind
   `use_llm` so offline/CI runs render fact-only.
4. `arts = report_mod.write_report(model, narrative=narrative)` and print a small panel
   pointing the operator at `arts.markdown_path` / `arts.json_path`.
5. **Verify the join key:** `report.py` groups remediation by `outcome.finding_id`.
   Confirm `RemediationOutcome` actually carries `finding_id` (grep the remediation
   package); if it does not, thread the finding id through `_remediate_confirmed` before
   wiring, or the FIX_PROVEN block will silently not attach.
6. Add an offline test in `tests/test_autonomous_cmd.py` (reuse its existing `_recon`/
   `_index`/`_judges`/`use_llm=False` seams) asserting a report file lands in a tmp dir.

`app/autonomous/__init__.py` does not re-export the report symbols yet — import as
`from app.autonomous import report` (or add the re-export while wiring).

## Then, in ROADMAP Part II build order (§13 / §14)

1. **Stage 8 — failure-cause analysis + retry** (the highest-value "smart" stage): on
   `INCONCLUSIVE` / suspicious-`DISPROVED`, a bounded LLM strategist proposes a
   *materially different* probe (encoding, `location` query→body→path→cookie, repaired
   anchor, tool-assist) — each re-judged by the **same** pure judge; strategist never
   sets a status. Log retries in the report for transparency.
2. **Stage 2 — SELECT ENDPOINTS**: rank/prune the recon surface by injectability to
   focus budget. **Stage 5 — PLAN EXECUTION**: order/concurrency/budget + which judges
   and which approved tools.
3. **§12 — deepen the skills KB**: technique-aware selection + derived metadata-only
   hint bundles feeding proposer / tool-selector / report prose (firewall stays absolute).
4. **Tier-B classes** (§10) in §7 phase style — cheapest-to-prove first: command
   injection & XXE (reuse the SSRF OOB collaborator), NoSQL, CRLF/header injection.
5. **Backlog (§14):** close `location="cookie"` end-to-end (judge+enforcer+proposer),
   then re-run the PortSwigger TrackingId blind-SQLi lab; UNION/data-extraction SQLi
   (feeds chaining artifacts); dedup duplicate CONFIRMED rows in the report.

## How to run

- **Tests:** `python -m pytest -q` (offline, ~31s). Single module: `python -m pytest tests/test_autonomous_report.py -q`.
- **The loop:** `./sentinel autonomous <url>` — DISCOVER→UNDERSTAND→HYPOTHESIZE→
  EXECUTE→PROVE→(gated)PATCH→PROVE. Also `./sentinel discover <url>`, `investigate`, `login`.
- **LLM provider:** default is local `ollama` / `qwen3:4b` (free, for bulk/CI). For a
  showcase run flip to Claude: `SENTINEL_LLM_PROVIDER=anthropic`,
  `SENTINEL_LLM_MODEL=claude-opus-4-8`, `ANTHROPIC_API_KEY` **in the environment only**
  (never in code or git). The provider layer never logs a key. The LLM only proposes —
  a stronger model buys better hypotheses/prose with zero new false-positive risk.
- **Live targets:** OWASP Juice Shop `:3000`, VAmPI `:5001`.
- **CI/gate env:** `SENTINEL_ASSUME_YES=1` (auto-approve deploy gate),
  `SENTINEL_SKIP_REMEDIATION=1`, `SENTINEL_CHAIN_POLICY=<path>`.

## Key file map

- `app/autonomous/` — the loop: `orchestrator.py` (stages + `Report`), `hypotheses.py`
  (qwen proposer), `judges.py` (bridge to the pure judges), `llm.py` (provider layer),
  `surface.py`, `session.py`, `probe.py`, **`report.py` (new)**.
- `app/security_graph/<class>/` — the 12 proof-carrying class packages (mirror-template
  §2): `<class>_policy.py`, `seed.py`, `executor.py`, `judge.py` (PURE), `run.py`,
  `discover.py`, `remediation.py`.
- `app/security_graph/chaining/` — the provable 2-link capstone (`compose.py`, decoy wall).
- `app/tools/` — `selector.py` (proposer plan), `runner.py`/`resolver.py`/`parsers.py`
  (approval-gated execution).
- `app/knowledge/skill_index.py` — the 817-card metadata KB (proposal/breadth-only).
- `app/commands/` — CLI: `autonomous_cmd.py`, `investigate_cmd.py`, `discover_cmd.py`,
  `remediation_gate.py`.
- `ROADMAP.md` (canonical), `USER_GUIDE.md`, `README.md`, `deck/` (investor deck).

## Known gaps / gotchas

- **Report not CLI-wired yet** — the immediate next step above.
- **Location vocab gap** — `_LOC_MAP` covers query/body_form/body_json/path; `cookie`
  and `header` still degrade to `query`. Blocks the cookie-ground-truth blind-SQLi lab.
- **Report dedup** — duplicate CONFIRMED/verdict rows are not deduped yet (§14 backlog).
- **Commit discipline** — commit at each §7/§14 phase boundary on `sentinel-2`;
  **do NOT push** unless the user explicitly asks. Use `SENTINEL_ASSUME_YES=1` for CI.
- **Never regress the contract** — every new stage is LLM-advisory + pure-judge-gated +
  behind the human deploy gate. A half-built class that can't prove its flip is worse
  than no class: finish one fully (test module + live check) before starting the next.

