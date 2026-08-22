<p align="center">
  <img src="assets/brand/sentinel_logo_dark.png" alt="Sentinel — Autonomous Authorization Research" width="720">
</p>

# Sentinel — User Guide

**Autonomous authorization research for live web targets — find → reason → prove, evidence-driven, with a bounded advisory AI.**

Sentinel points itself at a live HTTP target, recons the attack surface, forms conservative authorization hypotheses, and runs an adaptive research loop that ranks and probes them — showing every decision on an auditable "decision board." It is a local-first cyber-reasoning agent built for the AI Kavach challenge.

---

## TL;DR — quick start

Run everything **under WSL / Linux** from the repo root:

```bash
python3.12 -m venv .venv && source .venv/bin/activate && pip install -e .
```

Point `OLLAMA_URL` at your Ollama server, start a target, then:

```bash
./sentinel
```

At the `Sentinel > ` prompt:

```bash
investigate http://127.0.0.1:3000 12
```

Watch the decision board. Type `exit` to leave. Everything below explains each piece in depth.

---

## What Sentinel is / what it is NOT

**Sentinel IS:**

- An autonomous *authorization-research* engine. It discovers surface, generates hypotheses, scores them deterministically, and probes them under a strict scope guard.
- **Evidence-driven.** A raw HTTP status is a *fact*, never a verdict. Findings only crystallize from hypotheses that reach a `CONFIRMED` state under a deterministic judge.
- **Explainable and auditable.** Every research choice ships a human-readable rationale trail and shows the alternatives it outranked.
- **Target-agnostic.** The engine contains zero target-specific code. OWASP Juice Shop is only the test fixture; any reachable HTTP(S) URL works.
- **Bounded and safe.** Probes are scope-checked before a socket opens, kept local, non-destructive, and the LLM is advisory-only.

**Sentinel is NOT:**

- Not a signature scanner and not an exploit script.
- Not an "LLM wrapper." The AI only breaks ties among equally top-scored candidates; the deterministic score is always authoritative.
- Not (yet) a full find→reason→prove system end-to-end. The *find* half runs live today; the *reason/prove* half is implemented but not yet reachable autonomously (see **Roadmap / honest status**).
- Not a patching tool. No remediation stage exists today.

---

## Requirements

- **Python 3.12+** (the code uses `str | None` unions and `datetime.UTC`).
- **A local Ollama server** with the `qwen3:4b` model pulled (used for the advisory tiebreak).
- **A live HTTP(S) target** to investigate (e.g. OWASP Juice Shop).
- **WSL / Linux to run.** On the dev machine, source is edited on the Windows drive (`D:\scanner proj\sentinel`) but the app **runs under WSL/Linux** — the committed `.venv` is Linux-native (POSIX layout, `/usr/bin/python3.12`).
- Optional (legacy `hunt` pipeline only): the ProjectDiscovery Go binaries `subfinder`, `httpx`, `katana` on `PATH`. **Not needed for the primary `investigate` command.**

Runtime Python dependencies are minimal: `rich`, `requests`, `pyyaml`, `python-dotenv` (everything else is stdlib).

---

## Install

Do this **on the WSL / Linux side**, from the repo root. Create the Python 3.12 virtual environment:

```bash
python3.12 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install Sentinel (project name `sentinel-ai`) in editable mode:

```bash
pip install -e .
```

> Note: The committed `.venv` is Linux-only — do **not** try to run it from Windows `cmd`/PowerShell. If it is missing on the Linux side, recreate it with the commands above.

---

## Configure

Configuration comes from a `.env` file in the repo root, read by `app/config.py` via `load_dotenv()`. All variables have code defaults, so `.env` is optional — but under WSL you will usually need to override `OLLAMA_URL`.

| Variable | Purpose | Example / default |
|---|---|---|
| `OLLAMA_URL` | Base URL of the local Ollama server the advisor calls (`POST {OLLAMA_URL}/api/chat`). | `http://172.22.0.1:11434` (WSL dev value); default `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | Ollama model tag used for the advisory tiebreak. Must be pulled. | `qwen3:4b` |
| `AI_ADVISORY_TIMEOUT` | Short, independent timeout (s) for the per-cycle tiebreak so a slow model never stalls the loop. | `30` |
| `AI_ADVISORY_NUM_PREDICT` | Bounded output-token budget for the advisor's single-pick JSON reply. | `128` |
| `AI_ADVISORY_MAX_CANDIDATES` | Caps how many tied top-scored candidates are shown to the advisor per cycle. | `12` |
| `MAX_AI_INPUT` | Maximum characters of AI input context passed to the model. | `15000` |
| `REQUEST_TIMEOUT` | Timeout (s) for the legacy `app/ai.py` long-form analysis path only. | `600` |
| `LOG_LEVEL` | Python logging level (uppercased) applied via `logging.basicConfig`. | `INFO` |

A minimal WSL `.env` typically looks like:

```bash
printf 'OLLAMA_URL=http://172.22.0.1:11434\nOLLAMA_MODEL=qwen3:4b\n' > .env
```

> A second, separate config surface — `config/config.yaml` (read by `app/settings.py`, exposed by the REPL `config` command) — drives the legacy `hunt`/pipeline path only, not `investigate`.

---

## Start the services

### 1. Ollama with `qwen3:4b` (required)

Pull the model:

```bash
ollama pull qwen3:4b
```

Serve it (listens on port `11434`):

```bash
ollama serve
```

> **WSL networking note:** WSL2 has its own network namespace, so `localhost` inside WSL is *not* the Windows host. If Ollama runs on Windows, start it bound to all interfaces and point `OLLAMA_URL` at the WSL host-gateway IP:
>
> ```bash
> OLLAMA_HOST=0.0.0.0 ollama serve
> ```
>
> The gateway IP (dev value `172.22.0.1`) can change per machine/reboot — verify it:
>
> ```bash
> ip route | grep default
> ```
>
> Alternatively, install and run Ollama *inside* WSL and just use `http://127.0.0.1:11434`.

### 2. A live target (Juice Shop fixture)

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Any reachable HTTP(S) URL works — Juice Shop is only the fixture.

---

## Run it

From the repo root **under WSL/Linux**, launch the REPL with the authoritative launcher (it `cd`s in, activates `.venv`, and starts `app/cli.py`):

```bash
./sentinel
```

Equivalent entrypoints — the pip console script:

```bash
sentinel
```

…or invoking the module directly:

```bash
python3 app/cli.py
```

You will get a banner and the prompt `Sentinel > `. Run the **primary command** against your target (the second argument is the cycle budget, default `10`, clamped to `1..100`):

```bash
investigate http://127.0.0.1:3000 12
```

To just see the command's own syntax without contacting anything, call it with no argument:

```bash
investigate
```

Leave the REPL with `exit` (or `quit`, or Ctrl-C).

> **README caveat:** `README.md` is stale — it says `python3 test.py`, which is **not** the entrypoint. Use `./sentinel`.

---

## Reading the decision board

`investigate` renders a sequence of Rich panels. Here is what each one means.

### RECON panel

The discovered surface — facts only:

- **target** — the normalized target URL.
- **recon source** — `external_toolchain` (Subfinder/Httpx/Katana) or the builtin crawler fallback.
- **alive hosts** / **surface URLs** — hosts that responded and URLs crawled.
- **endpoints modeled** / **recon observations** — nodes materialized into the security graph.

### HYPOTHESES panel

- **total** — count of authorization hypotheses seeded, then a breakdown by kind (today: `authorization_candidate`).
- The footer states the core principle: *"Discovery is not a vulnerability. Each hypothesis is a justified reason to test authorization behaviour."*

### CYCLE NN · DECISION BOARD (one per cycle)

The heart of the tool. Each row:

- **action** — the research *capability* chosen this cycle (e.g. `authorization.candidate_check`). This is *what* Sentinel decided to do, not a result.
- **score** — the **deterministic frontier score** (0.000–1.000) of the chosen candidate. This is authoritative — it, not the AI, decides selection.
- **probing** — the concrete endpoint URL this cycle targets, recovered from the hypothesis.
- **outranked** — how many alternative candidates this choice beat.
- **ai advisor** — shown *only when the bounded LLM steered the pick* within a top-score tie. Displays `◈ steered`, a confidence, and a short reason. **This row is advisory-only** — provenance/telemetry, never authority. Most cycles will not show it.
- **http** — the response **status code** and execution status. Color reflects the range (2xx/3xx green, 4xx yellow, 5xx red) but **this is a fact, not a verdict.** An HTTP 200 is never a finding.
- **judge** — the deterministic authorization judge's verdict (`VALIDATED` / `DISPROVED` / `INCONCLUSIVE`) with a reason — shown *only if the judge ran*. In today's autonomous flow the judge does not fire, so this row typically does not appear (see **Roadmap**).

Below the rows:

- **rationale** (▹ bullets) — the "why this, why now": concatenated hypothesis-score reasons, applicability reasons, evaluation reasons, and novelty. This is what makes the loop auditable.
- **outranked:** — a glimpse of the *real endpoints* it chose between (up to three, then `+N more`).
- **↳ refined into N new hypothesis/hypotheses** — appears when a cycle spawns new hypotheses via refinement.

### CONFIRMED FINDINGS panel

A table (severity / title / confidence / status) of hypotheses that reached `CONFIRMED`. **Today, autonomous runs print instead:** *"No authorization findings were CONFIRMED in this run. Confirmation requires a reproduced authorization contradiction under the deterministic judge — never an HTTP status code alone."* That message is by design, not a crash.

### RESEARCH FRONTIER panel

The end-of-run outcome:

- **frontier phase** — `RESOLVED` / `ACTIVE` / `EXHAUSTED` / `MIXED` / `EMPTY`.
- **stopped** — why the loop ended (`frontier_exhausted` when diminishing returns drove all candidate value to zero, or `cycle_limit`).
- **active / exhausted / resolved** — hypothesis counts, plus reason bullets.

---

## Full command reference

All commands are entered at the `Sentinel > ` prompt. The command word is split from its argument once on whitespace.

| Command | Syntax | What it does |
|---|---|---|
| **investigate** | `investigate <target> [cycles]` | **Primary.** Runs the full autonomous authorization-research loop (recon → hypotheses → adaptive cycles → findings) and renders the decision board. `cycles` defaults to 10, clamped 1–100. Empty arg prints usage. |
| hunt | `hunt <target>` | Legacy recon+RAG pipeline. **Currently broken** (raises `NameError` in `core.py`); superseded by `investigate`. |
| findings | `findings` | Prints the in-memory findings of the session's `SentinelCore`. Empty unless a prior `hunt` populated it — `investigate` uses a separate graph and does not fill it. |
| search | `search <keyword>` | Full-text search of the local knowledge DB (table of ID / Title / Automation). |
| skill | `skill <id>` | Opens one knowledge "skill" by numeric id. |
| random | `random` | Prints one random knowledge skill. |
| list | `list` | Lists engagement directories under `./engagements` (creates the folder if missing). |
| config | `config` | Prints the parsed `config/config.yaml` settings (read-only). |
| resume | `resume <engagement>` | **Stub** — echoes its argument; does not restore state. |
| report | `report [name]` | **Stub** — echoes; does not open a report. |
| help | `help` | Prints the static command list. |
| exit / quit | `exit` | Leaves the REPL (handled directly in `main()`; Ctrl-C also exits). `quit` is an undocumented alias. |
| *(unknown)* | `<anything else>` | Prints `Unknown command: <cmd>` with no side effects. |

---

## The safety model

Sentinel is designed for **bounded, responsible autonomy**. The safety invariants are enforced in code, not just documented.

1. **Separation of find / reason / prove.** These are distinct capability callables — an independent `observe_fn` (facts), `judge_fn` (adjudication against explicit policy), and `planner`/`executor` (action). No single step can both act and adjudicate. The executor explicitly refuses to decide whether a response is a vulnerability (`execution/http.py`).
2. **An HTTP status is never a verdict.** Status codes are recorded as facts; observations conservatively map 2xx→allow, 401/403→deny, everything else→unknown — and even an "allow" is only an observation, not a finding. A hypothesis is `VALIDATED` only when observed behavior *contradicts an explicit graph policy* (`validation_core.py`), and a `SecurityFinding` materializes only from a `CONFIRMED` hypothesis (`analysis/findings.py`).
3. **The AI is caged.** The advisor is consulted only when ≥2 candidates share the exact top score. It picks by list index (mapped back to a real candidate id, so id hallucination is structurally impossible), any unknown id is discarded, it enters selection as a strict *secondary* sort key, and any failure falls back to deterministic order. Its confidence/reasoning are display-only telemetry that "never carry authority."
4. **Pre-connection scope guard.** Every probe is refused *before a socket opens* unless its scheme is `http`/`https`, its host is on the engagement allowlist (bound to the target), and its method is permitted. Sentinel only ever contacts the target it was told to investigate.
5. **Local, bounded, non-destructive.** Requests go through stdlib `urllib` with bounded timeouts; the AI call is bounded (`think=false`, `num_ctx=4096`, `num_predict=128`, short timeout). No destructive actions are taken.

---

## Troubleshooting

**Ollama unreachable / advisory step skipped.** The loop degrades gracefully — on any advisor failure it falls back to pure deterministic selection, so `investigate` still runs. To restore the tiebreak: confirm `ollama serve` is up, the model is pulled, and `OLLAMA_URL` is correct. Under WSL, re-check the host-gateway IP (it changes per reboot):

```bash
ip route | grep default
```

**Target down / connection refused.** `investigate` needs a live HTTP target. Confirm the fixture is running and reachable:

```bash
curl -I http://127.0.0.1:3000
```

If you point at a host not on the engagement scope, the executor refuses it before connecting — that is the scope guard working as intended.

**Slow first cycle.** The first `/api/chat` call loads the model into memory, and `qwen3:4b` on CPU is not instant. Latency is capped by `AI_ADVISORY_TIMEOUT` and `AI_ADVISORY_NUM_PREDICT`; on timeout the cycle proceeds deterministically. Lower `AI_ADVISORY_MAX_CANDIDATES` to shrink the prompt if needed.

**Model not found / pulls.** The advisory step requires `OLLAMA_MODEL` to be present in Ollama. Pull it before running:

```bash
ollama pull qwen3:4b
```

**"No findings were CONFIRMED."** This is expected today (see below), not an error — it reflects Sentinel's refusal to call an HTTP status a finding.

**Trying to run from Windows fails.** The `.venv` is Linux-native. Run under WSL/Linux via `./sentinel`.

---

## Roadmap / honest status

Sentinel today is a **polished, safe, deterministic find-and-rank engine with a real advisory-AI seam, atop a complete-but-dormant prove subsystem.**

**Working live, end-to-end (the *find* half):**

- Real recon → security-graph ingest → autonomous `authorization_candidate` hypotheses.
- Deterministic candidate scoring with transparent rationale and genuine diminishing-returns decay that terminates the frontier.
- A reachable, bounded AI advisory tiebreak (score stays authoritative).
- Scope-bounded, non-destructive HTTP execution recording facts only.

**Built but not yet reachable autonomously (the *reason/prove* half):**

- **No autonomous `CONFIRMED` finding is produced end-to-end today.** This is a *bootstrap gap*, not missing code.
- The candidate planner deliberately leaves `principal_id`/`resource_id`/`action`/`expected_outcome` empty, so the load-bearing `AuthorizationObservation` is never created → the deterministic judge never fires → no hypothesis reaches `CONFIRMED`.
- The judge, finding materialization, and prove/re-validation machinery are implemented and coherent, but gated behind hypothesis kinds (`authorization_policy_violation`) and policy edges that the autonomous flow never creates.

**Next milestones (in rough priority order):**

1. **Close the bootstrap gap** — seed principals + expected outcomes so structured authorization observations are created and the judge can run.
2. Wire differential / policy-violation hypotheses into the autonomous loop; register the currently-unregistered recheck executor (today a dry-run stub).
3. Multi-principal / differential authorization reasoning.
4. A remediation ("prove-then-patch") stage — explicitly absent today by design.
5. Multi-class support and bug-chaining (currently authorization-only).
6. Housekeeping: fix the broken legacy `hunt`, implement the `resume`/`report` stubs, and refresh the stale `README.md`.

Demo Sentinel as **autonomous, evidence-driven authorization research with bounded AI** — and present confirmed findings as the clearly-scoped next step, not a shipped capability.
