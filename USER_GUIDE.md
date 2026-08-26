<p align="center">
  <img src="assets/brand/sentinel_logo_dark.png" alt="Sentinel — Autonomous Authorization Research" width="720">
</p>

# Sentinel — User Guide

**Autonomous authorization research for live web targets — find → reason → prove → patch → prove, evidence-driven, with a bounded advisory AI.**

Sentinel points itself at a live HTTP target, recons the attack surface, forms conservative authorization hypotheses, and runs an adaptive research loop that ranks and probes them — showing every decision on an auditable "decision board." It is a local-first cyber-reasoning agent built for the AI Kavach challenge.

It closes the full find → reason → prove → patch → prove loop live across **five vulnerability classes** — broken access control (`authorization_policy_violation`), security-header posture (`security_misconfiguration`), insecure cookies (`insecure_cookie`), privilege escalation (`privilege_escalation`), and SQL injection (`injection`) — each adjudicated by its own **pure deterministic judge**. An opt-in **Login Tester** captures a real authenticated browser session (MFA-aware) so the same prove-chain can reason as the logged-in user. Every verdict traces to a judge reproducing a contradiction against an operator-declared oracle — never to a status code, never to the advisory LLM.

The engine holds **zero** target-specific knowledge: every class is driven only by operator-declared **data** (a policy oracle, a header/cookie baseline, a login matrix, an injection matrix) or a live-captured session. Point Sentinel at any stack and only that data changes — Juice Shop is the test fixture, not the product. Deployment-oriented, fill-in-the-blanks templates ship in `samples/` for every class.

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
investigate http://127.0.0.1:3000 12 samples/juice_shop_access_policy.json
```

Watch the decision board carry a live target through the full loop: recon → hypotheses → adaptive cycles → a `CONFIRMED` broken-access-control finding → a `FIX PROVEN` remediation (the shield denies the anonymous caller `403` under the same judge). Type `exit` to leave. Everything below explains each piece in depth.

Or point Sentinel at a URL with **no policy file at all** and let it discover the bugs:

```bash
discover http://127.0.0.1:3000
```

Discover mode runs header + cookie posture off the built-in secure baseline and **synthesizes the SQL-injection surface from live recon** (see [Zero-oracle discovery](#zero-oracle-discovery-discover-url)); every candidate is still gated by the same pure judge, so nothing is manufactured.

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
- Not a manufactured-verdict tool. A `CONFIRMED` finding requires the deterministic judge to reproduce a contradiction against an operator-declared policy, and a `FIX_PROVEN` remediation requires that *same* judge to flip to `DISPROVED` under live enforcement — never inferred from a status code.

---

## Requirements

- **Python 3.12+** (the code uses `str | None` unions and `datetime.UTC`).
- **A local Ollama server** with the `qwen3:4b` model pulled (used for the advisory tiebreak).
- **A live HTTP(S) target** to investigate (e.g. OWASP Juice Shop).
- **A shell.** The `./sentinel` launcher and the setup steps below assume Linux/WSL. To run on a **Windows host** (native PowerShell/Git Bash or WSL2), see the dedicated **[Running on Windows](#running-on-windows)** section — the app runs on Windows once you install Python 3.12 and enable UTF-8 mode. The repo's local `.venv` is Linux-native (POSIX layout) and gitignored, so Windows users create their own.
- Optional (legacy `hunt` pipeline only): the ProjectDiscovery Go binaries `subfinder`, `httpx`, `katana` on `PATH`. **Not needed for the primary `investigate` command.**
- Optional (**Login Tester** only): the `login` extra — `pip install -e ".[login]"` then `python -m playwright install chromium`. **Not needed for `investigate`;** the core install stays cloud-free and dependency-light.

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

> **Note:** the second argument is the cycle budget (default `10`, clamped `1..100`); the third is an optional access-policy oracle; a fourth optional arg is a source-repo directory for the root-cause patch.

---

## Running on Windows

The primary instructions above assume a Linux shell (the `./sentinel` launcher is a
bash script that sources `.venv/bin/activate`). On a Windows host you have two
supported paths.

### Path A — WSL2 (recommended)

The least-friction way to get the documented Linux behaviour on Windows:

1. Install WSL2 + Ubuntu (`wsl --install` in an elevated PowerShell, then reboot).
2. Open the Ubuntu shell and follow **Install → Configure → Run it** above verbatim —
   `./sentinel` works unchanged inside WSL.
3. Ollama: either run it on Windows bound to all interfaces
   (`OLLAMA_HOST=0.0.0.0 ollama serve`) and point `OLLAMA_URL` at the WSL host-gateway
   IP (see the WSL networking note under *Start the services*), or install Ollama
   **inside** WSL and use `http://127.0.0.1:11434`.

### Path B — native Windows (PowerShell / Git Bash)

**Prerequisites**

- **Python 3.12+ is required.** `pyproject.toml` pins `requires-python = ">=3.12"`, and
  four modules (`recon_engine.py`, `findings.py`, `engagement.py`, `memory.py`) import
  `datetime.UTC`, which only exists on Python 3.11+. On an older interpreter the REPL
  aborts at import with `ImportError: cannot import name 'UTC' from 'datetime'`, and
  `pip install -e .` refuses outright. Install 3.12 from
  [python.org](https://www.python.org/downloads/windows/) or `winget install Python.Python.3.12`,
  then invoke it as `py -3.12`.
- **Docker Desktop** for the Juice Shop fixture target.
- A shell: PowerShell or Git Bash (bundled with Git for Windows).

**Set up a Windows-native virtual environment.** The committed dev `.venv` is
Linux-native (`.venv/bin/…`) and gitignored — create your own; Windows venvs live under
`.venv\Scripts\` instead of `.venv/bin/`:

```bash
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1     # PowerShell   (Git Bash: source .venv/Scripts/activate)
pip install -e .
```

**Enable UTF-8 mode — this is the one Windows-specific gotcha.** Sentinel's Rich UI
draws box- and block-drawing characters. On the default Windows code page (cp1252) the
console raises `UnicodeEncodeError: 'charmap' codec can't encode character '▐'` the
moment it prints a panel. Turn on Python's UTF-8 mode before running:

```bash
$env:PYTHONUTF8 = "1"      # PowerShell (current session)
export PYTHONUTF8=1        # Git Bash  (current session)
```

Make it permanent with `setx PYTHONUTF8 1` (applies to new shells), and prefer
**Windows Terminal** (`chcp 65001`) over the legacy `conhost` console.

**Run it.** Because `./sentinel` activates a Linux venv, launch the module directly on
native Windows (this mirrors exactly what the launcher does — `python -m app.cli`):

```bash
python -m app.cli
```

…or the installed console script:

```bash
sentinel
```

Then use the commands exactly as documented elsewhere in this guide, e.g.:

```bash
investigate http://127.0.0.1:3000 12
```

```bash
autonomous http://127.0.0.1:3000
```

**Environment variables.** A `.env` file in the repo root works identically on Windows
(it is read by `python-dotenv`), so the *Configure* table above applies unchanged. To
drive the autonomous loop with a hosted model instead of local Ollama, set the provider
in the environment (or let the one-time `getpass` prompt collect the key):

```bash
$env:SENTINEL_LLM_PROVIDER = "anthropic"
$env:SENTINEL_LLM_MODEL    = "claude-opus-4-8"
$env:ANTHROPIC_API_KEY     = "sk-..."   # never commit this
```

Keys are read from the environment or a `getpass` prompt, held in memory only, and
never logged or written to disk.

**Tuning the autonomous pipeline (optional).** Two operator knobs shape the run
without ever weakening the contract — both default to *full coverage*:

```bash
$env:SENTINEL_ENDPOINT_BUDGET = "20"   # focus on the top-N most injectable endpoints
$env:SENTINEL_MAX_WORKERS     = "4"    # cap probe concurrency (gentler on a fragile target)
```

`SENTINEL_ENDPOINT_BUDGET` caps how many endpoints the *SELECT ENDPOINTS* stage keeps
after ranking them by injectability (params, resource ids, auth/api paths). Unset (or
`≤0`) = **rank-only, no pruning** — every endpoint is kept, just best-first; any pruning
is explicit and shown in the decision board. `SENTINEL_MAX_WORKERS` only *caps*
parallelism in the *PLAN EXECUTION* stage (never below 1, never above the real slot
count); it removes no work. Neither knob can confirm, drop, or manufacture a verdict —
the pure judges still dispose every hypothesis.

**Steering the run (you are a proposer, never a judge).** Between the plan and the
`EXECUTE + PROVE` stage the loop pauses at an **OPERATOR STEER** checkpoint so you can
add probes or hand it the auth context two matrix classes honestly need. Your steer is
folded exactly like an LLM or tool proposal — via `augment_plan`, re-ranked provable-first
— and the **same pure judge still disposes each one**. You can never confirm a finding.
The prompt only appears on a real TTY; it is silent in CI / headless runs and when
`$SENTINEL_ASSUME_YES` or `$SENTINEL_NO_STEER` is set. Non-interactively, pass the steer
through the environment:

```bash
$env:SENTINEL_STEER = "test sqli /rest/products/search q query HIGH
token eyJhbGciOi...             # a GENUINE captured bearer JWT (secret; never logged/echoed)
matrix ./access_policy.json"    # broken_auth / privesc oracle
$env:SENTINEL_NO_STEER = "1"    # force the checkpoint off even on a TTY
```

Steer grammar (one directive per line, verbs case-insensitive): `test <technique> <url|/path>
[param] [location] [severity]` adds a scope-guarded hypothesis (off-host suggestions are
reported as *ignored*, never probed); `token <bearer-jwt>` supplies a genuine session
token; `login <user> <pass> [login-url]` (or `creds <user>:<pass>`) hands Sentinel credentials
so it **logs in and captures the token itself** — no external driver; `login_url <url>` names
the login page; `matrix <path.json>` names a broken_auth/privesc oracle. A blank line / `go` /
`done` ends interactive input. Credentials and the captured token are secrets — held in memory
for the run only, **never logged, echoed, or written to disk** (the username, an identity, may
appear in a note; the password and token value never do).

**AUTH MATRIX (broken_auth / privilege_escalation).** These two classes are *matrix-driven*,
not single-probe, so they are deliberately absent from the wired single-probe judges and
prove in a **separate stage after EXECUTE**, gated on the context you steer in:

- **broken_auth** needs a forgery matrix (routes + strategy) **and a genuine session token**
  to forge from. You can hand one in (`token <jwt>` / `$SENTINEL_SESSION_TOKEN`) **or give
  Sentinel credentials and let it capture one itself**: with `login <user> <pass> [url]` (or
  `$SENTINEL_LOGIN_USERNAME` / `$SENTINEL_LOGIN_PASSWORD` / `$SENTINEL_LOGIN_URL`) Sentinel
  drives a headless HTTP form login, reads the session token from the **same location the
  matrix declares** (`token_location` — an `Authorization` header or a `session` cookie), and
  binds it as the sole authenticator. No token (and no working login) → **honestly skipped**
  (never a blind run that could manufacture a claim). The token is held in memory only and its
  value is **never logged, echoed, or placed in a note** — panels report only *captured* / *NO
  token*. For a **vertical** bypass a check may declare `forge_claims` (e.g.
  `{"sub": "administrator"}`) — the escalation target baked into the forged payload as operator
  ground truth; the pure judge still disposes the live three-probe differential, so a declared
  claim never fabricates a finding.
- **privilege_escalation** needs a ≥1-check matrix with declared principal headers, exactly
  as `investigate` consumes it.

**Optional impact demonstration (state-changing, doubly gated).** Proving the bypass is the
default; *demonstrating its concrete impact* — using the forged admin token to perform a real
privileged action (e.g. delete a user) — is an explicit opt-in. A broken_auth check may declare
an `impact` block naming only **intent** (`match` — a substring like `"delete"` — and `params`
that pick the object, e.g. `{"username": "carlos"}`); Sentinel then fetches the admin page the
bypass unlocked **with the forged token**, dynamically parses that live page for the matching
link/form (preferring the one already carrying every declared param value — the exact per-object
action), issues it with the forged token, and issues the **same action anonymously** as a
negative control. It never hardcodes a route. This is the one place the engine issues a real
state-changing request, so it fires **only** when the check declares `impact` **and** the
operator sets `$SENTINEL_ENABLE_IMPACT=1` **and** only after a `CONFIRMED` forgery — never for a
`DISPROVED`/`INCONCLUSIVE` one. The impact is itself a differential (the forged token performed
the action *and* an anonymous caller was denied it), the forged credential rides the request
**masked** in every report, and the declared params are ground truth, never a secret. (This is
exactly the PortSwigger "delete `carlos`" solve condition, so a lab flips to *solved* when the
demonstrated delete lands.)

Resolution precedence mirrors `investigate`: the dedicated `$SENTINEL_BROKEN_AUTH_POLICY` /
`$SENTINEL_PRIVESC_POLICY`, then the steer's `matrix <path>`, then the combined
`$SENTINEL_ACCESS_POLICY`; the token comes from the steer's `token` line or
`$SENTINEL_SESSION_TOKEN`, and **failing that**, from a live credential login when a
broken_auth matrix is present and credentials were supplied (an explicit token always wins, so
a live login is never driven needlessly). The stage **owns no verdict** — it runs the *same*
pure judges the `security_graph` classes already ship on a fresh graph and adapts each result
through the single `VALIDATED→CONFIRMED` site. A matrix `CONFIRMED` joins the same verdict pool
and renders with full steps-to-reproduce.

### Windows troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `UnicodeEncodeError: … '▐'` / `charmap codec` | legacy cp1252 console | `set PYTHONUTF8=1`; use Windows Terminal + `chcp 65001` |
| `ImportError: cannot import name 'UTC' from 'datetime'` | Python < 3.11 | install and use Python 3.12 (`py -3.12`) |
| `pip install -e .` refuses / version error | `requires-python >=3.12` | install Python 3.12 |
| `./sentinel`: *No such file* / bad interpreter | launcher is a Linux bash script (`.venv/bin/activate`) | run `python -m app.cli`, or use WSL2 (Path A) |
| Ollama connection refused | server not running / wrong URL | start `ollama serve`; native Windows → `OLLAMA_URL=http://127.0.0.1:11434` |

---

## The Login Tester (authenticated reasoning)

Anonymous scanning only sees the anonymous attack surface. The **Login Tester**
turns Sentinel into an *authenticated* reasoner: it captures a real logged-in
session — MFA and all — and then runs the exact same prove-chain **as the
logged-in user**. This is the enabler for the interesting bugs, because a real
session is what lets Sentinel reason about *authenticated* authorization and about
the *real* session cookies a target sets after login.

### Install the opt-in extra

Playwright is an **opt-in extra** so the core stays lightweight and cloud-free.
Install it once:

```bash
pip install -e ".[login]"
python -m playwright install chromium
```

Without the extra the `login` command still exists — it just prints an actionable
install hint and stops. Nothing about the core `investigate` path changes.

### What happens when you run `login`

```bash
login http://127.0.0.1:3000
```

1. **Credentials (safely).** Sentinel prompts for a username and reads the
   password with `getpass` (no echo). Credentials live in memory for the run
   only — they are **never written to disk and never logged**, and every probe
   stays scope-bound to the target host.
2. **A real browser opens.** Sentinel launches a visible Chromium, navigates to
   the login page (`login_url` if you gave one, else the target), and
   best-effort auto-fills the email/username and password fields. If the page
   uses selectors it can't guess, you simply log in yourself in the open window.
3. **MFA-aware wait (auto + manual).** Sentinel then waits for login to *finish*.
   It watches for two honest signals — a **session-like cookie** appearing, or the
   browser **leaving the login/auth/MFA path** — and, in parallel, lets you press
   **Enter** in the terminal as a manual "I'm done" fallback. First signal wins.
   This is how it handles MFA without guessing: you complete the second factor in
   the real browser, and Sentinel detects the transition.
4. **Session capture.** It reads `context.cookies()` (each cookie carries its
   *real* `httpOnly` / `secure` / `sameSite` flags) plus any bearer token in
   `localStorage`, and builds an in-memory `CapturedSession`.
5. **Authenticated reasoning.** Sentinel then runs its normal prove-chain over the
   captured identity (below), and the browser stays open until testing finishes
   (then closes) — or you close it yourself.

### What it reasons about — and the contract it keeps

The captured session feeds the **existing** prove-chain. It does **not** get a
special, weaker standard of proof:

- **Authenticated authorization.** If you supply an access-policy oracle, Sentinel
  merges the captured session's live headers (`Cookie`, optional `Authorization:
  Bearer …`) into the declared `authenticated` principal — **without rewriting a
  single operator decision or rule binding**. The operator still declares what the
  authenticated user *should* and *should not* reach; the Login Tester only
  supplies the real identity so the deterministic judge can test those rules as the
  logged-in user. No oracle ⇒ authenticated authz has nothing to prove and is
  honestly skipped.
- **Insecure cookies, grounded in observation.** Sentinel reconstructs the
  `Set-Cookie` line for each captured cookie **from the flags the browser actually
  observed** — it invents nothing. Those go through the *same* pure cookie judge
  (see below). A session cookie that really shipped without `HttpOnly`/`Secure`
  becomes a CONFIRMED `insecure_cookie` finding; a properly hardened one returns
  `DISPROVED` and no finding. The corrective fix is applied with the real
  `apply_cookie_mutations` primitive and re-judged — a genuine
  `VALIDATED → DISPROVED` flip.

### Chaining — honest today

When a run yields both a CONFIRMED `insecure_cookie` on the session and endpoints
reachable as that authenticated principal, Sentinel surfaces them together under
one **session context** as the *ingredients* of a chain (session captured →
weak session cookie → authenticated reach). It **does not** auto-compose a causal
attack narrative from them — full cross-class chaining stays the clearly labeled
frontier. Sentinel never manufactures a chain edge it did not prove.

---

## Insecure cookies (third vulnerability class)

`insecure_cookie` closes the same find → reason → prove → patch → prove loop as
broken access control and header posture, on the *same* seams — a session cookie
missing `HttpOnly`/`Secure` or carrying a dangerous `SameSite=None` is the classic
pivot for session theft and CSRF, and a prime chaining ingredient.

- **Oracle.** A `cookie_rules` array (in the access-policy file, or via
  `$SENTINEL_COOKIE_POLICY`) declares, per route, the expectations each
  `Set-Cookie` must satisfy: `must_have_flag` / `must_not_have_flag`
  (`HttpOnly` | `Secure`), and `samesite_must_equal` / `samesite_must_not_equal`.
  An empty `cookie_name` means "every `Set-Cookie` on this route."
- **Pure judge.** `judge_cookie_posture` re-parses the *observed* `Set-Cookie`
  headers on a fresh probe and decides each expectation deterministically. Absence
  of a `SameSite=None` is honestly **not** a violation of "must not equal None" —
  the judge only flags what the response actually carries.
- **PATCH + PROVE.** The loopback shield rewrites the forwarded `Set-Cookie`
  (`add_flag` / `remove_flag` / `set_samesite`); `FIX_PROVEN` is earned only when
  the same pure judge flips `VALIDATED → DISPROVED` through real enforcement.
- **Grounding.** Cookie expectations are only ever asserted against cookies a
  target actually set. The bundled sample oracles for Juice Shop and VAmPI
  **omit** `cookie_rules` on purpose: neither sets an anonymous/pre-login cookie,
  so manufacturing one would violate the contract. The class is exercised live via
  the **Login Tester** (real post-login `context.cookies()`) and by the offline
  test suite — honest, never guessed.

---

## Privilege escalation (fourth vulnerability class)

`privilege_escalation` finds the two escalation shapes that a role/ownership
model must forbid — **horizontal** (a user reaching another user's object:
IDOR / BOLA) and **vertical** (a plain user reaching an admin-only function) —
and closes the same find → reason → prove → patch → prove loop. It is the class
that most needs *real identities*, so it is driven either by tokens you declare
or by live sessions the Login Tester binds.

- **Oracle — a login matrix.** A `privesc_matrix` section (in the access-policy
  file, or a standalone file via `$SENTINEL_PRIVESC_POLICY`) declares
  `principals` — each with a `name`, `role`, real session `headers` (a bearer
  token and/or `Cookie` you are authorised to use), and a `control` request that
  reaches its **own** object — and `checks`, each a `horizontal` (with a
  `victim`) or `vertical` boundary the attacker principal MUST NOT cross, naming
  the forbidden `breach` request. The generic template is
  [`samples/privesc_matrix.example.json`](samples/privesc_matrix.example.json).
- **Pure judge — a three-probe differential.** For each check the deterministic
  judge fires *three* live probes: a **CONTROL** probe (attacker → its own
  object, which MUST succeed — proving the session is actually alive), a
  **BREACH** probe (attacker → the forbidden object/function), and an anonymous
  **BASELINE** probe (the same breach with **no** session). Escalation is
  `VALIDATED` **only** when control succeeds **and** breach is granted **and**
  the anonymous baseline is denied. That third probe is what stops a public
  route — or an app that `200`s everything — from ever being mistaken for a
  finding; a bare status code is never the verdict.
- **Identities from live logins.** Leave `headers` empty and the opt-in Login
  Tester binds real browser sessions to the declared principals **by index** at
  runtime — the identities then come from genuine logins, never from disk.
- **PATCH + PROVE.** The same loopback shield denies the attacker's cross-tenant
  / cross-role request; `FIX_PROVEN` is earned only when the same pure judge
  makes the full `VALIDATED → DISPROVED` flip under live enforcement (and each
  side re-fires its own anonymous baseline probe, so a shield can never take
  credit for a boundary that never reproduced pre-fix).

---

## SQL injection (fifth vulnerability class)

`injection` proves boolean-blind SQL injection with a **three-way boolean
differential** — never from an error string, a status code, or a reflected
payload. It closes the same find → reason → prove → patch → prove loop, with a
request-guard (WAF-style) virtual patch.

- **Oracle — an injection matrix.** An `injection_matrix` section (in the
  access-policy file, or a standalone file via `$SENTINEL_INJECTION_POLICY`)
  declares `checks`, each naming ONE request parameter (`param`) at a `location`
  (`query` / `body_form` / `body_json`) on a `method` + `path`, plus a benign
  `baseline_value` that returns a legitimate response. The declared parameter
  makes **no** security claim on its own — it only poses a question. The generic
  template is
  [`samples/injection_matrix.example.json`](samples/injection_matrix.example.json).
- **Pure judge — baseline / TRUE / FALSE.** The judge fires the benign baseline,
  then a ladder of **length-matched** `(TRUE, FALSE)` payload pairs that differ
  by a single character (`1` vs `2`) — so a reflected payload contributes
  identical bytes to both arms and cannot itself create a difference. Injection
  is `VALIDATED` only when some pair makes the response **track the injected
  boolean** (`TRUE ≠ FALSE`) **while one arm still reproduces the legitimate
  baseline** (the anchor). If every readable pair collapses (`TRUE == FALSE`),
  the judge returns `DISPROVED` and there is no finding — the injection analogue
  of a compliant control.
- **Target-agnostic payload ladder.** The ladder carries an *open-context*
  family and a *comment-terminated* (`-- -`) family that breaks out of a quoted
  string, closes 0/1/2 grouping parens, and comments away appended SQL — the
  common shape of a grouped `WHERE ((col LIKE '%<p>%' …) AND …)` query where the
  parameter may even be interpolated twice. Whichever paren depth keeps the
  injected query valid is the one that toggles the boolean; the wrong depths
  raise a backend error that collapses (`TRUE == FALSE`) rather than
  manufacturing a verdict. This is a generic SQL *shape*, not target logic — the
  `baseline_value` is the only target-specific datum, and it is operator ground
  truth, never an invented payload.
- **PATCH + PROVE.** The loopback shield runs a **request guard** that blocks the
  injection signature *before it reaches the upstream* (the boolean payloads
  collapse to a benign `TRUE == FALSE`) while still forwarding the legitimate
  baseline. `FIX_PROVEN` is earned only when the same pure judge flips
  `VALIDATED → DISPROVED` under that live enforcement; the durable fix the
  artifact recommends is a parameterised (bound) query.

---

## Zero-oracle discovery (`discover <url>`)

`discover <target>` is the answer to *"can Sentinel find bugs on its own, with
nothing but a URL?"* — **yes, honestly, for the classes whose ground truth is
internal**, and without weakening the no-manufacturing contract by a single
inch. It is the same engine as `investigate`, run in *discover mode*:

- **Header + cookie posture** already need no operator: they run off Sentinel's
  built-in **secure baseline**, so a bare URL proves those two classes as-is.
- **SQL injection is the flagship discoverable class.** Its ground truth is
  *internal* — the three-way boolean differential is *self-anchoring* (a benign
  baseline plus length-matched TRUE/FALSE pairs). The operator therefore never
  had to supply *intent*, only *where to look* — and reconnaissance observed that
  for us. In discover mode the injectable surface is **synthesized from live
  recon** by [`app/security_graph/injection/discover.py`](app/security_graph/injection/discover.py):
    - every query parameter recon actually saw (anchored to the value the app
      really served), **including API routes mined out of the target's own
      JavaScript** — e.g. an Angular/SPA call built from a template literal like
      `` `${host}/rest/products/search?q=${term}` `` is recovered and its `q`
      becomes a candidate, which is how discovery reaches a JSON API's real query
      surface; plus
    - a small, fixed, **target-agnostic** list of conventional query parameters
      (`q`, `query`, `search`, `id`, …) tried breadth-first across query-surface
      endpoints (`/rest`, `/api`, `search`, …), so an injectable parameter that
      never appears pre-populated in a link can still be surfaced.
- **The same pure judge decides every synthesized candidate.** A parameter the
  backend ignores collapses (`TRUE == FALSE`) → `DISPROVED` → no finding; a
  baseline that isn't a legitimate response → `INCONCLUSIVE` → no finding.
  Synthesis changes only *where to look*, never *how a verdict is reached* — the
  engine holds no target-specific knowledge; host, routes, and parameters are all
  discovered live.
- **CONFIRMED injections flow into the same gated PATCH + PROVE** (show proposed
  request-guard → take approval → prove `VALIDATED → DISPROVED`).

Authorization and privilege-escalation *intent* cannot be inferred from a bare
URL (who *should* be denied is a business fact, not an observable one), so those
classes still require a declared matrix — pass one to `investigate`. Their attack
surface is still surfaced by discover mode as honest research leads; they simply
never cross into a *finding* without a declared rule to contradict.

```
discover http://127.0.0.1:3000
```

Live against the Juice Shop fixture this surfaces and **CONFIRMS the `q`
parameter of `/rest/products/search`** (mined from the app's JavaScript, proven
by the differential, then `FIX_PROVEN` via the request-guard) alongside the
baseline header findings — with zero policy input, and every non-injectable
candidate honestly `DISPROVED` / `INCONCLUSIVE`.

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

A table (severity / title / confidence / status) of hypotheses that reached `CONFIRMED`. A finding appears **only** when the deterministic judge reproduces a contradiction between the live target and an operator-declared access policy. Without a policy oracle (or when the target honours the policy), autonomous runs print instead: *"No authorization findings were CONFIRMED in this run. Confirmation requires a reproduced authorization contradiction under the deterministic judge — never an HTTP status code alone."* That message is by design, not a crash.

### REMEDIATION · PATCH + PROVE panel (one per confirmed finding)

Shown after each class's findings table whenever at least one finding was
`CONFIRMED` (unless `$SENTINEL_SKIP_REMEDIATION` is set). Every class routes
through this same shield: broken access control denies the caller, header
posture rewrites response headers, insecure cookies rewrite `Set-Cookie`,
privilege escalation denies the cross-tenant/cross-role request, and injection
runs a request guard that blocks the payload upstream.

**Human-in-the-loop gate.** Before any patch is deployed, Sentinel **shows** the
proposed control and **asks for your approval** — the shield only stands up after
you confirm. Set `$SENTINEL_ASSUME_YES=1` to auto-approve for non-interactive /
CI runs; a non-TTY session without it declines cleanly rather than hanging. Only
after approval does Sentinel synthesize the corrective control, enforce it on a
live loopback shield, and re-run the *same* deterministic judge through it:

- **verdict** — `✔ FIX PROVEN` / `✘ FIX NOT PROVEN` / `— NOT APPLICABLE` / `✘ ERROR`.
- **control** — the derived rule, e.g. `MUST DENY anonymous → GET /api/Feedbacks`.
- **live prove** — the before/after re-probe through the enforcement shield: `before 200 VALIDATED → after 403 DISPROVED`. `FIX PROVEN` is reported *only* on that `VALIDATED → DISPROVED` flip under real enforcement.
- **artifacts** — the deployable configs rendered from the rule (`portable-json · nginx · envoy-rbac · caddy`).
- **source patch** — `GENERATED` / `ADVISORY` / `NOT_PROVIDED`, plus framework and file when a source repo was supplied.

The confirmed hypothesis and finding are structurally isolated during verification and are never mutated.

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
| **investigate** | `investigate <target> [cycles] [access_policy.json] [source_repo_dir]` | **Primary.** Runs the full autonomous find → reason → prove → patch → prove loop (recon → hypotheses → adaptive cycles → CONFIRMED findings → PATCH + PROVE remediation) across all five classes and renders the decision board. `cycles` defaults to 10, clamped 1–100. An `access_policy.json` (or `$SENTINEL_ACCESS_POLICY`) supplies the ground-truth oracle the judge needs; the *same* file may carry a `header_rules` section (posture), a `cookie_rules` section (insecure cookies), a `privesc_matrix` section (privilege escalation), and an `injection_matrix` section (SQL injection) — or each may be supplied independently via `$SENTINEL_HEADER_POLICY` / `$SENTINEL_COOKIE_POLICY` / `$SENTINEL_PRIVESC_POLICY` / `$SENTINEL_INJECTION_POLICY`. Any section that is absent is simply skipped (no manufactured target). An existing directory (or `$SENTINEL_SOURCE_ROOT`) enables the optional root-cause source patch. Set `$SENTINEL_SKIP_REMEDIATION=1` to skip the remediation stage, `$SENTINEL_ASSUME_YES=1` to auto-approve the human-in-the-loop remediation gate (non-interactive). Empty arg prints usage. |
| **discover** | `discover <target> [cycles]` | **Zero-oracle discovery — point Sentinel at a URL and it finds the bugs, no policy file.** Same engine as `investigate` in *discover mode*: header + cookie posture run off the built-in secure baseline, and the injectable surface for **SQL injection is SYNTHESIZED from live reconnaissance** — parameters observed on the surface (including API routes mined from the app's own JavaScript) plus a fixed, target-agnostic generic-parameter list on query-surface endpoints. Every synthesized candidate is still decided by the **same pure boolean-differential judge**, so nothing is manufactured: a parameter the backend ignores collapses (TRUE == FALSE) → DISPROVED → no finding. CONFIRMED injections flow into the same gated PATCH + PROVE. Authorization / privilege-escalation *intent* cannot be inferred from a bare URL, so those classes still need a declared matrix (pass one to `investigate`); their surface is still surfaced here as honest leads. See **Zero-oracle discovery** below. |
| **login** | `login <target> [login_url] [cycles] [access_policy.json]` | **Authenticated reasoning (opt-in).** Drives a real browser, prompts for credentials (`getpass`), waits for you to finish login/MFA, auto-detects completion, captures the session, then runs authenticated authorization probes **and** insecure-cookie analysis on the *real* captured session cookies — followed by PATCH + PROVE for anything CONFIRMED. Requires the opt-in extra (`pip install -e ".[login]"` + `python -m playwright install chromium`); without it the command prints an actionable install hint. Credentials are held in memory for the run only — never persisted, never logged. See **The Login Tester** below. |
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

**"No findings were CONFIRMED."** Not an error — it reflects Sentinel's refusal to call an HTTP status a finding. It happens when nothing the judge probed contradicted its ground truth: with an oracle, every declared expectation held; in `discover` mode, the synthesized injectable surface all collapsed to `DISPROVED` and the headers/cookies met the secure baseline. A clean target legitimately produces no findings.

**Trying to run from Windows fails.** The `.venv` is Linux-native. Run under WSL/Linux via `./sentinel`.

---

## Roadmap / honest status

Sentinel today is a **polished, safe, deterministic engine that closes the full find → reason → prove → patch → prove loop live**, with a real advisory-AI seam that never holds authority.

**Working live, end-to-end (the *find* half):**

- Real recon → security-graph ingest → autonomous `authorization_candidate` hypotheses.
- Deterministic candidate scoring with transparent rationale and genuine diminishing-returns decay that terminates the frontier.
- A reachable, bounded AI advisory tiebreak (score stays authoritative).
- Scope-bounded, non-destructive HTTP execution recording facts only.

**Working live, end-to-end (the *reason / prove* half):**

- An operator-supplied **access-policy oracle** (external ground truth, like an API authorization matrix) seeds `authorization_policy_violation` hypotheses with the principals, resources, actions, and expected outcomes the judge needs.
- The autonomous loop probes the live target, builds a structured `AuthorizationObservation`, and the **deterministic judge fires**: a `CONFIRMED` finding is materialized *only* when observed behaviour contradicts the declared policy (proven live vs Juice Shop: `GET /api/Feedbacks` → `200`/`VALIDATED` → `CONFIRMED`; `GET /api/Users` → `401`/`DISPROVED` → **no finding**, demonstrating Sentinel never manufactures a verdict).

**A second vulnerability class — security-header posture — closes the same loop:**

- The same operator file may carry a `header_rules` section (or `$SENTINEL_HEADER_POLICY`) declaring, per route, the browser-level protections an endpoint MUST ship (`must_present` / `must_absent` / `must_equal` / `must_not_equal`). These seed `security_misconfiguration` hypotheses that a **separate pure judge** (`judge_header_posture`) decides by freshly re-probing the live response headers — a compliant header returns `DISPROVED` and **no finding**.
- PATCH + PROVE reuses the *same* loopback shield, now rewriting the forwarded response headers (`set` / `remove` / `remove_if_equals`). `FIX_PROVEN` is earned only when that same pure judge flips `VALIDATED → DISPROVED` under real enforcement. The shield never stamps its own identity onto the response, so even a "strip the `Server` header" fix proves out honestly.

**A third vulnerability class — insecure cookies — closes the same loop:**

- A `cookie_rules` section (or `$SENTINEL_COOKIE_POLICY`) declares, per route, the
  hardening each `Set-Cookie` MUST satisfy (`must_have_flag` / `must_not_have_flag`
  for `HttpOnly`/`Secure`; `samesite_must_equal` / `samesite_must_not_equal`).
  These seed `insecure_cookie` hypotheses that a **third pure judge**
  (`judge_cookie_posture`) decides by re-parsing the observed `Set-Cookie` headers;
  a hardened cookie returns `DISPROVED` and no finding.
- PATCH + PROVE reuses the *same* loopback shield, now rewriting the forwarded
  `Set-Cookie` (`add_flag` / `remove_flag` / `set_samesite`). `FIX_PROVEN` is
  earned only on a `VALIDATED → DISPROVED` flip under real enforcement. Cookie
  expectations are grounded in observed `Set-Cookie` behaviour, never guessed —
  see **Insecure cookies** and **The Login Tester** above.

**A fourth vulnerability class — privilege escalation — closes the same loop:**

- A `privesc_matrix` section (or `$SENTINEL_PRIVESC_POLICY`) declares principals
  (each with real session `headers` and a `control` reaching its own object) and
  horizontal/vertical `checks`. A **fourth pure judge** fires a three-probe
  differential — control (attacker → own object, MUST succeed), breach (attacker
  → forbidden object/function), and an anonymous baseline (same breach with no
  session) — and `VALIDATED`s escalation **only** when control succeeds, breach
  is granted, and the anonymous baseline is denied. That anonymous probe rules
  out the public-route / "app 200s everything" confound, so a bare status code is
  never the verdict.
- PATCH + PROVE reuses the *same* loopback shield to deny the cross-tenant /
  cross-role request; `FIX_PROVEN` requires the full `VALIDATED → DISPROVED` flip
  under real enforcement, with each side re-firing its own anonymous baseline.
  Identities may be declared as tokens or bound from live Login-Tester sessions
  **by index**. See **Privilege escalation** above.

**A fifth vulnerability class — SQL injection — closes the same loop:**

- An `injection_matrix` section (or `$SENTINEL_INJECTION_POLICY`) names one
  request parameter and a benign `baseline_value`. A **fifth pure judge** runs a
  three-way boolean differential (baseline / length-matched TRUE / length-matched
  FALSE) and `VALIDATED`s injection **only** when a pair makes the response track
  the injected boolean (`TRUE ≠ FALSE`) while one arm still reproduces the
  legitimate baseline; every pair collapsing (`TRUE == FALSE`) returns
  `DISPROVED` / no finding. A target-agnostic payload ladder (open-context +
  comment-terminated `-- -` families) covers grouped `WHERE ((col LIKE …))` shapes
  incl. double interpolation — a generic SQL shape, not target logic.
- PATCH + PROVE reuses the *same* loopback shield as a **request guard** that
  blocks the injection signature upstream (the boolean arms collapse) while
  forwarding the legitimate baseline; `FIX_PROVEN` requires the pure judge to flip
  `VALIDATED → DISPROVED` under that live enforcement. Proven live vs Juice Shop:
  `q` on `/rest/products/search` (grouped double-interpolated `LIKE` query) →
  `CONFIRMED` → `FIX_PROVEN`; the parameterised `name` filter on `/api/Products`
  → every pair collapses → `DISPROVED`/no finding (the compliant control). See
  **SQL injection** above.

**Authenticated reasoning — the Login Tester:**

- An opt-in browser session (Playwright extra) captures a real logged-in identity,
  MFA and all, and feeds it into the *same* prove-chain: authenticated
  authorization (live session headers merged into the declared `authenticated`
  principal, no operator decision rewritten) plus insecure-cookie analysis on the
  *real* captured session cookies. Credentials are never persisted or logged.

**Zero-oracle discovery — URL-only, no operator file:**

- `discover <url>` runs the *same* engine with **no policy input at all**. Header
  and cookie posture run off the built-in secure `baseline.py`; the SQL-injection
  surface is **synthesized from live recon** (`injection/discover.py`) — observed
  query parameters (including API routes mined from the app's own JavaScript, with
  template-literal `${…}` interpolation collapsed to recover the static path) plus
  a fixed, target-agnostic generic-parameter list tried breadth-first across query
  surfaces. Every synthesized candidate is still gated by the *same* pure boolean
  differential judge, so a parameter that does not track the injected boolean
  collapses to `DISPROVED`/no finding — discovery decides only *where to look*,
  never the verdict. Proven live vs Juice Shop with a bare URL: `q` on
  `/rest/products/search` `CONFIRMED` → `FIX_PROVEN`, alongside baseline header
  findings, with every non-injectable candidate honestly `DISPROVED`/`INCONCLUSIVE`.
  Authorization / privilege-escalation still need intent (a policy can't be
  inferred from a URL), so discover mode surfaces those as honest research leads.
  See **Zero-oracle discovery** above.

**Validation — a deterministic, network-free test suite:**

- **136** tests cover the five pure judges, the seeders, the enforcer's mutation
  primitives (header / cookie rewrite, access-control denial, request-guard SQLi
  block), full offline FIND→CONFIRM→FIX_PROVEN flows with isolation checks
  across all five classes, and **zero-oracle discovery** (injectable-surface
  synthesis from live recon, plus JS route mining with template-literal recovery)
  — all gated by the *same* pure judges (plus a live headless-browser capture gated
  behind an env var). They run with **no network** — every verdict is reproduced by
  the pure judge against a canned oracle — so the epistemic contract itself is
  regression-tested. The full offline suite is `482 passed, 1 skipped` by
  default (network-free; the live tier below is deselected).

**Live CI harness — the SQLi wins, reproducible on demand:**

- The hand-run injection wins against Juice Shop and VAmPI are promoted to a
  gated, automated tier under `tests/live/`. Each test proves one win end-to-end
  with nothing mocked: the pure differential judge re-probes the live target and
  returns `VALIDATED`, then `remediate_injection_findings` stands a real loopback
  enforcement shield in front of the target and the *same* judge flips
  `VALIDATED → DISPROVED` (`FIX_PROVEN`). Three surfaces are covered: Juice Shop
  product-search `q` (query, quote-parity error-based), VAmPI `/users/v1/{username}`
  (path-segment), and Juice Shop `/rest/user/login` `email` (JSON body, auth-bypass
  with a `401` baseline anchor).
- These are **gated `live`** and **deselected by default** (`addopts = -m 'not
  live'`) — a plain `pytest` stays fully hermetic. Requesting a live-target
  fixture auto-marks the test `live`, so a network test can never leak into the
  offline run. Stand the targets up and run the tier:

  ```bash
  docker compose up -d           # Juice Shop :3000 + VAmPI :5001 (intentionally vulnerable)
  pytest -m live                 # an unreachable target SKIPS cleanly, never errors
  ```

  The same `docker-compose.yml` backs the GitHub Actions job in
  `.github/workflows/live.yml` (compose up → wait for both → seed VAmPI's DB →
  `pytest -m live`), so the wins are CI-defensible, not one-off demos.

**Target-agnostic — proven on two independent live targets:**

- The engine carries no target-specific knowledge: the oracle is the only ground truth. Proven end-to-end against both **OWASP Juice Shop** (Node) and **VAmPI** (Flask) — different stacks, different routes, same engine. On VAmPI: `GET /users/v1/_debug` (leaks every user + plaintext password) → `CONFIRMED` → `FIX_PROVEN`; an anonymous `DELETE` correctly rejected `401` → `DISPROVED`/no finding; CSP + `X-Content-Type-Options` absent and a leaked `Server: Werkzeug/…` header → 3 `CONFIRMED` posture findings, all `FIX_PROVEN`; a compliant CORS control → `DISPROVED`/no finding.

**Working live, end-to-end (the *patch → prove* half):**

- For each `CONFIRMED` finding — in any of the five classes — Sentinel first
  **shows the proposed control and takes your approval** (the human-in-the-loop
  gate; `$SENTINEL_ASSUME_YES=1` auto-approves for CI), then synthesizes a
  provider-agnostic **enforcement shield**, renders deployable artifacts (nginx /
  Envoy RBAC / Caddy / portable JSON), stands the rule up on a live loopback
  reverse proxy, and **re-runs the same deterministic judge through it**. The one
  shield carries every primitive: access-control denial, response-header rewrite,
  `Set-Cookie` rewrite, cross-tenant/cross-role denial, and an upstream
  request-guard that blocks a SQLi signature.
- `FIX_PROVEN` is reported *only* when that judge flips `VALIDATED → DISPROVED` under real enforcement; anything else is `FIX_FAILED` / `NOT_APPLICABLE` / `ERROR`. The confirmed hypothesis and finding are structurally isolated and never mutated by verification.
- **URL-only by default** (no source code required — the shield *is* the deployable fix). When the target's source repository is also supplied (positional dir arg or `$SENTINEL_SOURCE_ROOT`), Sentinel additionally emits a root-cause unified-diff authorization guard; its live proof needs the operator's own rebuild.

**Next milestones (in rough priority order):**

1. **Bug-chaining across classes** — auto-compose proven findings from two
   classes (e.g. a weak session cookie + an endpoint reachable as that
   authenticated principal, or a privilege-escalation boundary + an injectable
   parameter behind it) into a single causal attack narrative. Five independent
   classes now close the loop live, and the **Login Tester already assembles the
   *ingredients* of a chain** for one session, surfaced together under one session
   context. Auto-composing the causal narrative from those ingredients is the
   honest remaining frontier and is deliberately *not* manufactured today.
2. Extend zero-oracle discovery beyond the self-grounding classes — infer
   authorization / privilege-escalation *intent* from live differential signals
   (not only the declared oracle), so `discover <url>` can raise those classes too
   without an operator file. Injection already discovers its full surface live; the
   header/cookie baseline runs zero-config; authz/privesc remain the honest
   frontier because intent cannot yet be inferred from a URL alone.
3. Housekeeping: fix the broken legacy `hunt` and implement the `resume`/`report` stubs. (The `README.md` points at `./sentinel` and this guide.)

Demo Sentinel as **autonomous, evidence-driven authorization research with bounded AI that closes the full find → prove → patch → prove loop live** — every verdict traceable to the deterministic judge, never to a status code or the LLM.
