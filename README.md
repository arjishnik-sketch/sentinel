<p align="center">
  <img src="assets/brand/sentinel_logo_dark.png" alt="Sentinel — Autonomous Cyber-Reasoning" width="640">
</p>

# Sentinel

**Autonomous cyber-reasoning for live web targets — find → reason → prove → patch → prove.**

Sentinel points itself at a live HTTP(S) target, recons the surface, forms
conservative hypotheses, probes them under a strict scope guard, and lets a
**deterministic judge** decide every verdict. A finding crystallizes *only* when
that judge reproduces a contradiction against an operator-declared oracle — never
from a status code, never from the advisory LLM. For each confirmed finding it
then synthesizes a corrective control, enforces it on a live loopback shield, and
re-runs the *same* judge through it: `FIX PROVEN` is earned only on a real
`VALIDATED → DISPROVED` flip under enforcement.

It is local-first (Ollama `qwen3:4b`, no cloud), evidence-driven, and
target-agnostic — proven end-to-end on two independent live stacks (OWASP Juice
Shop and VAmPI).

## Vulnerability classes (all close the full loop live)

- **Broken access control** — `authorization_policy_violation`
- **Security-header posture** — `security_misconfiguration`
- **Insecure cookies** — `insecure_cookie` (missing `HttpOnly` / `Secure`, weak `SameSite`)

## Quick start

Run everything **under WSL / Linux** from the repo root:

```bash
python3.12 -m venv .venv && source .venv/bin/activate && pip install -e .
```

Start a target and an Ollama server, then launch the REPL:

```bash
./sentinel
```

At the `Sentinel > ` prompt:

```bash
investigate http://127.0.0.1:3000 12 samples/juice_shop_access_policy.json
```

## Login Tester (opt-in)

Turn anonymous scanning into **authenticated** reasoning. Sentinel drives a real
browser, you log in (MFA supported — it waits and auto-detects completion),
and it captures the session, then runs authenticated authorization probes plus
cookie-security analysis on the *real* session cookies:

```bash
pip install -e ".[login]" && python -m playwright install chromium
```

```bash
login http://127.0.0.1:3000
```

Credentials are read via `getpass`, held in memory for the run only, never
persisted or logged.

## Documentation

See **[USER_GUIDE.md](USER_GUIDE.md)** for the full guide: install, configure,
reading the decision board, the safety model, every command, and honest status.
