# Sentinel — Master Roadmap: the Autonomous Web Pentester

> **This is the canonical reference document for finishing Sentinel.**
> **Part I** (§0–§9) is the proof-carrying core: 12 vulnerability classes + provable
> chaining, all shipped. **Part II** (§10–§14) is the standing mandate — turning that
> core into a dynamic, tool-wielding, LLM-driven autonomous pentester (taxonomy, tool
> selector, deepened skills KB, and the smart recon→report pipeline). Every item —
> old and new — preserves the hard epistemic contract (§1) that makes Sentinel
> defensible. Build against this file; update it as work lands.

**Status legend:** ✅ done & committed · 🔨 planned (spec below) · 🧭 frontier (labeled, not manufactured)

---

## 0. Where we are

| # | Class | Kind | Severity | Discovery | Status |
|---|-------|------|----------|-----------|--------|
| 1 | Broken access control | `authorization_policy_violation` | HIGH | oracle-required | ✅ |
| 2 | Security-header posture | `security_misconfiguration` | MEDIUM | zero-config baseline | ✅ |
| 3 | Insecure cookies | `insecure_cookie` | MEDIUM | zero-config baseline | ✅ |
| 4 | Privilege escalation | `privilege_escalation` | HIGH | oracle/login-required | ✅ |
| 5 | SQL injection | `injection` | HIGH | **zero-oracle (synth)** | ✅ |
| 6 | Template injection (SSTI) | `template_injection` | HIGH | **zero-oracle** | ✅ |
| 7 | Cross-site scripting (XSS) | `xss` | HIGH | **zero-oracle** | ✅ |
| 8 | Path traversal / LFI | `path_traversal` | HIGH | **zero-oracle** | ✅ |
| 9 | Open redirect | `open_redirect` | MEDIUM | **zero-oracle** | ✅ |
| 10 | CORS misconfiguration | `cors_misconfig` | MEDIUM | **zero-config baseline** | ✅ |
| 11 | Server-side request forgery | `ssrf` | HIGH | **zero-oracle (OOB)** | ✅ |
| 12 | Broken auth / JWT | `broken_auth` | HIGH | hybrid (login-seeded) | ✅ |
| ★ | **Provable chaining** | `chain` | — | artifact-driven | ✅ |

Five classes close the full **find → reason → prove → patch → prove** loop live.
The seven below mirror the same proven seams. Six of seven are *self-grounding*
(zero-oracle discoverable) — each one extends the "point at a URL" story, which is
the compounding value. Chaining is the apex.

---

## 1. The invariant contract (every class obeys this — no exceptions)

A class that violates any of these is worse than a class that does not exist,
because it manufactures a verdict. This is the whole moat.

1. **A finding requires the *pure* deterministic judge to reproduce a
   contradiction.** `judge_X(graph, *, hypothesis, ...) -> ValidationJudgment`
   is a pure function of graph state — no network, no scoring, no mutation, no
   target knowledge. A `SecurityFinding` materializes *only* from a `CONFIRMED`
   hypothesis (`analysis/findings.py`).
2. **A bare HTTP status is never the verdict.** Every class proves via a
   *differential* with an *anchor*: some probe must reproduce a legitimate
   baseline, so the signal is tied to real behaviour, not to one status code or
   one error page. (Injection: one boolean arm reproduces the benign baseline.
   Privesc: control succeeds + anonymous baseline denied. New classes below each
   name their anchor explicitly.)
3. **`FIX_PROVEN` requires the SAME pure judge to flip `VALIDATED → DISPROVED`**
   under live enforcement, on a *scratch graph seeded with relationships only*.
   `proven = (before == "VALIDATED" and after == "DISPROVED")`. Never gate on
   `after == DISPROVED` alone — a shield must not take credit for a boundary that
   never reproduced pre-fix. The confirmed hypothesis/finding is structurally
   isolated and never mutated by verification.
4. **The AI is advisory-only** — a bounded tiebreak that never carries authority
   and never manufactures findings, verdicts, or evidence.
5. **A compliant / inert control → DISPROVED → no finding.** Every class ships a
   negative control in its samples and tests (the injection analogue of a
   parameterised filter that collapses).
6. **The engine holds zero target-specific knowledge.** Target host, routes,
   params, payloads-as-shapes arrive as DATA, live-observed surface, or generic
   target-agnostic ladders. Never hard-code a target's routes.
7. **Bounded, non-destructive, scope-guarded.** Every probe refused before a
   socket opens unless scheme∈{http,https}, host on the engagement allowlist, and
   method permitted. Credentials via `getpass`, in-memory only, never logged.

---

## 2. The mirror-template package (the seams every new class implements)

Each class is a sibling package under `app/security_graph/<class>/`, mirroring the
proven `injection/`, `posture/`, `cookies/`, `privesc/` packages. Copy the closest
existing package and change only the class-specific logic.

```
app/security_graph/<class>/
  <class>_policy.py   # dataclasses + parse_<class>_policy(payload) / load_<class>_policy(path)
  seed.py             # seed_<class>_hypotheses(graph, policy, *, target_base): emits
                      #   Relationship(relation="requires_no_<class>", target="<class>:<aspect>",
                      #     metadata=(method,path,param,...,severity,source)),
                      #   declaration Evidence(mode="<class>_declaration"),
                      #   declaration Experiment(kind="<class>_declaration"),
                      #   OPEN Hypothesis(kind="<class>",
                      #     identity=HypothesisIdentity(kind, principal_id, resource_id, action=aspect))
                      #   idempotent via find_equivalent_hypothesis
  executor.py         # <Class>ProbeExecutor(HttpAuthorizationExecutor); kind="<class>_check"; no new logic
  judge.py            # PURE judge_<class>(graph, *, hypothesis, ...experiment_ids) -> ValidationJudgment
  run.py              # investigate_<class>(graph, executor=None) + run_<class>_investigation(
                      #   graph, policy, *, target_base, executor=None); reuses
                      #   add_validation_judgment + apply_validation_judgment +
                      #   materialize_confirmed_findings (all kind-agnostic, unchanged)
  discover.py         # (self-grounding classes) synthesize_<class>_policy(graph, ...) -> <Class>Discovery
  remediation.py      # synthesize_<class>_remediation / render_<class>_artifacts /
                      #   verify_<class>_remediation / remediate_<class>_and_prove / remediate_<class>_findings
  __init__.py         # re-exports
```

Then wire the three shared touch-points:
- `analysis/findings.py` → add `"<class>": "<SEVERITY>"` to `_SEVERITY_BY_KIND`.
- `orchestration/target.py` → register `<Class>ProbeExecutor` in `_default_executors`.
- `app/commands/investigate_cmd.py` → a matrix/findings/remediation panel section
  mirroring the injection block, behind the human-in-the-loop remediation gate
  (`app/commands/remediation_gate.py`; `SENTINEL_ASSUME_YES=1` for CI); and, for
  self-grounding classes, a `discover_mode` synthesis hook.

**Graph primitives available** (`models.py`): `Hypothesis`, `HypothesisIdentity`,
`Relationship(source, relation, target, metadata)`, `Evidence(id, source, data)`,
`Experiment(kind, request, evidence_ids)`, `ValidationJudgment(status,
contradiction_kind, expected, observed, evidence_ids)`, `SecurityFinding`.

**The enforcement shield** (`remediation/enforcer.py`) already carries these
provider-agnostic primitives — reuse before inventing:
- `AccessControlRule` + `evaluate_request` → deny a request by principal/route.
- `ResponseHeaderRule` + `apply_header_mutations` → `set` / `remove` /
  `remove_if_equals` a response header (used by posture; reused by CORS below).
- `CookieAttributeRule` + `apply_cookie_mutations` → `add_flag` / `remove_flag` /
  `set_samesite` on `Set-Cookie`.
- `RequestGuardRule` + `evaluate_request_guard` → refuse to forward a request whose
  `param` (in `query` / `body_form` / `body_json`) matches a **signature family**.
  Today only `_SQLI_SIGNATURES`. **Generalize this** to carry a pluggable family
  (`sqli`, `ssti`, `xss`, `traversal`, `url_allowlist`, `jwt`) — one guard, many
  classes. This is the single highest-leverage refactor for the new classes.

---

## 3. Two families — and why we prioritise self-grounding

**Self-grounding (zero-oracle):** the ground truth is *internal* to the probe.
A randomised marker either does something only a vulnerability could cause, or it
does not. The operator supplies nothing — recon supplies *where to look*, and the
pure judge decides. These extend the "point at a URL" flagship pitch. Injection is
the archetype; classes 6–11 all belong here.

**Intent-required:** the ground truth is *external* — "user A must not reach B",
"field X is privileged". This cannot be inferred from a URL. Authz, privesc, and
(mostly) broken-auth live here; they surface as honest research leads in
`discover` mode and confirm only with an operator oracle or a captured session.

> **Selection rule for all future work:** prefer self-grounding classes. Each one
> turns "URL-only discovery" from a one-off into a *repeatable pattern*, and that
> pattern is the million-dollar story — *a discovery engine where every new class
> inherits the proof contract for free.*

---

## 4. The seven new classes

Each spec gives: **what**, **why it fits the contract**, the **pure-judge
mechanism + anchor** (the honesty core), **zero-oracle discovery**, the
**PATCH + PROVE** control, **severity**, and **honest limits**.

### Class 6 — Template injection · `template_injection` · HIGH · zero-oracle

- **What.** User input evaluated by a server-side template engine (Jinja2, Twig,
  Freemarker, ERB, Velocity…) → arbitrary expression evaluation, often RCE.
- **Why it fits.** The cleanest self-grounding signal after boolean SQLi:
  arithmetic that only an evaluator produces.
- **Pure-judge mechanism + anchor.** Pick two random operands `a`, `b`. Send the
  payload in template syntaxes (`{{a*b}}`, `${a*b}`, `#{a*b}`, `<%= a*b %>`), and
  a **control** probe carrying the *literal string* `a*b` in a non-template
  position. `VALIDATED` only when the response contains the **computed product
  `a*b`** AND does **not** contain the literal `"a*b"`, AND the control probe does
  **not** yield the product. The control is the anchor: it proves the app merely
  *reflects*, so a product appearing only under template syntax can come only from
  evaluation. Randomised operands make coincidental matches vanishing.
- **Zero-oracle discovery.** `synthesize_template_injection_policy(graph)` draws
  reflected/observed params (same surface source as `injection/discover.py`) +
  the generic-param list. A param must reflect to be a candidate; non-reflecting
  params collapse to DISPROVED cheaply.
- **PATCH + PROVE.** `RequestGuardRule` with the new `ssti` signature family
  (`{{`, `${`, `#{`, `<%`, `%>`, `{%`) → template metacharacters never reach the
  evaluator → product absent → judge flips to `DISPROVED`. Durable fix (documented
  in the artifact): never render user input as a template; use a logic-less engine.
- **Limits.** Blind SSTI (no reflected output) needs an OOB/timing channel — defer
  to the SSRF OOB collaborator; label as frontier.

### Class 7 — Cross-site scripting · `xss` · HIGH · zero-oracle (reflected) + browser (DOM/stored)

- **What.** User input returned into an HTML/JS context without contextual
  encoding → attacker script runs in the victim's origin.
- **Why it fits.** Reflected XSS is self-grounding: a randomised marker with
  context-breaking metacharacters either survives *unescaped in an executable
  position* or it does not. No operator intent required.
- **Pure-judge mechanism + anchor.** Emit a nonce marker wrapped in each of a
  small ladder of breakout shapes (`"><svg/onload=…{nonce}>`, `';{nonce}//`,
  `</script>{nonce}`, attribute-break `" {nonce}=x`). The **anchor control** sends
  the SAME nonce entity-encoded / in a known-safe position. `VALIDATED` only when
  the breakout marker appears with its **metacharacters intact in a
  markup-executable context** (raw `<`,`>`,`"` unescaped around the nonce) AND the
  encoded control shows the app *does* reflect but *does* encode. The judge parses
  the reflection position, it does not merely substring-match the nonce — a nonce
  echoed inside a text node with `&lt;` encoding is DISPROVED. Randomised nonce
  rules out coincidence and lets stored/second-order hits be attributed.
- **Zero-oracle discovery.** Same reflected-param surface as SSTI/SQLi from recon;
  a param must reflect the nonce at all to be a candidate.
- **DOM / stored (opt-in browser).** Where the sink is client-side or persisted,
  the reflected substring test is insufficient. Reuse the **opt-in Playwright**
  path (already used by the login tester): navigate, install a `window`
  execution-sentinel (`window.__sentinel_xss(nonce)`), submit the marker, and
  `VALIDATED` only when the sentinel *fires with the matching nonce* — real
  execution, observed, never inferred. Absent Playwright → reflected-only, DOM/
  stored labeled frontier (graceful degradation, honest).
- **PATCH + PROVE.** `RequestGuardRule` `xss` family on the breakout shape blocks
  the payload → marker cannot reach the sink unescaped → judge flips `DISPROVED`.
  Durable fix in the artifact: contextual output encoding + CSP, never input
  blocklisting as the primary control (documented as defense-in-depth only).
- **Limits.** The request-guard is a virtual patch (WAF-grade), explicitly framed
  as such; the durable remediation is encoding. Mutation/polyglot evasion of the
  guard is acknowledged — the guard *proves the boundary is enforceable*, it is
  not sold as complete.

### Class 8 — Path traversal / LFI · `path_traversal` · HIGH · zero-oracle

- **What.** User input flows into a filesystem path → `../` sequences escape the
  intended directory and read arbitrary files (or include them).
- **Why it fits.** Strongest self-grounding signal of all: a leaked OS file has an
  **invariant signature** that cannot appear by coincidence. No operator, no
  intent — the file either leaks or it does not.
- **Pure-judge mechanism + anchor.** Ladder of traversal payloads targeting
  cross-OS canaries: `../../../../etc/passwd`, `..\..\..\..\windows\win.ini`, plus
  URL-encoded (`%2e%2e%2f`) and double-encoded variants. `VALIDATED` only when the
  response body contains an **OS-file invariant regex** — `root:.*:0:0:` for
  `/etc/passwd`, `[fonts]`/`[extensions]` for `win.ini` — that a normal app
  response could never contain. The **anchor control** requests a benign
  in-directory filename (or the raw param value with no traversal) and must return
  a *legitimate* success without the invariant — proving the endpoint really
  serves files, so the canary signature is attributable to escape, not to an error
  page that happens to mention "root".
- **Zero-oracle discovery.** Recon surface for params that look file-ish
  (`file`, `path`, `page`, `template`, `doc`, `download`, `include` — a generic,
  target-agnostic ladder) plus any observed param whose value resembles a path or
  filename. Non-file params return no canary → DISPROVED cheaply.
- **PATCH + PROVE.** `RequestGuardRule` `traversal` family (`../`, `..\`, encoded
  variants, absolute-path and null-byte markers) → traversal sequence refused →
  canary absent → judge flips `DISPROVED`. Durable fix: canonicalize then confirm
  the resolved path stays within an allowlisted root (documented).
- **Limits.** Files without a stable invariant signature (arbitrary app source)
  can't be proven by canary alone — only the known-canary hit is CONFIRMED; other
  reads surface as leads. Honest and bounded.

### Class 9 — Open redirect · `open_redirect` · MEDIUM · zero-oracle

- **What.** A redirect parameter (`next`, `url`, `redirect`, `return`, `dest`,
  `continue`) is honoured without an origin check → the app bounces the victim to
  an attacker-controlled host (phishing pivot, OAuth token theft enabler).
- **Why it fits.** Self-grounding: put a **randomised sentinel host** in the param
  and see whether the app's own `Location` (or meta-refresh / JS redirect) points
  off-origin to *that exact host*. Only a missing origin check produces this.
- **Pure-judge mechanism + anchor.** Two probes. Off-origin probe: param =
  `https://sentinel-<nonce>.example/` → `VALIDATED` when the response `Location`
  header (or `<meta http-equiv=refresh>` / `window.location`) resolves to the
  attacker host with the nonce. **Anchor control**: param = a *same-origin* path on
  the target → must redirect successfully **on-origin**, proving the redirect
  machinery works and is being exercised, so the off-origin bounce is a real
  policy gap and not a dead param. Nonce host rules out coincidental `Location`s.
- **Zero-oracle discovery.** Recon params matching the generic redirect-param
  ladder, plus any observed param whose value already looks like a URL or path.
- **PATCH + PROVE.** Reuse the response side: a new `ResponseHeaderRule`-style
  `remove_if_offorigin` on `Location` (or the request-guard `url_allowlist`
  family) → off-origin `Location` stripped/rewritten to a safe default → judge
  flips `DISPROVED`, while the same-origin control still succeeds. Durable fix:
  allowlist redirect targets / use relative paths only (documented).
- **Limits.** Redirects gated behind auth or multi-step flows need the login
  tester to reach; label as needing a session.

### Class 10 — CORS misconfiguration · `cors_misconfig` · MEDIUM · zero-config baseline (posture family)

- **What.** `Access-Control-Allow-Origin` reflects an arbitrary request `Origin`
  (or is `*`) **together with** `Access-Control-Allow-Credentials: true` → any site
  can read authenticated responses cross-origin.
- **Why it fits.** This is a **posture class**, mirroring headers/cookies: the
  ground truth is the server's own response behaviour under a controlled request,
  not operator intent. Runs zero-config off the secure baseline.
- **Pure-judge mechanism + anchor.** Send `Origin: https://sentinel-<nonce>.evil`.
  `VALIDATED` when the response reflects **that exact attacker origin** in ACAO
  (or ACAO `*`) **and** sets ACAC `true`. The **anchor control** is the SAME
  request with **no `Origin`** (or a same-origin `Origin`): it establishes the
  baseline ACAO behaviour, so a reflected attacker origin is provably origin-
  reflection, not a static safe value. (Reflection *without* credentials is a
  lower-severity note, not the confirmed finding.)
- **Discovery.** Zero-config: probe observed endpoints (especially those that
  already return auth-bearing responses) with the attacker `Origin`. No operator
  input.
- **PATCH + PROVE.** Reuse `ResponseHeaderRule`: `remove_if_equals` the reflected
  ACAO / `set` ACAO to a fixed safe origin / `remove` ACAC → the reflection
  collapses → judge flips `DISPROVED`. Durable fix: strict origin allowlist,
  never reflect, never pair `*` with credentials (documented).
- **Limits.** Preflight-only and non-credentialed CORS quirks are notes, not HIGH
  findings — severity stays honest to real impact.

### Class 11 — Server-side request forgery · `ssrf` · HIGH · zero-oracle (OOB)

- **What.** The server fetches a URL the attacker controls → attacker reaches
  internal services, cloud metadata, or the loopback plane through the server.
- **Why it fits.** Self-grounding via an **out-of-band (OOB) callback**: the
  ground truth is "did the *server* connect back to a host only we know about?"
  A randomised nonce path makes the hit unforgeable — only genuine server-side
  fetching produces it.
- **New infrastructure — the OOB collaborator.** A `SentinelCollaborator` server
  that mirrors `RemediationEnforcer`'s loopback/ephemeral-port pattern (SSRF-safe
  by construction): binds `127.0.0.1:<ephemeral>`, records `(nonce, source_ip,
  timestamp)` for every request path it receives, exposes `.base_url` and
  `.hits(nonce)`. In-process, no external DNS/network — the target must be able to
  reach loopback (true for the local-target threat model; documented as a
  requirement, and the collaborator host arrives as DATA, not hard-coded).
- **Pure-judge mechanism + anchor.** For a candidate URL param, probe with
  `http://<collaborator>/<nonce>`. `VALIDATED` only when `collaborator.hits(nonce)`
  records a matching request — the pure judge reads recorded hits from evidence,
  it does not infer from the target's HTTP status. **Anchor control**: probe with
  a public *same-safe* URL the app is expected to fetch (or the collaborator on a
  *different* nonce that we then confirm was NOT hit) — establishes that the param
  drives a fetch at all and that only the injected nonce produced our callback. No
  callback → DISPROVED / INCONCLUSIVE.
- **SAFETY (critical, non-negotiable).** Sentinel only ever asks the target to
  fetch **Sentinel's own collaborator**. It NEVER probes `169.254.169.254`,
  internal RFC-1918 ranges, or third-party hosts — the callback host is our
  loopback listener, scope-guarded like every other probe. We prove the SSRF
  *capability* (server fetches an attacker-chosen URL) without ever exercising it
  against a real internal target. This keeps the class non-destructive and legal.
- **PATCH + PROVE.** `RequestGuardRule` `url_allowlist` family → the injected
  collaborator URL is refused (only allowlisted hosts forwarded) → no callback →
  judge flips `DISPROVED`. Durable fix: allowlist egress destinations, block
  loopback/link-local/metadata ranges at the fetch layer (documented).
- **Limits.** Blind SSRF with no OOB reachability, and DNS-rebinding nuances, are
  frontier. We prove the reachable-callback case honestly and label the rest.

### Class 12 — Broken authentication / JWT · `broken_auth` · HIGH · hybrid (login-seeded)

- **What.** Token-validation flaws: `alg=none` / unsigned tokens accepted,
  RS256→HS256 confusion, weak HMAC secret, missing signature verification.
- **Why it's hybrid.** It needs a *real captured token* to forge from (the login
  tester supplies this), but once seeded the proof is self-grounding: a forged
  token is either accepted where anonymous is denied, or it is not.
- **Pure-judge mechanism + anchor (privesc-style 3-probe differential).** From a
  captured JWT, derive forgeries: (a) `alg=none` / stripped signature, (b)
  RS256→HS256 confusion signed with the public key as HMAC secret, (c) weak-secret
  brute over a bounded dictionary. Three probes per candidate: **control** (the
  genuine captured token → MUST succeed, proves the route is live and the session
  valid), **breach** (the forged token → the escalation probe), **anonymous
  baseline** (no token → MUST be denied, rules out a public route). `VALIDATED`
  only when control succeeds AND forged token is accepted AND anonymous is denied.
  A forged token rejected (401) → DISPROVED. This is the exact privesc anchor
  pattern, reused verbatim.
- **Discovery / seeding.** Not URL-only — requires the `login` command's captured
  session (a real token). In `discover` mode it surfaces as an honest lead
  ("JWT observed; run `login` to prove token-forgery"). This is the one new class
  that is intent-adjacent, and it's honestly labeled as login-seeded.
- **PATCH + PROVE.** `RequestGuardRule` `jwt` family → refuses to forward requests
  bearing a token with `alg=none`/no signature/failed verification → forged token
  denied → judge flips `DISPROVED` while the genuine token still succeeds. Durable
  fix: pin allowed algorithms, verify signature against the correct key, reject
  unsigned (documented).
- **Limits.** Weak-secret brute is bounded to a small dictionary (non-destructive,
  no infinite cracking); strong secrets → honest DISPROVED, not a false negative
  claim. Session-fixation and OAuth-flow bugs are separate frontier items.

---

## 5. The highest-leverage refactor: one guard, many families

Five of the seven classes (SSTI, XSS, path-traversal, SSRF, JWT) and the shipped
SQLi class all PATCH+PROVE through the **same** primitive:
`RequestGuardRule` + `evaluate_request_guard`. Today the guard hard-codes
`_SQLI_SIGNATURES`. Generalize it **once** and every class inherits a proven,
already-tested virtual-patch seam.

**Refactor (do this before Class 6):**
- Add `signature_family: str` to `RequestGuardRule` (default `"sqli"` for back-compat).
- Replace the single `_SQLI_SIGNATURES` lookup in `_matches_sqli_signature` with a
  registry `_SIGNATURE_FAMILIES: dict[str, tuple[re.Pattern, ...]]` keyed by family:
  `sqli`, `ssti`, `xss`, `traversal`, `url_allowlist`, `jwt`. `evaluate_request_guard`
  selects the family named on each rule.
- `url_allowlist` is inverted (deny unless the value's host is on an allowed set
  carried in rule metadata) — the guard interface already passes the raw value; add
  an `allow` field used only by that family.
- Keep every existing signature/test green: the SQLi family and its behaviour are
  unchanged; this is purely additive.

This is the single change that makes the remaining classes cheap. Each class then
ships its signature tuple + a two-line wiring, not a new enforcement mechanism.

**Response-side additions (small, isolated):** open-redirect and CORS reuse
`ResponseHeaderRule`; open-redirect adds one `remove_if_offorigin` op on `Location`.
No new server, no new handler path.

---

## 6. ★ The capstone: provable chaining

Chaining is where Sentinel stops finding *bugs* and starts proving *attack paths* —
the apex of the "reason, don't signature" thesis and the clearest million-dollar
differentiator. It is also the easiest place to manufacture a lie, so it obeys a
contract stricter than any single class.

### 6.1 The provable-edge contract

An edge `A ⇒ B` (finding A enables finding B) is emitted **only** when all three
hold:

1. **A yields a typed artifact.** A CONFIRMED finding A exposes a concrete value in
   its evidence — a `leaked_object_id`, `credential`, `session_cookie`,
   `bearer_token`, `internal_url`, or `redirect_target`. The artifact is
   *extracted from A's real recorded evidence*, never synthesized.
2. **B consumes that artifact as probe input.** B's normal probe is re-run in a
   scratch graph with the artifact injected as its input (the leaked id becomes
   B's object id; the exfiltrated cookie becomes B's session; the internal URL
   becomes B's fetch target).
3. **B's own pure judge fires `VALIDATED` on that input.** The same kind-specific
   pure judge that gates a standalone B decides the chained B. No new judge, no
   relaxed threshold.

### 6.2 The load-bearing decoy test (the honesty anchor)

An edge is real only if the artifact is *load-bearing* — B must depend on it. So
the composer runs B **twice**:

- with the **real** artifact from A → must be `VALIDATED`,
- with a **decoy** artifact of the same shape but wrong value (random id, wrong
  cookie, unrelated URL) → must be **NOT** `VALIDATED`.

`edge_proven = (real == VALIDATED and decoy != VALIDATED)`. If the decoy also
validates, B did not actually need A — there is no causal link, and **no edge is
emitted**. This mirrors the FIX_PROVEN flip contract: a chain must reproduce a
contradiction that collapses without its precondition. Manufacturing an edge is
the chaining analogue of manufacturing a finding — strictly forbidden.

### 6.3 The artifact model + composer

New package `app/security_graph/chaining/`:

```
chaining/
  artifacts.py    # ChainArtifact(kind, value, source_finding_id, evidence_id)
                  #   + extract_artifacts(graph, finding) -> list[ChainArtifact]
                  #   (per-class extractors keyed by finding.kind; PURE reads of
                  #    recorded evidence — SQLi row → leaked_object_id, XSS+cookie →
                  #    session_cookie, SSRF → internal_url, broken_auth → bearer_token)
  consume.py      # inject_artifact(scratch_graph, artifact, target_hypothesis)
                  #   maps an artifact into B's probe input by B.kind
  compose.py      # compose_chains(graph) -> list[ChainFinding]
                  #   for each CONFIRMED A, each extractable artifact, each candidate
                  #   B: run B's pure chain in a scratch graph (real vs decoy),
                  #   emit ChainFinding only when edge_proven
  chain_finding.py# ChainFinding(links=[A,B], artifact_kind, proof=(real,decoy),
                  #   severity=max(A,B) escalated one step)
  chain_policy.py # parse/load_chain_targets(doc) -> ChainPolicy(targets, source_kind)
                  #   PURE DATA: the operator declares link-2's downstream object
                  #   route + captured attacker session (the honest hybrid input),
                  #   like privesc_policy. Empty => "no chaining pass requested".
  __init__.py
```

**CLI-wired (✅).** `investigate_cmd.py` renders `_chain_matrix_panel` +
`_chain_findings_panel` and runs a CAPSTONE stage after the SSRF pass (before
the final outcome panel), gated on declared `chain_targets` (a section of the
combined policy file, or `SENTINEL_CHAIN_POLICY`) AND a CONFIRMED source finding
proven earlier in the SAME run. When no edge survives the decoy wall it says so
honestly rather than manufacturing a chain. Template: `samples/chain_targets.example.json`.

The composer **reuses each class's existing run/judge unchanged** — it is an
orchestrator over proven parts, holding zero new verdict logic. A `ChainFinding`
materializes only from `edge_proven`, exactly as a `SecurityFinding` materializes
only from a CONFIRMED hypothesis.

### 6.4 Concrete 2-link chains (the ones we can prove now)

- **SQLi ⇒ IDOR/BOLA.** SQLi CONFIRMED dumps a table → extract a real
  `leaked_object_id` (another user's order/basket id) → feed it as the object id
  to the authorization probe → authz judge VALIDATES access to an object the
  principal shouldn't reach; decoy (random id) → 404/403, not validated. *Proves a
  data-leak becomes an account-boundary breach.*
- **insecure-cookie + reflected-XSS ⇒ session exfiltration.** Cookie CONFIRMED
  lacks `HttpOnly` (readable by script) + reflected-XSS CONFIRMED on the same
  origin → the XSS execution-sentinel reads `document.cookie` and recovers the
  real session cookie; decoy (a cookie set `HttpOnly`) → unreadable, not validated.
  *Proves two mediums compose into a session-theft HIGH.*
- **SSRF ⇒ internal reachability ⇒ credential.** SSRF CONFIRMED (server fetches
  our collaborator) → the collaborator can serve a redirect to a second
  Sentinel-controlled nonce path standing in for an internal service → proves the
  server will follow server-side into a second hop; decoy nonce not hit → not
  validated. *Proves the pivot depth, safely, against our own listeners only.*

### 6.5 Honest scope

- **2-link chains are provable now** with the decoy contract and cost nothing new
  beyond the composer.
- **3+ link chains are combinatorial frontier.** The composer can in principle
  compose transitively, but each additional hop multiplies scratch-graph runs and
  the decoy matrix; we cap at 2 links for proven `ChainFinding`s and surface deeper
  paths as *labeled hypotheses* (`chain_lead`), never as proven chains.
- **Never manufacture an edge.** A plausible-looking A→B with no load-bearing
  artifact is a lead, not a chain. The decoy test is the wall.

---

## 7. Build order & sequencing

Ordered by cost-to-prove (reuse first, new infra last):

- **Phase 0 — the guard refactor (§5).** Generalize `RequestGuardRule` to pluggable
  signature families. One PR, all existing tests stay green. Unblocks five classes.
- **Phase 1 — reuse-only classes.** SSTI (§Class 6), open-redirect (§Class 9),
  CORS (§Class 10). Each is a signature family or a `ResponseHeaderRule` reuse +
  the mirror-template package. Cheapest, highest ratio of proven-class-per-credit.
- **Phase 2 — reflected-signal classes.** Path-traversal (§Class 8), reflected XSS
  (§Class 7). New pure judges (canary regex; markup-context parse) but no new infra.
- **Phase 3 — new-infrastructure classes.** SSRF (§Class 11, OOB collaborator) and
  broken-auth/JWT (§Class 12, login-seeded forgery). Each needs one new bounded,
  loopback, scope-safe component.
- **Phase 4 — provable 2-link chaining (§6).** After ≥4 self-grounding classes
  exist, the composer has real artifacts to pass. Ship SQLi⇒IDOR first (both
  classes already live), then the cookie+XSS and SSRF chains as those classes land.

Each phase is independently shippable and independently demoable — the deck/E2E
story grows by one proven class or one proven chain at a time.

---

## 8. Definition of done (per class) & credit guidance

A class is **done** — not before — when every box is checked:

- [ ] Package `app/security_graph/<class>/` with all seams (§2), pure judge is a
      pure function of graph state (no network/scoring/mutation in the judge).
- [ ] `analysis/findings.py` severity entry; `orchestration/target.py` executor
      registered; `investigate_cmd.py` panel behind the remediation gate;
      `discover.py` + discover-mode hook for self-grounding classes.
- [ ] A **negative control** ships in samples AND tests (compliant/inert →
      DISPROVED → no finding). A class without a proven negative control is unproven.
- [ ] PATCH+PROVE reproduces the **VALIDATED→DISPROVED flip** on a scratch graph
      seeded with relationships only; `proven` gates on the flip, never on
      `after==DISPROVED` alone.
- [ ] Offline test module `tests/security_graph/test_<class>.py`, network-free,
      mirroring `test_injection.py` (parse, VALIDATED→CONFIRMED, DISPROVED control,
      pure enforcer mutation, remediate_and_prove FIX_PROVEN + isolation, live
      enforcer integration over a stub upstream). Full suite stays green.
- [ ] Live E2E against a real target where the surface exists, or an honest
      "target sets no such surface → class skips" note (never a manufactured target).
- [ ] Docs (USER_GUIDE + README + deck) updated; this ROADMAP row flipped to ✅.

**Credit guidance (for resuming across sessions as credits refill).** Spend in
the Phase order above — each phase is a natural commit boundary on `sentinel-2`
(do NOT push unless asked). Cheapest value first: Phase 0+1 (the guard refactor +
SSTI/open-redirect/CORS) converts the fewest credits into the most proven classes.
Do one class fully (through its test module + live check) before starting the
next — a half-built class that can't prove its flip is worse than no class. If
credits run out mid-class, the mirror-template package (§2) + this class's spec in
§4 are enough to resume cleanly. Update the §0 table and the roadmap memory as
each class lands.

---

## 9. The million-dollar thesis

Every scanner on the market answers *"does this pattern match?"* Sentinel answers
*"can I prove this is exploitable, and can I prove my patch closed it?"* — and it
carries the proof. That is the whole moat, and it compounds:

1. **Proof-carrying findings.** Not a signature hit — a reproduced contradiction
   from a pure judge, with a differential and an anchor. Near-zero false positives
   by construction; a compliant control *proves itself* DISPROVED.
2. **Auto-proven virtual patches.** Not advice — a live enforcement shield whose
   effect is re-proven by the SAME judge flipping VALIDATED→DISPROVED. Sentinel is
   the only class of tool that ships the fix *and the proof the fix worked*.
3. **The caged AI.** The LLM is advisory-only and can never manufacture a verdict.
   This is what makes the output trustworthy enough to auto-remediate — the
   feature nobody else can safely sell.
4. **Every new class inherits the contract for free.** The mirror-template package
   means class N+1 costs a signature family + a judge, not a new trust model. Going
   5→12 classes is linear effort for exponential coverage — a discovery engine, not
   a rule pack.
5. **Chaining is the apex nobody can fake.** Proving an *attack path* (with the
   load-bearing decoy test) turns a list of bugs into a demonstrated breach — the
   thing a CISO actually pays for — while the decoy contract keeps it honest.

The URL-only discoverer (`discover <url>`) already makes points 1–4 real for the
self-grounding classes today. This roadmap turns "5 classes, 1 chain-capable
engine" into "**12 classes + provable chaining, every one inheriting the proof
contract**" — a tool whose output you can trust enough to act on automatically.
That trust, at that coverage, is the million-dollar idea.

---

# Part II — From 12 classes to an autonomous pentester

> The 12 classes above are the proof-carrying **core**. Part II is the mandate that
> supersedes the original framing: Sentinel is not a class checklist, it is a
> **dynamic, tool-wielding, LLM-driven autonomous web pentester** — point it at a
> URL; it reconnoiters, adapts to the target's shape, hypothesizes, selects tools,
> executes, analyses failures and retries, then emits a proof-carrying report with a
> gated auto-patch. The AI-Kavach CTF is a **side quest, not the aim** — de-scoped
> from planning. Everything in Part II inherits Part I's invariant contract (§1):
> **tools and the LLM PROPOSE; a pure judge DISPOSES.** A tool hit is a LEAD until a
> differential judge reproduces it. Adding capability we cannot prove is the
> analogue of manufacturing a verdict — forbidden. "Doing a class wrong is worse
> than not doing it" governs every graduation below.

## 10. The vulnerability taxonomy (the 200-item list, folded honestly)

The submitted 200-item list is real but redundant and cloud-heavy: dozens are
variants of one class (XSS ×12, SQLi ×6, CSRF ×3, XXE/DoS/TOCTOU/XSSI twice), and
~65 of the tail (123, 132, 135–198) are AWS/K8s/serverless **config-audit** items,
not black-box web probing. Folded into families, keyed to the one rule that
matters — **a family graduates to a shipped class only when it has a pure
differential judge with an explicit anchor** — it collapses to four tiers.

### Tier A — SHIPPED (proof-carrying today; 12 classes + chaining)

These list items are already covered by a pure differential judge or posture baseline:

| Family | List items folded in | Sentinel class |
|--------|----------------------|----------------|
| XSS (reflected/stored/DOM/variants) | 1, 22–27, 61–63, 86–90, 116–117, 150, 155–156 | `xss` |
| SQL injection (all sub-types) | 3, 91–96 | `sql_injection` |
| SSRF (+ token-leak/metadata variants) | 6, 129, 160, 165, 171, 183, 194 | `ssrf` |
| Template injection | 148 | `ssti` |
| Path traversal / LFI / RFI | 4, 5, 19, 52, 107 | `path_traversal` |
| Open redirect | 12, 60, 73, 106 | `open_redirect` |
| CORS misconfiguration | 15, 115, 164 | `cors` |
| Broken auth / JWT | 9, 10, 38, 142, 199, 130, 131, 161 | `broken_auth` (lead+forge) |
| Access control / IDOR / privesc | 7, 11, 59 | `privesc` / authz |
| Security-header posture | 21, 45, 55, 143 | `security_misconfiguration` |
| Insecure cookies / session flags | 53, 103 | `insecure_cookie` |
| Chained attack paths | 97 | `chain` capstone |

### Tier B — NEXT (a real differential/posture judge exists or is cheap; the working roadmap)

Each becomes a mirror-template class (§2) with its own anchor. Ordered by cost-to-prove:

| Family | List items | Anchor / proof sketch |
|--------|-----------|-----------------------|
| Command injection | 17, 109 | OOB collaborator callback (reuse SSRF infra) or time-delay differential |
| XXE | 18, 118 | OOB entity fetch to collaborator; control = inert doc |
| NoSQL injection | 82 | boolean operator differential (`[$ne]`) vs benign anchor |
| CRLF / header / host-header injection | 28, 79 | injected response header/`Location` appears vs stripped control |
| HTML injection | 27 | reflected markup unescaped, no script (XSS judge, lower sev) |
| Insecure deserialization | 40 | OOB/time gadget canary; control = benign blob |
| File upload → shell | 13, 65, 66, 108, 110 | uploaded canary retrievable + executed (OOB), control rejected |
| Secrets / key leakage | 41, 43, 49, 102 | regex-invariant + entropy on responses/JS (trufflehog/gitleaks assist) |
| Disclosure (dir listing, backup, source, debug, DB) | 20, 42, 69–72 | invariant-signature differential vs 404 anchor |
| Clickjacking | 21 | missing `X-Frame-Options`/`frame-ancestors` posture |
| Cache poisoning / deception | 37, 127, 153 | unkeyed-input reflection persists across a second clean request |
| Request smuggling / desync | 46, 126, 163 | dual-response differential (bounded, non-destructive) |
| CSRF (state-changing, no token) | 2, 84, 85 | cross-origin state change succeeds vs token-present control |
| Prototype pollution | 124 | polluted `__proto__` observably changes a later response |

### Tier C — FRONTIER (honest LEADs only; need a session, an oracle, or time/state)

Surfaced as clearly-labelled leads in `discover`/`autonomous` mode; **never**
auto-confirmed, because the ground truth is external (intent, timing, or a second
identity) and cannot be proven by a single self-grounding differential:

- Business-logic / payment / access-control-logic flaws — 30, 57, 58, 59 (logic part)
- Race conditions / TOCTOU — 16, 99, 122 (needs concurrency oracle; bounded)
- Rate-limit / brute-force / account-takeover — 31, 51, 104, 32, 33, 133 (needs identity + is intrusive)
- 2FA/MFA bypass, OAuth/SAML/PKCE flow bugs — 9, 161, 29, 130, 131, 154, 199 (multi-step session)
- Subdomain / broken-link / dangling takeover — 34, 36 (needs external DNS/registration state)
- WebSocket / postMessage / service-worker abuse — 111, 144, 156, 155 (needs browser harness)
- Padding-oracle / timing / weak-entropy / crypto — 112, 113, 100, 101, 114 (statistical oracle)
- Cert/TLS/HSTS posture — 75, 76, 143 (TLS layer; posture-adjacent, partial)

### Tier D — OUT OF SCOPE for a black-box web scanner (honestly excluded)

The cloud/AWS/K8s/serverless config-audit tail is **not** web-probing — it needs
provider credentials and an IaC/API audit engine, a different product. Manufacturing
black-box "findings" for these would violate the contract. Explicitly OUT (audit,
don't fake): 123, 132, 134–141, 145–147, 149, 151–152, 157–159, 162, 166–198.
Pure denial-of-service (35, 119) is **permanently OUT** — destructive, contract-forbidden.
The web-reachable slivers of the cloud tail (SSRF-to-metadata) are already covered
by `ssrf` in Tier A; that is the honest intersection.

> **Taxonomy rule of thumb:** breadth is earned per differential, not declared per
> list entry. Tier A is real today; Tier B is the build queue; Tier C is the lead
> surface; Tier D is a different tool. This ordering is the antidote to "very basic".

## 11. The tool-selection module (`app/tools/selector.py`) — tools PROPOSE

Sentinel already has a real, approval-gated tool layer (`app/tools/runner.py` +
`resolver.py` + `parsers.py`, tested in `tests/test_tool_execution.py`). The
"tool list" ask is satisfied by a **selector built on top of it**, not by ingesting
the submitted PDF encyclopedia — which is ~90% fiction ("Tachyonic Payloads",
"Parallel-Universe Exploitation", "Gödel's Incompleteness Payloads") and whose
realistic sliver is offensive AD/C2/physical-red-team gear out of scope for a web
scanner. Dumping fictional tools into a selector manufactures capability — the
analogue of manufacturing a verdict. So the registry is a **curated, real** set.

**`ToolSpec` registry (curated, real, drivable).** Each entry: `name`, `role`
(recon | discovery | fingerprint | proof-assist | manual-only), `phase`,
`techniques` (which hypothesis classes it feeds), `install` (→ `resolver.INSTALL_RECIPES`),
`parser` (→ `parsers.*`), and `proposes_only: True` (a hard field — no tool is ever
a verdict source). Seed set, all already-known OSS:

- **Recon / surface:** `subfinder`, `dnsx`, `httpx`, `katana`, `gau`, `waybackurls`
  (+ `amass` as an optional heavyweight). Feed the crawl/alive surface.
- **Parameter & content discovery:** `arjun` (hidden params → new endpoints/params),
  `ffuf` (content/dir brute → new endpoints). Expand the injectable surface.
- **Fingerprint:** `wafw00f` (WAF → informs retry/evasion strategy), `nuclei`
  (template hits → **LEADS only**, re-proved by our judges).
- **Technique proof-assist (DEMOTED to proposers):** `sqlmap` → seeds `sql_injection`
  candidate params; `dalfox` → seeds `xss` candidates. Their "findings" are NEVER
  trusted — they only nominate params/URLs our pure judge then confirms or DISPROVES.
- **Secrets:** `trufflehog`, `gitleaks` → regex+entropy leads for the disclosure family.
- **Manual-only (documented, never auto-run):** Burp Suite / Turbo Intruder — the
  realistic picks from the PDF, surfaced as operator guidance in the report, not driven.

**Selector API (pure, deterministic, offline-testable):**
`select_tools(surface, hypotheses) -> ToolPlan` ranks specs by (technique match,
phase, surface fit); `ToolPlan.recon()/discovery()/assist()` group them. It returns
a PLAN of DATA — it never runs anything. Execution stays behind
`runner.run_tool(..., approve=...)` with the `_deny` default (no silent install).
Tool output flows through `parsers.*` back into the `Surface`/hypothesis set, so a
tool **widens what we test**; the differential judge still decides. Wire into the
orchestrator's new SELECT-TOOLS + PLAN-EXECUTION stages (§13). Tests mirror
`test_tool_execution.py` seams (`_resolve`/`_runner`), fully network-free.

## 12. Deepening the skills KB (`app/knowledge/skill_index.py`) — "make Sentinel smarter"

The 817-skill Anthropic Cybersecurity KB (Apache-2.0) is already a derived,
metadata-only, license-safe index feeding qwen breadth hints. "Transform the skills
to make Sentinel smarter" = deepen it past shallow name/description ranking, keeping
the firewall absolute (**skills never become findings; only metadata ships; never
skill bodies; proposal/breadth-only**):

1. **Technique-aware selection.** Today cards rank by *surface* terms. Add a
   `technique` axis: map each `SkillCard` to the hypothesis techniques it informs
   (from tags/subdomain/mitre) so the proposer can pull *"what do the experts try
   for `ssti`?"* per hypothesis, not just per target. `select_for_technique(tech)`
   beside `select_for_surface`.
2. **Derived hint bundles (metadata-only).** From each card's existing metadata,
   distil three bounded, license-safe hint lists per technique: *payload-shape*
   cues (e.g. "polyglot", "double-encoding" as words already in tags/descriptions),
   *tool* references (skill mentions `ffuf`/`sqlmap` → cross-link to §11 registry),
   and *remediation* cues (feeds the report §13). No skill prose is copied — only
   term-level signals derived from the metadata we already ship.
3. **Three consumers, one firewall.** The bundle feeds (a) the **proposer** (richer
   breadth prompt), (b) the **tool selector** (skill→tool cross-links), (c) the
   **report** (remediation phrasing). None of these can emit a finding — they only
   shape PROPOSALS and PROSE. The pure judge is untouched.

Ship as an additive layer (a companion `skill_hints.py` + new methods on
`SkillIndex`), rebuilding `skill_index.json` with the extra derived fields; all
existing KB tests stay green. Attribution/license fields in the JSON are preserved.

## 13. The smart agentic pipeline (the flow you asked for)

Your requested loop — *recon → endpoint selection → test planning → tool selection
→ execution planning → execute → analyse → **failure-cause analysis + retry** →
solution analysis → **report (repro + proofs + remediation)**, "and it should be
smart"* — maps onto the existing orchestrator as named stages. Every new stage is
**LLM-advisory + pure-judge-gated + behind the human deploy gate**:

| # | Stage | Status | What it adds |
|---|-------|--------|--------------|
| 1 | DISCOVER (recon) | ✅ exists | live recon → `Surface` |
| 2 | SELECT ENDPOINTS | ✅ shipped | rank/prune surface by injectability (params, reflection, auth) to focus budget (`SENTINEL_ENDPOINT_BUDGET`; default = rank-only, full coverage) |
| 3 | PLAN TESTS (hypothesize) | ✅ exists | rule floor + LLM breadth |
| 4 | SELECT TOOLS | 🔨 new (§11) | technique→tool plan (proposers only) |
| 5 | PLAN EXECUTION | ✅ shipped | order, concurrency (`SENTINEL_MAX_WORKERS`), rounds; which judges + which approved tools — pure annotation, never a coverage gate |
| 6 | EXECUTE | ✅ exists | `run_plan` + approval-gated tool runs |
| 7 | ANALYSE RESULT | ✅ exists | tiered verdicts (CONFIRMED/DISPROVED/LEAD/INCONCLUSIVE) |
| 8 | FAILURE-CAUSE + RETRY | 🔨 new | on INCONCLUSIVE/suspicious-DISPROVED, an advisory strategist proposes a *different* probe shape (encoding, location, anchor, tool-assist); bounded retries; **re-judged by the SAME pure judge** — never a verdict flip by the strategist |
| 9 | SOLUTION ANALYSIS | ✅ exists | remediation synthesis + FIX_PROVEN flip |
| 10 | REPORT | ✅ module shipped · 🔨 CLI-wire pending | per-finding: steps-to-reproduce (real probe requests), proofs (differential+anchor+judge reason+evidence), remediation (patch + proven flip), severity; markdown/JSON |

**The two honesty-critical new stages:**

- **Failure-cause analysis + retry (stage 8).** This is where "smart" lives without
  breaking the contract. When a judge returns INCONCLUSIVE (or DISPROVED with a
  reflection/anchor signal that suggests the *probe shape* was wrong, not the
  hypothesis), a bounded **retry strategist** (LLM-advisory, ≤N attempts) proposes a
  materially different probe: a new encoding, a different `location` (query→body→
  path→cookie/header), a repaired anchor, a WAF-evasion mutation, or a tool-assisted
  candidate. Each retry is a fresh PROPOSAL fed back through the **same pure judge**.
  The strategist can never set a status — it only earns the judge another honest
  measurement. Retries are logged as attempts in the report (transparency), and the
  loop is bounded to stay non-destructive.
- **Report generator (stage 10, `app/autonomous/report.py`) — ✅ SHIPPED (module),
  🔨 CLI-wiring pending.** For every CONFIRMED
  finding it assembles a proof-carrying record straight from `JudgeEvidence`:
  *steps-to-reproduce* = the literal probe requests the judge ran (sensitive header
  *values* masked); *proof* = the
  differential (baseline vs breakout), the anchor, the judge's verbatim reason, and
  the recorded evidence ids; *remediation* = the synthesized patch + the
  VALIDATED→DISPROVED flip that proved it; *severity* from the class. The LLM may
  **narrate** (readable prose, exec summary) but never **assert** — every claim is
  backed by a graph fact or it is omitted. Renders markdown (human) + JSON
  (machine). Leads and retried-but-unproven items are shown honestly, unpromoted.
  `build_report` / `render_markdown` / `render_json` / `write_report` / `narrate` all
  ship with 13 offline tests (`tests/test_autonomous_report.py`). **Remaining:** call it
  at the end of `autonomous_cmd.run()` (capture `_remediate_confirmed` outcomes, build +
  write, print an artifact panel), gate `narrate` behind `use_llm`, add a CLI-level test.

## 14. Blockers, backlog & operating notes

**LLM providers / the API key (answered).** The pluggable provider layer already
ships (`SENTINEL_LLM_PROVIDER=ollama|anthropic|openai|compatible`; keys via
env/`getpass`, closure-bound, never logged). Using a strong Claude model is **safe
and high-value here specifically because of the contract**: Opus supercharges the
*creative* half (PROPOSE / retry-strategise / analyse / report-narrate) while the
pure judge still DISPOSES — so a smarter model buys better hypotheses and prose with
**zero new false-positive risk**. Config for the credited key: set
`SENTINEL_LLM_PROVIDER=anthropic`, `ANTHROPIC_API_KEY` in the environment (not in
code, not in git), `SENTINEL_LLM_MODEL=claude-opus-4-8` (or `claude-opus-5`). Keep
`ollama`/qwen as the free local default for bulk/CI; flip to Opus for showcase runs.

**Location vocab gap (backlog).** `_LOC_MAP` covers query/body_form/body_json/path;
**cookie** and **header** still degrade to query. Close `location="cookie"` end-to-end
(judge + enforcer + proposer), then re-run the PortSwigger TrackingId blind-SQLi lab
(cookie ground truth); then `location="header"`.

**Other backlog:** UNION/data-extraction SQLi (feeds chaining artifacts); WAF/filter
evasion ladder (pairs with stage 8 + `wafw00f`); a Learning KB (episode store /
priors / exemplars, proposal-only); dedup duplicate CONFIRMED/verdict rows in the
report.

**Build order for Part II:** §11 tool selector ✅ → §13 report generator ✅ →
CLI-wire report ✅ → §13 failure-cause+retry (stage 8, adaptive loop) ✅ → §11
NOMINATE stage ✅ *(sqlmap driven as a real nominator behind the pure judge,
approval-gated — "tool-wielding" now true)* → **live CI harness ✅** *(gated
`tests/live/` tier + `docker-compose.yml` + `.github/workflows/live.yml`; the
Juice Shop / VAmPI SQLi wins are now reproducible `VALIDATED`→`FIX_PROVEN`
integration tests, deselected by default via `-m 'not live'`)* → endpoint-select
(stage 2) ✅ + exec-plan (stage 5) ✅ *(both pure DATA: Stage 2 ranks/prunes the
surface by injectability behind `SENTINEL_ENDPOINT_BUDGET` — default rank-only, full
coverage; Stage 5 derives work slots + judge/lead assignment + real concurrency
(`SENTINEL_MAX_WORKERS`) + rounds + in-scope proof-assist tools, never dropping a
hypothesis)* → **NEXT:** wire broken_auth/privesc judges into the
autonomous `_SPECS` → §12 KB deepening → Tier-B classes in the §7 phase style
(command-injection & XXE first, reusing the SSRF OOB collaborator). Commit at
each boundary on `sentinel-2` (no push). Every item obeys §1.

---

*End of roadmap (Part I: 12 classes + chaining; Part II: the autonomous pentester).
Build against this file; flip status rows to ✅ as items land, and keep the
invariant contract (§1) inviolate — a manufactured verdict, or a capability we
cannot prove, is worse than a missing class.*
