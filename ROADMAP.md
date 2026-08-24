# Sentinel — Master Roadmap: 12 Vulnerability Classes + Provable Chaining

> **This is the canonical reference document for finishing Sentinel.**
> It specifies the 7 remaining vulnerability classes (bringing the total to 12) and
> the *provable chaining* capstone. Every item here is engineered to preserve the
> hard epistemic contract that makes Sentinel defensible. Build against this file;
> update it as classes land.

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
| 7 | Cross-site scripting (XSS) | `xss` | HIGH | **zero-oracle** | 🔨 |
| 8 | Path traversal / LFI | `path_traversal` | HIGH | **zero-oracle** | 🔨 |
| 9 | Open redirect | `open_redirect` | MEDIUM | **zero-oracle** | ✅ |
| 10 | CORS misconfiguration | `cors_misconfig` | MEDIUM | **zero-config baseline** | ✅ |
| 11 | Server-side request forgery | `ssrf` | HIGH | **zero-oracle (OOB)** | ✅ |
| 12 | Broken auth / JWT | `broken_auth` | HIGH | hybrid (login-seeded) | 🔨 |
| ★ | **Provable chaining** | `chain` | — | artifact-driven | 🔨 |

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
  __init__.py
```

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

*End of roadmap. Build against this file; flip §0 rows to ✅ as classes land, and
keep the invariant contract (§1) inviolate — a manufactured verdict is worse than
a missing class.*
