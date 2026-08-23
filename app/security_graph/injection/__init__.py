"""
SQL injection (boolean differential) — Sentinel's fifth vulnerability class.

Where `authorization` asks *"can this principal reach this resource?"*,
`posture` asks *"does this endpoint ship the declared browser protections?"*,
`cookies` asks *"are the issued cookies safe to hold a session in?"*, and
`privilege_escalation` asks *"can one real account cross a boundary it was never
granted?"*, this axis asks the classic server-side question: *"does an
attacker-controlled parameter reach the backend query — can a boolean payload
change what the query returns?"*

This class is a **three-way boolean differential**, and that is what makes it
sound. A single status code is never a verdict. For each declared injectable
parameter the judge reads three kinds of live probe: a *baseline* probe (the
benign declared value, which must return a legitimate response — the anchor),
and one or more length-matched *(TRUE, FALSE)* pairs (the benign value plus a
boolean tautology vs. the same value plus a boolean contradiction). Every pair
is equal length to the character, so a payload reflected verbatim into the
response contributes identical bytes to BOTH arms — any TRUE≠FALSE difference
can therefore only come from the backend evaluating the injected SQL boolean.
Injection is VALIDATED only when a pair makes the response track the boolean
(TRUE≠FALSE) AND one arm reproduces the legitimate baseline exactly; every pair
collapsing (TRUE==FALSE) is DISPROVED; a mis-declared/unreachable baseline is
INCONCLUSIVE.

The epistemic contract is identical to the other classes and deliberately so:

  * an operator **injection matrix** (pure data — endpoint + parameter + a
    benign baseline value) declares which parameter MUST NOT alter the query;
  * the seeder routes each declared surface into an OPEN `injection` hypothesis
    — never a finding;
  * the live probes (the *same* HTTP executor) fetch the real baseline / TRUE /
    FALSE responses;
  * a PURE, deterministic judge decides the differential, returning VALIDATED /
    DISPROVED / INCONCLUSIVE;
  * a finding materialises only when a live boolean payload *provably* toggled
    the backend query.

Remediation reuses the live enforcement shield as a **request-guard (virtual
patch)**: the same reverse proxy refuses to forward this parameter when it
carries a SQL-injection signature (403) while forwarding the benign value
unchanged, and the fix is PROVEN when the SAME judge flips VALIDATED → DISPROVED
through it — the boolean payloads are blocked so TRUE and FALSE collapse and the
differential is gone. The durable fix is a parameterised query in the handler.
Nothing here invents a verdict, and the engine holds no target-specific logic:
every host/route/parameter detail arrives as operator-declared matrix data.
"""

from .injection_policy import (
    InjectionCheck,
    InjectionPolicy,
    boolean_payload_pairs,
    load_injection_policy,
    parse_injection_policy,
)
from .judge import (
    InjectionExpectation,
    injection_expectation,
    judge_injection,
)
from .executor import InjectionProbeExecutor
from .seed import injection_target, seed_injection_policy
from .run import (
    InjectionProbeResult,
    investigate_injection,
    run_injection_investigation,
)
from .remediation import (
    InjectionControlRule,
    InjectionRemediationArtifacts,
    InjectionRemediationOutcome,
    InjectionRemediationPlan,
    render_injection_artifacts,
    remediate_injection_and_prove,
    remediate_injection_findings,
    synthesize_injection_remediation,
    verify_injection_remediation,
)

__all__ = [
    "InjectionCheck",
    "InjectionPolicy",
    "boolean_payload_pairs",
    "load_injection_policy",
    "parse_injection_policy",
    "InjectionExpectation",
    "injection_expectation",
    "judge_injection",
    "InjectionProbeExecutor",
    "injection_target",
    "seed_injection_policy",
    "InjectionProbeResult",
    "investigate_injection",
    "run_injection_investigation",
    "InjectionControlRule",
    "InjectionRemediationArtifacts",
    "InjectionRemediationOutcome",
    "InjectionRemediationPlan",
    "render_injection_artifacts",
    "remediate_injection_and_prove",
    "remediate_injection_findings",
    "synthesize_injection_remediation",
    "verify_injection_remediation",
]
