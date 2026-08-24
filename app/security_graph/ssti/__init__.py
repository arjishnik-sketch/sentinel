"""
Server-side template injection (SSTI) — Sentinel's sixth vulnerability class.

Where `injection` asks *"does an attacker-controlled parameter reach the backend
SQL query?"*, this axis asks the template-layer analogue: *"does an
attacker-controlled parameter reach a server-side template engine — is it
evaluated rather than merely reflected?"*

This class is an **arithmetic-evaluation differential**, and that is what makes
it sound. A single status code is never a verdict, and neither is a reflected
value. For each declared parameter the judge reads a *control* probe (the literal
expression ``a*b`` with no template delimiters, which must merely be reflected)
and a set of *payload* probes (that same ``a*b`` wrapped in each common template
delimiter — ``{{…}}``, ``${…}``, ``#{…}``, ``<%= … %>``). SSTI is VALIDATED only
when a payload response contains the *computed product* ``a*b`` while the literal
expression is gone AND the control proved the app merely reflects the literal (so
the product can only have been produced by the backend evaluating the template);
every payload merely reflected is DISPROVED; a contaminated/unreadable control is
INCONCLUSIVE.

The epistemic contract is identical to the other classes and deliberately so:

  * an operator **ssti matrix** (pure data — endpoint + parameter) declares which
    parameter MUST NOT be evaluated (or discovery synthesizes it from live recon);
  * the seeder generates the arithmetic operands once, records them, and routes
    each declared surface into an OPEN `template_injection` hypothesis — never a
    finding;
  * the live probes (the *same* HTTP executor) fetch the real control / payload
    response bodies;
  * a PURE, deterministic judge decides the differential, returning VALIDATED /
    DISPROVED / INCONCLUSIVE;
  * a finding materialises only when a live template payload *provably* rendered
    the computed product while the literal vanished.

Remediation reuses the live enforcement shield as a **request-guard (virtual
patch)** with signature family ``ssti``: the same reverse proxy refuses to
forward this parameter when it carries a template delimiter (403) while
forwarding the benign control literal unchanged, and the fix is PROVEN when the
SAME judge flips VALIDATED → DISPROVED through it. The durable fix is to never
render untrusted input as a template. Nothing here invents a verdict, and the
engine holds no target-specific logic.
"""

from .ssti_policy import (
    SSTICheck,
    SSTIPolicy,
    load_ssti_policy,
    make_operands,
    parse_ssti_policy,
    template_payloads,
)
from .judge import (
    SSTIExpectation,
    ssti_expectation,
    judge_template_injection,
)
from .executor import SSTIProbeExecutor
from .seed import seed_ssti_policy, ssti_target
from .run import (
    SSTIProbeResult,
    investigate_ssti,
    run_ssti_investigation,
)
from .discover import SSTIDiscovery, synthesize_ssti_policy
from .remediation import (
    SSTIControlRule,
    SSTIRemediationArtifacts,
    SSTIRemediationOutcome,
    SSTIRemediationPlan,
    render_ssti_artifacts,
    remediate_ssti_and_prove,
    remediate_ssti_findings,
    synthesize_ssti_remediation,
    verify_ssti_remediation,
)

__all__ = [
    "SSTICheck",
    "SSTIPolicy",
    "load_ssti_policy",
    "make_operands",
    "parse_ssti_policy",
    "template_payloads",
    "SSTIExpectation",
    "ssti_expectation",
    "judge_template_injection",
    "SSTIProbeExecutor",
    "seed_ssti_policy",
    "ssti_target",
    "SSTIProbeResult",
    "investigate_ssti",
    "run_ssti_investigation",
    "SSTIDiscovery",
    "synthesize_ssti_policy",
    "SSTIControlRule",
    "SSTIRemediationArtifacts",
    "SSTIRemediationOutcome",
    "SSTIRemediationPlan",
    "render_ssti_artifacts",
    "remediate_ssti_and_prove",
    "remediate_ssti_findings",
    "synthesize_ssti_remediation",
    "verify_ssti_remediation",
]
