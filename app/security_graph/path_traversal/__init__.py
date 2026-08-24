"""
Path traversal / local file inclusion (LFI) — Sentinel's eighth vulnerability class.

Where `injection` asks *"does an attacker-controlled parameter reach the backend
SQL query?"*, `template_injection` asks *"is it evaluated by a template engine?"*
and `xss` asks *"is it reflected as active markup?"*, this axis asks the
filesystem-layer analogue: *"does an attacker-controlled parameter read a file
OUTSIDE the intended directory — leaking a system file?"*

This class is an **OS-canary differential**, and that is what makes it sound. A
single status code is never a verdict, and neither is a file read on its own. For
each declared parameter the judge reads a *control* probe (a benign,
traversal-free, non-OS filename — ``sentinel-baseline.txt`` — which can never leak
a system file) and a fixed ladder of *payload* probes (directory-escape shapes
aimed at cross-OS canary files: ``../../../../etc/passwd``,
``..\\..\\..\\windows\\win.ini``, absolute paths, NUL-byte truncation). Path
traversal is VALIDATED only when a payload response contains an **OS-file
invariant** — ``root:x:0:0:`` for ``/etc/passwd``, a ``[fonts]``/``[extensions]``
section for ``win.ini`` — that is ABSENT from the control; a control that already
carries an invariant (or is unreadable) is INCONCLUSIVE; anything else is
DISPROVED. The invariant is content a normal application response could never
contain by coincidence, so its appearance is attributable to a file read, and the
control anchors that attribution by invariant ABSENCE.

The epistemic contract is identical to the other classes and deliberately so:

  * an operator **path-traversal matrix** (pure data — endpoint + parameter)
    declares which parameter MUST NOT read files outside its root (or discovery
    synthesizes it from live recon);
  * the seeder records the fixed benign control filename and routes each declared
    surface into an OPEN `path_traversal` hypothesis — never a finding;
  * the live probes (the *same* HTTP executor) fetch the real control / payload
    response bodies;
  * a PURE, deterministic judge decides the differential, returning VALIDATED /
    DISPROVED / INCONCLUSIVE;
  * a finding materialises only when a live payload *provably* leaked an OS-file
    invariant absent from the control.

Remediation reuses the live enforcement shield as a **request-guard (virtual
patch)** with signature family ``traversal``: the same reverse proxy refuses to
forward this parameter when it carries a directory-escape signature (403) while
forwarding the benign control filename unchanged, and the fix is PROVEN when the
SAME judge flips VALIDATED -> DISPROVED through it. The durable fix is to
canonicalise the resolved path and confine it to an allowlisted base directory.
Nothing here invents a verdict, and the engine holds no target-specific logic.
"""

from .traversal_policy import (
    CONTROL_VALUE,
    TraversalCheck,
    TraversalPolicy,
    canary_invariants,
    leaked_canary,
    load_traversal_policy,
    parse_traversal_policy,
    traversal_payloads,
)
from .judge import (
    TraversalExpectation,
    traversal_expectation,
    judge_path_traversal,
)
from .executor import PathTraversalProbeExecutor
from .seed import seed_path_traversal_policy, traversal_target
from .run import (
    PathTraversalProbeResult,
    investigate_path_traversal,
    run_path_traversal_investigation,
)
from .discover import PathTraversalDiscovery, synthesize_path_traversal_policy
from .remediation import (
    PathTraversalControlRule,
    PathTraversalRemediationArtifacts,
    PathTraversalRemediationOutcome,
    PathTraversalRemediationPlan,
    render_path_traversal_artifacts,
    remediate_path_traversal_and_prove,
    remediate_path_traversal_findings,
    synthesize_path_traversal_remediation,
    verify_path_traversal_remediation,
)

__all__ = [
    "CONTROL_VALUE",
    "TraversalCheck",
    "TraversalPolicy",
    "canary_invariants",
    "leaked_canary",
    "load_traversal_policy",
    "parse_traversal_policy",
    "traversal_payloads",
    "TraversalExpectation",
    "traversal_expectation",
    "judge_path_traversal",
    "PathTraversalProbeExecutor",
    "seed_path_traversal_policy",
    "traversal_target",
    "PathTraversalProbeResult",
    "investigate_path_traversal",
    "run_path_traversal_investigation",
    "PathTraversalDiscovery",
    "synthesize_path_traversal_policy",
    "PathTraversalControlRule",
    "PathTraversalRemediationArtifacts",
    "PathTraversalRemediationOutcome",
    "PathTraversalRemediationPlan",
    "render_path_traversal_artifacts",
    "remediate_path_traversal_and_prove",
    "remediate_path_traversal_findings",
    "synthesize_path_traversal_remediation",
    "verify_path_traversal_remediation",
]
