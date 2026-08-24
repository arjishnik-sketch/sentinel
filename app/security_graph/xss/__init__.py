"""
Reflected cross-site scripting (XSS) — Sentinel's seventh vulnerability class.

Where `injection` asks *"does an attacker-controlled parameter reach the backend
SQL query?"* and `template_injection` asks *"is it evaluated by a template
engine?"*, this axis asks the browser-layer analogue: *"is an attacker-controlled
parameter reflected into the response as active HTML markup — un-escaped, so it
executes in the victim's browser?"*

This class is a **reflection differential**, and that is what makes it sound. A
single status code is never a verdict, and neither is a reflected value on its
own. For each declared parameter the judge reads a *control* probe (a benign
random alphanumeric marker with no HTML-significant characters, which must merely
be reflected) and a set of *payload* probes (that same marker wrapped in active
markup — ``<script>``, ``<svg onload=>``, ``<img onerror=>``, ``<body onload=>``).
Reflected XSS is VALIDATED only when a payload response contains the raw markup
VERBATIM (the ``<tag`` and the marker inside it survived un-escaped) AND the
control proved the app reflects the bare marker — so the ``<``/``>`` provably
passed through output encoding untouched; every payload the app HTML-escapes is
DISPROVED; a contaminated/unreadable control is INCONCLUSIVE.

The epistemic contract is identical to the other classes and deliberately so:

  * an operator **xss matrix** (pure data — endpoint + parameter) declares which
    parameter MUST NOT reflect active markup (or discovery synthesizes it from
    live recon);
  * the seeder generates the benign marker once, records it, and routes each
    declared surface into an OPEN `xss` hypothesis — never a finding;
  * the live probes (the *same* HTTP executor) fetch the real control / payload
    response bodies;
  * a PURE, deterministic judge decides the differential, returning VALIDATED /
    DISPROVED / INCONCLUSIVE;
  * a finding materialises only when a live payload *provably* reflected raw
    active markup un-escaped while the control proved reflection.

Remediation reuses the live enforcement shield as a **request-guard (virtual
patch)** with signature family ``xss``: the same reverse proxy refuses to forward
this parameter when it carries an XSS breakout signature (403) while forwarding
the benign marker unchanged, and the fix is PROVEN when the SAME judge flips
VALIDATED → DISPROVED through it. The durable fix is context-aware output
encoding at the sink plus a restrictive Content-Security-Policy. Nothing here
invents a verdict, and the engine holds no target-specific logic.
"""

from .xss_policy import (
    XSSCheck,
    XSSPolicy,
    load_xss_policy,
    make_marker,
    marker_payloads,
    parse_xss_policy,
)
from .judge import (
    XSSExpectation,
    xss_expectation,
    judge_reflected_xss,
)
from .executor import XSSProbeExecutor
from .seed import seed_xss_policy, xss_target
from .run import (
    XSSProbeResult,
    investigate_xss,
    run_xss_investigation,
)
from .discover import XSSDiscovery, synthesize_xss_policy
from .remediation import (
    XSSControlRule,
    XSSRemediationArtifacts,
    XSSRemediationOutcome,
    XSSRemediationPlan,
    render_xss_artifacts,
    remediate_xss_and_prove,
    remediate_xss_findings,
    synthesize_xss_remediation,
    verify_xss_remediation,
)

__all__ = [
    "XSSCheck",
    "XSSPolicy",
    "load_xss_policy",
    "make_marker",
    "marker_payloads",
    "parse_xss_policy",
    "XSSExpectation",
    "xss_expectation",
    "judge_reflected_xss",
    "XSSProbeExecutor",
    "seed_xss_policy",
    "xss_target",
    "XSSProbeResult",
    "investigate_xss",
    "run_xss_investigation",
    "XSSDiscovery",
    "synthesize_xss_policy",
    "XSSControlRule",
    "XSSRemediationArtifacts",
    "XSSRemediationOutcome",
    "XSSRemediationPlan",
    "render_xss_artifacts",
    "remediate_xss_and_prove",
    "remediate_xss_findings",
    "synthesize_xss_remediation",
    "verify_xss_remediation",
]
