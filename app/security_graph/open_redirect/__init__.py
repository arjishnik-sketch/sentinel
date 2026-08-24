"""
Open redirect — Sentinel's ninth vulnerability class.

Where `template_injection` asks *"does an attacker-controlled parameter reach a
server-side template engine?"*, this axis asks the redirect-layer analogue:
*"does an attacker-controlled parameter control the redirect destination — can it
send a victim to an attacker-chosen off-origin host?"*

This class is a **two-probe host differential**, and that is what makes it sound.
A single status code is never a verdict, and neither is a bare 3xx. For each
declared parameter the judge reads a same-origin *control* anchor probe (the
parameter set to the target's own origin, which a genuine redirector honours
on-origin) and an off-origin *payload* probe (the parameter set to a URL on a
random, unroutable nonce host ``sentinel-<nonce>.example``). Open redirect is
VALIDATED only when the payload response's ``Location`` header resolves to the
*nonce host* — a host that could ONLY have come from our parameter value, so the
redirect is provably attacker-controlled — AND the control anchor proves the
endpoint legitimately redirects on-origin; a payload that does not reach the
nonce host is DISPROVED; a payload that reaches the nonce host while the anchor
fails to reproduce an on-origin redirect is INCONCLUSIVE.

The epistemic contract is identical to the other classes and deliberately so:

  * an operator **open-redirect matrix** (pure data — endpoint + parameter)
    declares which parameter MUST NOT redirect off-origin (or discovery
    synthesizes it from live recon);
  * the seeder generates the unforgeable nonce host once, records it, and routes
    each declared surface into an OPEN `open_redirect` hypothesis — never a
    finding;
  * the live probes (a NO-FOLLOW HTTP executor) OBSERVE the real ``Location``
    header without ever following it — the unroutable nonce host is never
    contacted;
  * a PURE, deterministic judge decides the differential, returning VALIDATED /
    DISPROVED / INCONCLUSIVE;
  * a finding materialises only when a live off-origin payload *provably*
    redirected to the nonce host while the same-origin control anchored.

Remediation reuses the live enforcement shield as a **request-guard (virtual
patch)** with signature family ``url_allowlist``: the same reverse proxy refuses
to forward this parameter when it carries an off-origin URL whose host is not on
the engagement allowlist (403) while forwarding the benign same-origin control
unchanged, and the fix is PROVEN when the SAME judge flips VALIDATED → DISPROVED
through it. The durable fix is to never build a redirect target from raw user
input. Nothing here invents a verdict, and the engine holds no target-specific
logic.
"""

from .open_redirect_policy import (
    OpenRedirectCheck,
    OpenRedirectPolicy,
    load_open_redirect_policy,
    make_nonce,
    nonce_host,
    parse_open_redirect_policy,
    payload_url,
)
from .judge import (
    OpenRedirectExpectation,
    open_redirect_expectation,
    judge_open_redirect,
)
from .executor import OpenRedirectProbeExecutor
from .seed import seed_open_redirect_policy, open_redirect_target
from .run import (
    OpenRedirectProbeResult,
    investigate_open_redirect,
    run_open_redirect_investigation,
)
from .discover import OpenRedirectDiscovery, synthesize_open_redirect_policy
from .remediation import (
    OpenRedirectControlRule,
    OpenRedirectRemediationArtifacts,
    OpenRedirectRemediationOutcome,
    OpenRedirectRemediationPlan,
    render_open_redirect_artifacts,
    remediate_open_redirect_and_prove,
    remediate_open_redirect_findings,
    synthesize_open_redirect_remediation,
    verify_open_redirect_remediation,
)

__all__ = [
    "OpenRedirectCheck",
    "OpenRedirectPolicy",
    "load_open_redirect_policy",
    "make_nonce",
    "nonce_host",
    "parse_open_redirect_policy",
    "payload_url",
    "OpenRedirectExpectation",
    "open_redirect_expectation",
    "judge_open_redirect",
    "OpenRedirectProbeExecutor",
    "seed_open_redirect_policy",
    "open_redirect_target",
    "OpenRedirectProbeResult",
    "investigate_open_redirect",
    "run_open_redirect_investigation",
    "OpenRedirectDiscovery",
    "synthesize_open_redirect_policy",
    "OpenRedirectControlRule",
    "OpenRedirectRemediationArtifacts",
    "OpenRedirectRemediationOutcome",
    "OpenRedirectRemediationPlan",
    "render_open_redirect_artifacts",
    "remediate_open_redirect_and_prove",
    "remediate_open_redirect_findings",
    "synthesize_open_redirect_remediation",
    "verify_open_redirect_remediation",
]
