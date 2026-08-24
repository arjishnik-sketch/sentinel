"""
Server-side request forgery (SSRF) — Sentinel's eleventh vulnerability class.

Where `open_redirect` asks *"can an attacker-controlled parameter send a victim's
browser to an attacker-chosen host?"*, this axis asks the server-side analogue:
*"can an attacker-controlled parameter coerce the BACKEND into making a request of
an attacker-chosen URL?"* — the class behind cloud-metadata theft, internal port
scans, and firewall-bypass pivots.

This class is an **out-of-band callback differential**, and that is what makes it
sound. A single status code is never a verdict. Sentinel stands up its OWN loopback
collaborator (see :mod:`.collaborator`) — a listener bound to ``127.0.0.1`` that
makes no outbound request, performs no DNS, and forwards nothing; it only receives
and records. For each declared parameter the judge reads a same-origin *control*
anchor probe (the parameter set to the target's own origin — a benign fetch that
reaches only the target itself, establishing the HTTP baseline AND that the payload
nonce is un-hit before injection) and a *payload* probe (the parameter set to the
collaborator's callback URL carrying a fresh random nonce). SSRF is VALIDATED only
when the collaborator records a hit on the *payload nonce* — a token that appears
ONLY in the URL we injected, so the request could only have come from the target
fetching our input — AND the control anchor confirms that nonce was un-hit before
injection while a never-injected control nonce stays un-hit; a payload that
triggers no callback is DISPROVED; a recorded control nonce (a spurious/forged
record) or a failed anchor is INCONCLUSIVE.

The epistemic contract is identical to the other classes and deliberately so:

  * an operator **SSRF matrix** (pure data — endpoint + fetch parameter) declares
    which parameter MUST NOT be coerced into a server-side fetch (or discovery
    synthesizes it from live recon);
  * the seeder routes each declared surface into an OPEN `ssrf` hypothesis — never
    a finding — and mints per-probe nonces at probe time, not at seed time;
  * the live probes inject ONLY Sentinel's own loopback collaborator URL — NEVER a
    metadata IP, an RFC-1918 host, or any third party;
  * a PURE, deterministic judge decides the differential from recorded callback
    booleans alone, returning VALIDATED / DISPROVED / INCONCLUSIVE;
  * a finding materialises only when a live payload *provably* reached the
    collaborator on the unforgeable nonce while the control anchored.

Remediation reuses the live enforcement shield as a **request-guard (virtual
patch)** with signature family ``url_allowlist``: the same reverse proxy refuses to
forward this parameter when it carries a URL whose ``host:port`` is not the
engagement target's own (an egress allowlist of exactly one destination) while
forwarding the benign same-origin control unchanged, and the fix is PROVEN when the
SAME judge flips VALIDATED → DISPROVED through it. The durable fix is to allowlist
egress destinations at the fetch layer and block loopback / link-local /
cloud-metadata ranges. Nothing here invents a verdict, and the engine holds no
target-specific logic.
"""

from .ssrf_policy import (
    SsrfCheck,
    SsrfPolicy,
    load_ssrf_policy,
    make_nonce,
    parse_ssrf_policy,
)
from .collaborator import CollaboratorHit, SentinelCollaborator
from .judge import SsrfExpectation, ssrf_expectation, judge_ssrf
from .executor import SsrfProbeExecutor
from .seed import seed_ssrf_policy, ssrf_target
from .run import (
    SsrfProbeResult,
    investigate_ssrf,
    run_ssrf_investigation,
)
from .discover import SsrfDiscovery, synthesize_ssrf_policy
from .remediation import (
    SsrfControlRule,
    SsrfRemediationArtifacts,
    SsrfRemediationOutcome,
    SsrfRemediationPlan,
    render_ssrf_artifacts,
    remediate_ssrf_and_prove,
    remediate_ssrf_findings,
    synthesize_ssrf_remediation,
    verify_ssrf_remediation,
)

__all__ = [
    "SsrfCheck",
    "SsrfPolicy",
    "load_ssrf_policy",
    "make_nonce",
    "parse_ssrf_policy",
    "CollaboratorHit",
    "SentinelCollaborator",
    "SsrfExpectation",
    "ssrf_expectation",
    "judge_ssrf",
    "SsrfProbeExecutor",
    "seed_ssrf_policy",
    "ssrf_target",
    "SsrfProbeResult",
    "investigate_ssrf",
    "run_ssrf_investigation",
    "SsrfDiscovery",
    "synthesize_ssrf_policy",
    "SsrfControlRule",
    "SsrfRemediationArtifacts",
    "SsrfRemediationOutcome",
    "SsrfRemediationPlan",
    "render_ssrf_artifacts",
    "remediate_ssrf_and_prove",
    "remediate_ssrf_findings",
    "synthesize_ssrf_remediation",
    "verify_ssrf_remediation",
]
