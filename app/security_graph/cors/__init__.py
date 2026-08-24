"""
CORS misconfiguration — Sentinel's tenth vulnerability class.

Where `open_redirect` asks *"does an attacker-controlled parameter control the
redirect destination?"*, this axis asks the access-control analogue: *"does the
server trust an arbitrary cross-origin caller — will it hand a victim's browser a
credentialed cross-origin read from the attacker's site?"*

This class is a **two-probe origin differential**, and that is what makes it
sound. A reflected origin ALONE is never a verdict, and neither is a bare ``*``.
For each declared surface the judge reads a no-Origin *control* anchor probe (the
same request with no ``Origin`` header) and an attacker-Origin *payload* probe
(the same request carrying an ``Origin`` header naming a random, unroutable nonce
origin ``https://sentinel-<nonce>.example``). A CORS misconfiguration is
VALIDATED only when the payload response reflects that exact nonce origin (or
``*``) in ``Access-Control-Allow-Origin`` — a value that could ONLY have come
from our input — AND sets ``Access-Control-Allow-Credentials: true`` — the flag
that makes the response readable cross-site — AND the no-Origin control proves
the reflection is origin-driven rather than a static header. A payload that does
not reflect our origin, reflects it without credentials, or emits the same header
even without an Origin is DISPROVED.

The epistemic contract is identical to the other classes and deliberately so:

  * an operator **CORS matrix** (pure data — method + path) declares which
    cross-origin surface MUST be safe (or discovery synthesizes it from live
    recon);
  * the seeder generates the unforgeable nonce origin once, records it, and
    routes each declared surface into an OPEN `cors_misconfig` hypothesis — never
    a finding;
  * the live probes capture every response header verbatim — the unroutable nonce
    origin is only ever ECHOED back in a header, never contacted;
  * a PURE, deterministic judge decides the differential, returning VALIDATED /
    DISPROVED / INCONCLUSIVE;
  * a finding materialises only when a live payload probe *provably* reflected our
    attacker origin with credentials while the no-Origin control anchored.

Remediation reuses the live enforcement shield as a **response-header rewrite**:
the same reverse proxy forwards the attacker ``Origin`` to the upstream, then
strips ``Access-Control-Allow-Origin`` and the load-bearing
``Access-Control-Allow-Credentials`` from the forwarded response, and the fix is
PROVEN when the SAME judge flips VALIDATED → DISPROVED through it. The durable fix
is to never reflect an arbitrary Origin with credentials. Nothing here invents a
verdict, and the engine holds no target-specific logic.
"""
from .cors_policy import (
    CorsCheck,
    CorsPolicy,
    load_cors_policy,
    make_nonce,
    nonce_host,
    nonce_origin,
    parse_cors_policy,
)
from .judge import (
    CorsExpectation,
    cors_expectation,
    cors_response_headers,
    judge_cors,
)
from .executor import CorsProbeExecutor
from .seed import seed_cors_policy, cors_target
from .run import (
    CorsProbeResult,
    investigate_cors,
    run_cors_investigation,
)
from .discover import CorsDiscovery, synthesize_cors_policy
from .remediation import (
    CorsControlRule,
    CorsRemediationArtifacts,
    CorsRemediationOutcome,
    CorsRemediationPlan,
    render_cors_artifacts,
    remediate_cors_and_prove,
    remediate_cors_findings,
    synthesize_cors_remediation,
    verify_cors_remediation,
)

__all__ = [
    "CorsCheck",
    "CorsPolicy",
    "load_cors_policy",
    "make_nonce",
    "nonce_host",
    "nonce_origin",
    "parse_cors_policy",
    "CorsExpectation",
    "cors_expectation",
    "cors_response_headers",
    "judge_cors",
    "CorsProbeExecutor",
    "seed_cors_policy",
    "cors_target",
    "CorsProbeResult",
    "investigate_cors",
    "run_cors_investigation",
    "CorsDiscovery",
    "synthesize_cors_policy",
    "CorsControlRule",
    "CorsRemediationArtifacts",
    "CorsRemediationOutcome",
    "CorsRemediationPlan",
    "render_cors_artifacts",
    "remediate_cors_and_prove",
    "remediate_cors_findings",
    "synthesize_cors_remediation",
    "verify_cors_remediation",
]
