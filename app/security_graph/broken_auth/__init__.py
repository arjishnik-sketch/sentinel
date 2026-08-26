"""
Broken authentication (JWT forgery) — Sentinel's twelfth vulnerability class.

Where `privilege_escalation` asks *"can one authenticated principal cross an
object/function boundary?"*, this axis asks a deeper question about the token
itself: *"does the server authentically VERIFY the token, or does it trust a
token Sentinel minted?"* — the class behind ``alg=none`` acceptance, unsigned
tokens, RS256→HS256 confusion, and weak-secret HMAC forgery.

This class is a privesc-style **three-probe differential**, and that is what
makes it sound. A single status code is never a verdict. For each declared route
the PURE :func:`judge_broken_auth` reads a *control* probe (the GENUINE captured
token as the SOLE authenticator → MUST succeed, proving the route is token-
authenticated and the session valid), a *breach* probe (a FORGED token as the
SOLE authenticator → the validation-flaw probe), and an anonymous *baseline*
probe (NO token → MUST be denied, ruling out a public route). Broken auth is
VALIDATED only when the genuine token works, the forged token ALSO works, AND
anonymous is denied — so the acceptance is provably attributable to a token
Sentinel forged, not to a public route or a cookie session. Every forged payload
carries a benign ``sentinel_forge`` marker claim, so acceptance proves the server
validated a token WE minted rather than merely echoing the original.

The epistemic contract is identical to the other classes and deliberately so:

  * an operator **broken-auth matrix** (pure data — route + forgery strategy)
    declares which routes MUST reject a forged token (or discovery synthesizes
    the routes from live recon, with the ONE live input this hybrid class needs —
    a genuine bearer token captured from an authenticated session, never a file);
  * the seeder derives the forgery PURELY and OFFLINE (see :mod:`.forge`), routes
    each declared boundary into an OPEN `broken_auth` hypothesis — never a
    finding — and skips any check whose forgery is not derivable (a non-JWT token,
    missing material, or an uncrackable strong secret) so nothing is ever claimed
    without a real probe;
  * a PURE, deterministic judge decides the differential from observed status
    codes alone, returning VALIDATED / DISPROVED / INCONCLUSIVE;
  * a finding materialises only when a forged token is PROVABLY accepted where the
    genuine token works and anonymous is denied.

Remediation is **honest by construction**. For a guard-provable forgery
(``alg_none`` / ``unsigned``) it reuses the live enforcement shield as a
**request-guard (virtual patch)** with signature family ``jwt`` — the same reverse
proxy refuses to forward the route's ``Authorization`` header when it carries a
forged/unsigned token while forwarding a genuinely-signed one, and the fix is
PROVEN when the SAME judge flips VALIDATED → DISPROVED through it. For a validly
*signed* forgery (``hs256_confusion`` / ``weak_secret``) no shape-guard can help,
so the outcome is honestly ``ADVISORY_ONLY`` — Sentinel never claims a proof it
cannot earn. The durable fix in every case is handler-side: pin the accepted
algorithms and verify the signature against the real key. Nothing here invents a
verdict, and the engine holds no target-specific logic.
"""

from .broken_auth_policy import (
    BrokenAuthCheck,
    BrokenAuthPolicy,
    BrokenAuthPrincipal,
    ControlRoute,
    GUARD_PROVABLE_STRATEGIES,
    TokenLocation,
    load_broken_auth_policy,
    parse_broken_auth_policy,
)
from .forge import (
    ForgeResult,
    JwtParts,
    decode_jwt,
    derive_forgery,
    strip_bearer,
)
from .judge import (
    BrokenAuthExpectation,
    broken_auth_expectation,
    judge_broken_auth,
)
from .executor import BrokenAuthProbeExecutor
from .seed import broken_auth_target, seed_broken_auth_policy
from .run import (
    BrokenAuthProbeResult,
    investigate_broken_auth,
    run_broken_auth_investigation,
)
from .discover import BrokenAuthDiscovery, synthesize_broken_auth_policy
from .remediation import (
    BrokenAuthControlRule,
    BrokenAuthRemediationArtifacts,
    BrokenAuthRemediationOutcome,
    BrokenAuthRemediationPlan,
    render_broken_auth_artifacts,
    remediate_broken_auth_and_prove,
    remediate_broken_auth_findings,
    synthesize_broken_auth_remediation,
    verify_broken_auth_remediation,
)

__all__ = [
    "BrokenAuthCheck",
    "BrokenAuthPolicy",
    "BrokenAuthPrincipal",
    "ControlRoute",
    "TokenLocation",
    "GUARD_PROVABLE_STRATEGIES",
    "load_broken_auth_policy",
    "parse_broken_auth_policy",
    "ForgeResult",
    "JwtParts",
    "decode_jwt",
    "derive_forgery",
    "strip_bearer",
    "BrokenAuthExpectation",
    "broken_auth_expectation",
    "judge_broken_auth",
    "BrokenAuthProbeExecutor",
    "broken_auth_target",
    "seed_broken_auth_policy",
    "BrokenAuthProbeResult",
    "investigate_broken_auth",
    "run_broken_auth_investigation",
    "BrokenAuthDiscovery",
    "synthesize_broken_auth_policy",
    "BrokenAuthControlRule",
    "BrokenAuthRemediationArtifacts",
    "BrokenAuthRemediationOutcome",
    "BrokenAuthRemediationPlan",
    "render_broken_auth_artifacts",
    "remediate_broken_auth_and_prove",
    "remediate_broken_auth_findings",
    "synthesize_broken_auth_remediation",
    "verify_broken_auth_remediation",
]
