"""
Privilege escalation (login matrix) — Sentinel's fourth vulnerability class.

Where `authorization` asks *"can this anonymous/declared principal reach this
resource?"*, `posture` asks *"does this endpoint ship the declared browser-level
protections?"*, and `cookies` asks *"are the issued cookies safe to hold a
session in?"*, this axis asks the question that only becomes reachable once you
are **authenticated**: *"can one real logged-in account cross a privilege
boundary it was never granted?"* — reading another user's object (horizontal /
IDOR / BOLA) or reaching a function reserved for a higher role (vertical).

This class is a **three-probe differential**, and that is what makes it sound. A
single status code is never a verdict: the same live session runs a *control*
probe (the attacker reaching its OWN object, which MUST succeed) and a *breach*
probe (the attacker reaching the forbidden object/function), and the breach
route is replayed once more with NO session as an anonymous *baseline*. Only
when the control succeeds — proving the session is genuinely alive — AND the
breach is granted AND the anonymous baseline is denied does the boundary count
as crossed. The control leg eliminates the "expired session" confound; the
anonymous negative control eliminates the "public route / app returns 200 for
everything" confound, so a granted breach counts only when it is attributable
to the attacker's own identity.

The epistemic contract is identical to the other classes and deliberately so:

  * an operator **login matrix** (pure data — accounts + boundaries) declares
    which principal MUST NOT reach which route, and how the session is carried;
  * the seeder routes each declared boundary into an OPEN `privilege_escalation`
    hypothesis — never a finding;
  * the live probes (the *same* HTTP executor) fetch the real control/breach
    responses;
  * a PURE, deterministic judge compares the observed differential against the
    declared boundary, returning VALIDATED / DISPROVED / INCONCLUSIVE;
  * a finding materialises only when a live session *provably* crossed a
    declared boundary. A boundary that holds — or a session that cannot even
    reach its own object — yields DISPROVED / INCONCLUSIVE and no finding.

Remediation reuses the live enforcement shield: the same reverse proxy that
denies broken-access-control requests denies exactly this attacker session on
exactly the breach route while forwarding everything else — including the
attacker's own legitimate access — and the fix is PROVEN when the same judge
flips to DISPROVED through it (breach 403, control still 2xx). Nothing here
invents a verdict, and the engine holds no target-specific logic: every
host/route/account detail arrives as operator-declared matrix data or a
live-captured session.
"""

from .privesc_policy import (
    PrivEscCheck,
    PrivEscPolicy,
    PrivEscPrincipal,
    load_privesc_policy,
    parse_privesc_policy,
)
from .judge import (
    PrivEscExpectation,
    judge_privilege_escalation,
    privesc_expectation,
)
from .executor import PrivEscProbeExecutor
from .seed import privesc_target, seed_privesc_policy
from .run import (
    PrivEscProbeResult,
    investigate_privilege_escalation,
    run_privesc_investigation,
)
from .remediation import (
    PrivEscControlRule,
    PrivEscRemediationArtifacts,
    PrivEscRemediationOutcome,
    PrivEscRemediationPlan,
    render_privesc_artifacts,
    remediate_privesc_findings,
    remediate_privesc_and_prove,
    synthesize_privesc_remediation,
    verify_privesc_remediation,
)

__all__ = [
    "PrivEscCheck",
    "PrivEscPolicy",
    "PrivEscPrincipal",
    "load_privesc_policy",
    "parse_privesc_policy",
    "PrivEscExpectation",
    "judge_privilege_escalation",
    "privesc_expectation",
    "PrivEscProbeExecutor",
    "privesc_target",
    "seed_privesc_policy",
    "PrivEscProbeResult",
    "investigate_privilege_escalation",
    "run_privesc_investigation",
    "PrivEscControlRule",
    "PrivEscRemediationArtifacts",
    "PrivEscRemediationOutcome",
    "PrivEscRemediationPlan",
    "render_privesc_artifacts",
    "remediate_privesc_findings",
    "remediate_privesc_and_prove",
    "synthesize_privesc_remediation",
    "verify_privesc_remediation",
]
