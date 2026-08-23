"""
Insecure cookies — Sentinel's third vulnerability class.

Where `authorization` asks *"can this principal reach this resource?"* and
`posture` asks *"does this endpoint ship the browser-level protections the
operator declared?"*, this axis asks *"are the cookies this endpoint issues
safe to hold a session in?"* — the ``HttpOnly`` / ``Secure`` attributes and a
non-permissive ``SameSite`` value on every ``Set-Cookie``.

A weak session cookie is the classic pivot: missing ``HttpOnly`` invites theft
via XSS, missing ``Secure`` invites transport downgrade, and ``SameSite=None``
opens the door to CSRF. These are exactly the *ingredients* a real attacker
chains with a broken-access-control finding.

The epistemic contract is identical to the other classes and deliberately so:

  * an operator **cookie oracle** (pure data) declares expectations;
  * the seeder routes each expectation into an OPEN `insecure_cookie`
    hypothesis — never a finding;
  * the live probe (the *same* Set-Cookie-capturing HTTP executor) fetches the
    real ``Set-Cookie`` headers;
  * a PURE, deterministic judge parses the observed cookies and compares them
    against the declared expectation, returning VALIDATED / DISPROVED /
    INCONCLUSIVE;
  * a finding materialises only when an *observed* cookie *contradicts* the
    declared posture. A compliant — or simply unset — cookie yields DISPROVED
    and no finding.

Remediation reuses the live enforcement shield: the same reverse proxy that
denies broken-access-control requests can harden the forwarded ``Set-Cookie``,
and the fix is PROVEN when the same judge flips to DISPROVED through it.
Nothing here invents a security verdict, and no expectation is ever asserted
against a cookie the target does not genuinely set.
"""

from .cookie_policy import (
    CookieExpectation,
    CookiePolicy,
    CookieRule,
    load_cookie_policy,
    parse_cookie_policy,
)
from .judge import cookie_posture_expectation, judge_cookie_posture
from .executor import CookieProbeExecutor
from .seed import seed_cookie_policy
from .run import (
    CookieProbeResult,
    investigate_cookie_posture,
    run_cookie_investigation,
)
from .remediation import (
    CookieControlRule,
    CookieRemediationArtifacts,
    CookieRemediationOutcome,
    CookieRemediationPlan,
    render_cookie_artifacts,
    remediate_cookie_findings,
    remediate_cookie_and_prove,
    synthesize_cookie_remediation,
    verify_cookie_remediation,
)

__all__ = [
    "CookieExpectation",
    "CookiePolicy",
    "CookieRule",
    "load_cookie_policy",
    "parse_cookie_policy",
    "cookie_posture_expectation",
    "judge_cookie_posture",
    "CookieProbeExecutor",
    "seed_cookie_policy",
    "CookieProbeResult",
    "investigate_cookie_posture",
    "run_cookie_investigation",
    "CookieControlRule",
    "CookieRemediationArtifacts",
    "CookieRemediationOutcome",
    "CookieRemediationPlan",
    "render_cookie_artifacts",
    "remediate_cookie_findings",
    "remediate_cookie_and_prove",
    "synthesize_cookie_remediation",
    "verify_cookie_remediation",
]
