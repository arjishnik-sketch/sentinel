"""
Security-misconfiguration posture — Sentinel's second vulnerability class.

Where `authorization` asks *"can this principal reach this resource?"*, this
axis asks *"does this endpoint ship the browser-level protections the
operator declared?"* — HTTP security headers (CSP, HSTS, X-Frame-Options,
Referrer-Policy), a non-wildcard CORS policy, and the absence of
information-disclosure headers.

The epistemic contract is identical to authorization and deliberately so:

  * an operator **header-posture oracle** (pure data) declares expectations;
  * the seeder routes each expectation into an OPEN `security_misconfiguration`
    hypothesis — never a finding;
  * the live probe (the *same* header-capturing HTTP executor authorization
    uses) fetches the real response headers;
  * a PURE, deterministic judge compares observed headers against the declared
    expectation and returns VALIDATED / DISPROVED / INCONCLUSIVE;
  * a finding materialises only when observed behaviour *contradicts* the
    declared posture. A compliant header yields DISPROVED and no finding.

Remediation reuses the live enforcement shield: the same reverse proxy that
denies broken-access-control requests can inject / rewrite / strip response
headers, and the fix is PROVEN when the same judge flips to DISPROVED through
it. Nothing here invents a security verdict.
"""

from .header_policy import (
    HeaderExpectation,
    HeaderPolicy,
    HeaderRule,
    load_header_policy,
    parse_header_policy,
)
from .judge import header_posture_expectation, judge_header_posture
from .executor import SecurityHeaderExecutor
from .seed import seed_header_policy
from .run import investigate_header_posture, run_posture_investigation
from .remediation import (
    HeaderControlRule,
    HeaderRemediationArtifacts,
    HeaderRemediationOutcome,
    HeaderRemediationPlan,
    render_header_artifacts,
    remediate_header_findings,
    remediate_header_and_prove,
    synthesize_header_remediation,
    verify_header_remediation,
)

__all__ = [
    "HeaderExpectation",
    "HeaderPolicy",
    "HeaderRule",
    "load_header_policy",
    "parse_header_policy",
    "header_posture_expectation",
    "judge_header_posture",
    "SecurityHeaderExecutor",
    "seed_header_policy",
    "investigate_header_posture",
    "run_posture_investigation",
    "HeaderControlRule",
    "HeaderRemediationArtifacts",
    "HeaderRemediationOutcome",
    "HeaderRemediationPlan",
    "render_header_artifacts",
    "remediate_header_findings",
    "remediate_header_and_prove",
    "synthesize_header_remediation",
    "verify_header_remediation",
]
