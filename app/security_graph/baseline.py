"""
Zero-config secure baseline oracles.

Sentinel's header-posture and insecure-cookie classes are driven by an
operator-declared oracle. This module supplies a built-in, industry-standard
DECLARED baseline so ``investigate <target>`` runs both classes with no
operator authoring at all — the zero-config path.

The baseline is DECLARED GROUND TRUTH, exactly like an operator-authored policy
file: a curated set of OWASP-aligned secure-default expectations that an
operator implicitly endorses by running Sentinel without a custom policy. It is
NOT a set of findings and it never manufactures one. Every baseline expectation
is still routed into the same prove-chain and decided by the same PURE judge
against a freshly re-probed live response:

  * a header/cookie that satisfies the baseline yields DISPROVED and NO finding
    (the honest differential — a compliant target produces nothing);
  * a finding materialises only when the live response genuinely contradicts a
    declared baseline expectation.

An operator-authored policy always takes precedence; the baseline only fills the
gap when no rules were declared for a class. Set ``$SENTINEL_NO_BASELINE=1`` to
disable the baseline entirely (operator-only mode).
"""

from __future__ import annotations

from .cookies.cookie_policy import CookieExpectation, CookiePolicy, CookieRule
from .posture.header_policy import HeaderExpectation, HeaderPolicy, HeaderRule


# Human-readable provenance shown in the oracle panel, so it is always obvious a
# run used the built-in baseline rather than an operator-authored file.
BASELINE_HEADER_SOURCE = "built-in · OWASP secure-headers baseline"
BASELINE_COOKIE_SOURCE = "built-in · secure-cookie baseline"

# Probed on the app root — every HTTP target serves a root document, and the
# protections below are response-wide browser controls expected on every
# navigation response.
_BASELINE_METHOD = "GET"
_BASELINE_PATH = "/"
_BASELINE_RESOURCE = "app root document"


# --- security-header baseline ----------------------------------------------
# A curated OWASP-aligned secure-headers audit. Each is one unambiguous check
# the PURE judge answers against the live response — never a heuristic score.
_HEADER_EXPECTATIONS = (
    HeaderExpectation(
        header="Content-Security-Policy",
        requirement="must_present",
        severity="HIGH",
        rationale=(
            "A Content-Security-Policy is the primary browser defence against "
            "cross-site scripting and mixed content; its absence leaves "
            "injected script unconstrained."
        ),
    ),
    HeaderExpectation(
        header="Strict-Transport-Security",
        requirement="must_present",
        severity="HIGH",
        rationale=(
            "HSTS forces HTTPS and defeats SSL-stripping downgrade attacks; "
            "absent, a network attacker can transparently downgrade the "
            "connection."
        ),
    ),
    HeaderExpectation(
        header="X-Content-Type-Options",
        requirement="must_present",
        severity="MEDIUM",
        rationale=(
            "Without 'nosniff' a browser may MIME-sniff a response into an "
            "executable type, enabling content-type confusion attacks."
        ),
    ),
    HeaderExpectation(
        header="X-Frame-Options",
        requirement="must_present",
        severity="MEDIUM",
        rationale=(
            "X-Frame-Options (or CSP frame-ancestors) prevents the page being "
            "framed by a hostile site — the clickjacking defence."
        ),
    ),
    HeaderExpectation(
        header="Referrer-Policy",
        requirement="must_present",
        severity="LOW",
        rationale=(
            "A Referrer-Policy prevents the full request URL — which may carry "
            "tokens or identifiers — from leaking to third-party origins."
        ),
    ),
    HeaderExpectation(
        header="Permissions-Policy",
        requirement="must_present",
        severity="LOW",
        rationale=(
            "A Permissions-Policy restricts access to powerful browser features "
            "(camera, microphone, geolocation) an app does not use."
        ),
    ),
    HeaderExpectation(
        header="Access-Control-Allow-Origin",
        requirement="must_not_equal",
        value="*",
        severity="HIGH",
        rationale=(
            "A wildcard CORS origin lets any website read cross-origin "
            "responses; combined with credentialed requests it is a "
            "data-exfiltration primitive."
        ),
    ),
    HeaderExpectation(
        header="X-Powered-By",
        requirement="must_absent",
        severity="LOW",
        rationale=(
            "X-Powered-By discloses server technology and version, narrowing "
            "an attacker's search for known exploits; it should be suppressed."
        ),
    ),
)


def default_header_policy() -> HeaderPolicy:
    """The built-in OWASP-aligned secure-headers baseline (probed on ``GET /``)."""
    return HeaderPolicy(
        rules=(
            HeaderRule(
                method=_BASELINE_METHOD,
                path=_BASELINE_PATH,
                resource=_BASELINE_RESOURCE,
                expectations=_HEADER_EXPECTATIONS,
            ),
        )
    )


# --- secure-cookie baseline -------------------------------------------------
# ``cookie_name`` is empty, so each check asserts against EVERY Set-Cookie the
# route actually issues. A target that sets no cookie on the root yields
# DISPROVED and no finding — the honest differential, never a manufactured one.
_COOKIE_EXPECTATIONS = (
    CookieExpectation(
        cookie_name="",
        check="must_have_flag",
        flag="HttpOnly",
        severity="HIGH",
        rationale=(
            "A session cookie without HttpOnly is readable from JavaScript, so "
            "any XSS becomes full session theft."
        ),
    ),
    CookieExpectation(
        cookie_name="",
        check="must_have_flag",
        flag="Secure",
        severity="MEDIUM",
        rationale=(
            "Without Secure a cookie is transmitted over plain HTTP and can be "
            "captured by a network attacker."
        ),
    ),
    CookieExpectation(
        cookie_name="",
        check="samesite_must_not_equal",
        value="None",
        severity="MEDIUM",
        rationale=(
            "SameSite=None sends the cookie on cross-site requests, the "
            "precondition for cross-site request forgery; a session cookie "
            "should be Lax or Strict."
        ),
    ),
)


def default_cookie_policy() -> CookiePolicy:
    """The built-in secure-cookie baseline (every ``Set-Cookie`` on ``GET /``)."""
    return CookiePolicy(
        rules=(
            CookieRule(
                method=_BASELINE_METHOD,
                path=_BASELINE_PATH,
                resource=_BASELINE_RESOURCE,
                expectations=_COOKIE_EXPECTATIONS,
            ),
        )
    )


# --- serialization ----------------------------------------------------------
# Emit the baseline (or any policy) back to the JSON `header_rules`/`cookie_rules`
# shape the parsers accept, so the spec importer can attach the same baseline to
# a candidate document from a single source of truth.


def header_rules_payload(policy: HeaderPolicy) -> list[dict]:
    """Serialise a :class:`HeaderPolicy` to a ``header_rules`` JSON array."""
    rules: list[dict] = []
    for rule in policy.rules:
        expectations: list[dict] = []
        for exp in rule.expectations:
            item: dict = {
                "header": exp.header,
                "requirement": exp.requirement,
                "severity": exp.severity,
            }
            if exp.value is not None:
                item["value"] = exp.value
            if exp.rationale:
                item["rationale"] = exp.rationale
            expectations.append(item)
        rules.append(
            {
                "method": rule.method,
                "path": rule.path,
                "resource": rule.resource,
                "expectations": expectations,
            }
        )
    return rules


def cookie_rules_payload(policy: CookiePolicy) -> list[dict]:
    """Serialise a :class:`CookiePolicy` to a ``cookie_rules`` JSON array."""
    rules: list[dict] = []
    for rule in policy.rules:
        expectations: list[dict] = []
        for exp in rule.expectations:
            item: dict = {
                "check": exp.check,
                "severity": exp.severity,
            }
            if exp.cookie_name:
                item["cookie_name"] = exp.cookie_name
            if exp.flag is not None:
                item["flag"] = exp.flag
            if exp.value is not None:
                item["value"] = exp.value
            if exp.rationale:
                item["rationale"] = exp.rationale
            expectations.append(item)
        rules.append(
            {
                "method": rule.method,
                "path": rule.path,
                "resource": rule.resource,
                "expectations": expectations,
            }
        )
    return rules
