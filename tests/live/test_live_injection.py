"""Live-target injection wins, made CI-defensible.

These are the SAME SQL-injection confirmations the project has demonstrated by
hand against OWASP Juice Shop and VAmPI, promoted to gated, reproducible tests.
Each pair proves one win end-to-end through the real pipeline, with nothing
mocked:

  * ``*_confirmed`` — the PURE differential judge (via ``make_judge``) re-probes
    the live target and returns ``VALIDATED`` (a reproduced differential with an
    explicit anchor). This is the §1 contract observed live: the judge disposes.
  * ``*_fix_proven`` — ``remediate_injection_findings`` stands a real loopback
    ``RemediationEnforcer`` in front of the target and the same judge FLIPS
    ``VALIDATED -> DISPROVED`` under enforcement. FIX_PROVEN is earned, not
    declared.

Gating: every test here requests a ``*_url`` fixture, so ``tests/conftest.py``
auto-marks it ``live`` and the offline ``-m 'not live'`` default deselects the
whole file. Run them with ``pytest -m live`` once the targets are up
(``docker compose up -d``); an unreachable target SKIPS cleanly via the fixture.

Wins covered:
  * Juice Shop product search ``q`` (query)      — quote-parity error-based SQLi
  * VAmPI ``/users/v1/{username}`` (path)         — path-segment SQLi
  * Juice Shop ``/rest/user/login`` email (json)  — auth-bypass SQLi, 401 anchor
"""
from __future__ import annotations

import pytest

from app.autonomous.hypotheses import Hypothesis
from app.autonomous.judges import make_judge
from app.security_graph.injection.remediation import remediate_injection_findings


def _confirm(hyp: Hypothesis):
    """Run the pure SQLi judge live and assert it VALIDATED the differential.

    Returns the JudgeEvidence — its ``.graph`` carries the OPEN finding the
    remediation stage re-proves on, so a ``*_fix_proven`` test can chain from it
    without opening a second recon socket."""
    judge = make_judge("sql_injection")
    status, reason, evidence = judge(hyp)
    assert status == "VALIDATED", f"expected VALIDATED, got {status}: {reason}"
    assert evidence is not None, "a VALIDATED verdict must carry its proof graph"
    return evidence


def _fix_proven(evidence) -> None:
    """Remediate + prove on the very graph the judge just validated on.

    Asserts the deterministic VALIDATED -> DISPROVED flip under a live loopback
    enforcement shield — the honest definition of FIX_PROVEN."""
    outcomes = remediate_injection_findings(evidence.graph)
    assert outcomes, "no confirmed injection finding to remediate"
    outcome = outcomes[0]
    assert outcome.result == "FIX_PROVEN", (
        f"expected FIX_PROVEN, got {outcome.result}: {outcome.detail}")
    verification = outcome.verification
    assert verification is not None
    assert verification.before_status == "VALIDATED", (
        f"pre-fix injection must still reproduce, got {verification.before_status}")
    assert verification.after_status == "DISPROVED", (
        f"under the shield the injection must stop, got {verification.after_status}")
    assert verification.proven is True


# ---- Juice Shop product search: quote-parity error-based SQLi (query) --------

def _juice_search_hyp(juice_url: str) -> Hypothesis:
    # `q` is interpolated into a SQL string literal; an odd number of quotes
    # breaks the literal (HTTP 500) and an even number restores it (200) — the
    # quote-parity arm's anchor.
    return Hypothesis("sql_injection", f"{juice_url}/rest/products/search?q=apple",
                      "GET", "q", "query", severity="HIGH")


def test_juice_search_sqli_confirmed(juice_url):
    _confirm(_juice_search_hyp(juice_url))


def test_juice_search_sqli_fix_proven(juice_url):
    _fix_proven(_confirm(_juice_search_hyp(juice_url)))


# ---- VAmPI /users/v1/{username}: path-segment SQLi (path) --------------------

def _vampi_path_hyp(vampi_url: str) -> Hypothesis:
    # The trailing path segment (a username) is placed straight into the lookup.
    # The judge's path-baseline anchors on the concrete last segment ("name1"),
    # the default user the /createdb seed guarantees exists.
    return Hypothesis("sql_injection", f"{vampi_url}/users/v1/name1",
                      "GET", "username", "path", severity="HIGH")


def test_vampi_path_sqli_confirmed(vampi_url):
    _confirm(_vampi_path_hyp(vampi_url))


def test_vampi_path_sqli_fix_proven(vampi_url):
    _fix_proven(_confirm(_vampi_path_hyp(vampi_url)))


# ---- Juice Shop /rest/user/login: auth-bypass SQLi (json body, 401 anchor) ---

def _juice_login_hyp(juice_url: str) -> Hypothesis:
    # The email field is interpolated into the identity lookup. A bad credential
    # legitimately answers 401, so the differential's anchor set must include it
    # (success_statuses); the 2xx default would return INCONCLUSIVE.
    return Hypothesis("sql_injection", f"{juice_url}/rest/user/login",
                      "POST", "email", "body_json", severity="HIGH",
                      success_statuses=(200, 401, 403))


def test_juice_login_sqli_confirmed(juice_url):
    _confirm(_juice_login_hyp(juice_url))


def test_juice_login_sqli_fix_proven(juice_url):
    _fix_proven(_confirm(_juice_login_hyp(juice_url)))
