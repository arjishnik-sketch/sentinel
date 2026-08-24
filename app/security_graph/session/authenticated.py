"""
Turn a captured browser session into oracles the existing prove-chain accepts.

Pure, browser-free, unit-testable. Two builders:

  * :func:`authenticated_policy` fills the *live captured* session headers
    (``Cookie`` + optional bearer) into a named principal of the operator's
    access policy — WITHOUT rewriting any declared decision or re-pointing any
    rule. The operator still declares what the authenticated principal should
    (or should not) reach; the login tester merely supplies the real identity
    so the deterministic judge can test those rules as the logged-in user.

  * :func:`session_baseline_cookie_policy` derives an *advisory* cookie oracle
    from the session's own cookies. It only ever targets cookies the browser
    actually set whose names are session/auth-like, and only declares the
    standard hardening baseline (HttpOnly + Secure + SameSite≠None). It asserts
    nothing: the pure cookie judge still decides each verdict against the flags
    the browser genuinely observed. Grounded in observation, never guessed.
"""

from __future__ import annotations

from dataclasses import replace

from ..policy.access_policy import AccessPolicy, PolicyPrincipal
from ..privesc.privesc_policy import PrivEscPolicy
from ..broken_auth.broken_auth_policy import BrokenAuthPolicy, BrokenAuthPrincipal
from .browser_login import SESSION_COOKIE_NAMES, CapturedSession


def _bearer_header(session: CapturedSession) -> tuple[tuple[str, str], ...]:
    """The bearer token as the SOLE authenticator header, or () if none.

    Broken-auth isolates the TOKEN as the sole authenticator (no cookie), so a
    route guarded by cookie rather than token cannot pass the control probe and
    never yields a false positive.
    """
    if not session.bearer:
        return ()
    return (("Authorization", f"Bearer {session.bearer}"),)


def broken_auth_principal_from_session(
    session: CapturedSession,
    *,
    name: str = "authenticated",
    role: str = "user",
) -> BrokenAuthPrincipal:
    """Build a broken-auth principal carrying ONLY the session's bearer token.

    A session with no bearer yields a principal with no headers — the honest
    failure mode: the seeder finds no genuine token, so it seeds no probe and
    nothing is ever claimed.
    """
    return BrokenAuthPrincipal(
        name=name,
        headers=_bearer_header(session),
        role=role,
    )


def broken_auth_policy_from_session(
    policy: BrokenAuthPolicy,
    session: CapturedSession,
    *,
    name: str = "authenticated",
) -> BrokenAuthPolicy:
    """
    Bind a LIVE captured session's bearer token into a broken-auth matrix.

    The operator matrix declares only *structure* (which routes must reject a
    forged token, and the forgery strategy); the one credential this class needs —
    a genuine bearer token to forge FROM — is supplied here from a real browser
    login, never read from a file. The token is bound as the SOLE authenticator
    (Authorization only, no cookie). A session with no bearer leaves the principal
    tokenless, so the control probe cannot succeed and the judge returns
    INCONCLUSIVE rather than a manufactured finding.
    """
    role = policy.principal.role if policy.principal is not None else "user"
    principal_name = policy.principal.name if policy.principal is not None else name
    principal = BrokenAuthPrincipal(
        name=principal_name,
        headers=_bearer_header(session),
        role=role,
    )
    return replace(policy, principal=principal)


def session_headers(
    session: CapturedSession,
) -> tuple[tuple[str, str], ...]:
    """The request headers that replay this session as the caller."""
    headers: list[tuple[str, str]] = []
    if session.cookie_header:
        headers.append(("Cookie", session.cookie_header))
    if session.bearer:
        headers.append(("Authorization", f"Bearer {session.bearer}"))
    return tuple(headers)


def authenticated_policy(
    base_policy: AccessPolicy | None,
    session: CapturedSession,
    *,
    principal_name: str = "authenticated",
) -> AccessPolicy | None:
    """
    Return the operator policy with the captured session's live headers merged
    into ``principal_name``. Declared decisions and rule→principal bindings are
    left untouched. Returns ``None`` when there is no operator policy to test —
    authenticated authz then has nothing to prove and is honestly skipped.
    """
    if base_policy is None:
        return None

    headers = session_headers(session)

    principals: list[PolicyPrincipal] = []
    replaced = False
    for principal in base_policy.principals:
        if principal.name == principal_name:
            principals.append(
                PolicyPrincipal(
                    name=principal.name,
                    kind=principal.kind,
                    roles=principal.roles,
                    headers=headers,
                )
            )
            replaced = True
        else:
            principals.append(principal)

    if not replaced:
        principals.append(
            PolicyPrincipal(
                name=principal_name,
                kind="user",
                roles=(),
                headers=headers,
            )
        )

    return AccessPolicy(principals=tuple(principals), rules=base_policy.rules)


def session_baseline_cookie_policy(
    session: CapturedSession,
    *,
    method: str = "GET",
    path: str = "/",
    severity: str = "HIGH",
) -> dict:
    """
    Build a ``cookie_rules`` payload (advisory hardening baseline) for the
    session-like cookies the browser actually set. Returns an empty payload
    (``{"cookie_rules": []}``) when the session carries no session-like cookie,
    so no expectation is ever manufactured for a cookie that was not observed.
    """
    expectations: list[dict] = []
    for cookie in session.cookies:
        if cookie.name.strip().lower() not in SESSION_COOKIE_NAMES:
            continue
        expectations.append(
            {
                "cookie_name": cookie.name,
                "check": "must_have_flag",
                "flag": "HttpOnly",
                "severity": severity,
            }
        )
        expectations.append(
            {
                "cookie_name": cookie.name,
                "check": "must_have_flag",
                "flag": "Secure",
                "severity": severity,
            }
        )
        expectations.append(
            {
                "cookie_name": cookie.name,
                "check": "samesite_must_not_equal",
                "value": "None",
                "severity": severity,
            }
        )

    if not expectations:
        return {"cookie_rules": []}

    return {
        "cookie_rules": [
            {
                "method": method,
                "path": path,
                "resource": "authenticated session",
                "expectations": expectations,
            }
        ]
    }


def privesc_policy_from_sessions(
    policy: PrivEscPolicy,
    sessions: list[CapturedSession | None],
) -> PrivEscPolicy:
    """
    Bind LIVE captured sessions to an operator login-matrix policy.

    ``sessions[i]`` supplies the identifying request headers (``Cookie`` +
    optional bearer) for ``policy.principals[i]`` — so the first account the
    operator logged in as is principal #0, the second is principal #1, and so
    on. The matrix declares only *structure* (which accounts exist, the control
    endpoint each legitimately owns, and the boundaries an attacker must not
    cross); every credential is supplied here from a real browser login, so no
    token is ever read from or written to a policy file.

    A principal with no captured session keeps its declared (typically empty)
    headers. That is the honest failure mode: its control probe cannot succeed,
    so the three-probe judge returns INCONCLUSIVE and no finding is manufactured.
    Declared control/breach paths and check directions are never rewritten — the
    deterministic judge still decides every verdict from the live differential.
    """
    principals = []
    for index, principal in enumerate(policy.principals):
        session = sessions[index] if index < len(sessions) else None
        if session is not None:
            principals.append(
                replace(principal, headers=session_headers(session))
            )
        else:
            principals.append(principal)

    return replace(policy, principals=tuple(principals))
