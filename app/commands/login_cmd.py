"""
`login <target> [login_url] [access_policy.json]` — Sentinel's Login Tester.

Open a real, visible browser; the operator logs in with their own credentials
and completes MFA; Sentinel auto-detects completion (or the operator presses
Enter), captures the authenticated session, and then reasons over it with the
existing prove-chain:

  * **authenticated authorization** — the captured session's live headers are
    supplied to the operator's declared `authenticated` principal, so the
    deterministic judge tests those access rules AS the logged-in user;
  * **insecure cookies** — the session's real cookies (with their genuine
    HttpOnly/Secure/SameSite) are judged against a hardening baseline, and each
    confirmed weak cookie is PATCH+PROVEN against the exact observed cookie.

Credentials are read with getpass and held in memory for the run only — never
stored, never logged. Playwright is an opt-in extra, imported lazily.
"""

import getpass
import os
import sys
import threading

from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.models import Evidence, ExecutionResult

from .investigate_cmd import (
    console,
    _C_ACCENT,
    _C_BAD,
    _C_DIM,
    _C_OK,
    _C_PRIMARY,
    _C_WARN,
    _short,
    _banner,
    _findings_panel,
    _remediation_panel,
    _cookie_findings_panel,
    _cookie_remediation_panel,
    _privesc_matrix_panel,
    _privesc_findings_panel,
    _privesc_remediation_panel,
    _broken_auth_matrix_panel,
    _broken_auth_findings_panel,
    _broken_auth_remediation_panel,
    _gate_remediation,
)


class _CapturedCookieExecutor(ExperimentExecutor):
    """
    In-memory cookie executor: replays the EXACT Set-Cookie lines the browser
    observed (or their corrected form during PROVE). No network — the session's
    cookies are already captured, so the pure judge measures real posture.
    """

    kind = "cookie_check"

    def __init__(self, set_cookies, *, status_code=200):
        self._cookies = list(set_cookies)
        self._status = status_code

    def execute(self, experiment):
        evidence = Evidence(
            id=f"ev:session-cookie:{experiment.id}",
            source="captured_session",
            data={
                "mode": "http",
                "status_code": self._status,
                "response_headers": {},
                "set_cookie": list(self._cookies),
                "url": experiment.request.url if experiment.request else "",
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", str(self._status)),),
        )


def _mask(value: str, keep: int = 3) -> str:
    """Redact a secret-ish value for display — never print full credentials."""
    text = str(value or "")
    if len(text) <= keep:
        return "•" * len(text)
    return text[:keep] + "…" + f"({len(text)} chars)"


def _session_panel(session, target: str, login_url: str | None) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_C_DIM, justify="right")
    table.add_column(style="white")

    table.add_row("target", f"[{_C_PRIMARY}]{_short(target, 60)}[/{_C_PRIMARY}]")
    if login_url:
        table.add_row("login url", f"[{_C_DIM}]{_short(login_url, 60)}[/{_C_DIM}]")
    if session.final_url:
        table.add_row("landed on", f"[{_C_DIM}]{_short(session.final_url, 60)}[/{_C_DIM}]")
    table.add_row(
        "session cookies",
        f"[{_C_ACCENT}]{len(session.cookies)}[/{_C_ACCENT}] captured",
    )
    table.add_row(
        "bearer token",
        f"[{_C_OK}]present[/{_C_OK}] [{_C_DIM}]{_mask(session.bearer)}[/{_C_DIM}]"
        if session.bearer
        else f"[{_C_DIM}]none[/{_C_DIM}]",
    )

    cookies = Table(
        show_header=True,
        header_style=f"bold {_C_ACCENT}",
        border_style=_C_ACCENT,
        expand=True,
    )
    cookies.add_column("cookie")
    cookies.add_column("HttpOnly", justify="center")
    cookies.add_column("Secure", justify="center")
    cookies.add_column("SameSite")
    for cookie in session.cookies:
        def _yn(flag, good):
            style = _C_OK if flag == good else _C_BAD
            return f"[{style}]{'yes' if flag else 'no'}[/{style}]"

        ss = cookie.same_site or "—"
        ss_style = _C_BAD if cookie.same_site == "None" else _C_DIM
        cookies.add_row(
            f"[white]{_short(cookie.name, 28)}[/white]",
            _yn(cookie.http_only, True),
            _yn(cookie.secure, True),
            f"[{ss_style}]{ss}[/{ss_style}]",
        )

    note = Text(
        "\nCredentials were used only to drive the live login — never stored, "
        "never logged. The session is held in memory for this run only. Cookie "
        "attributes above are exactly what the browser observed.",
        style=_C_DIM,
    )

    blocks = [table]
    if session.cookies:
        blocks += [Rule(style=_C_DIM), cookies]
    blocks.append(note)

    return Panel(
        Group(*blocks),
        title=f"[{_C_ACCENT}]▐ AUTHENTICATED SESSION CAPTURED[/{_C_ACCENT}]",
        border_style=_C_ACCENT,
        padding=(1, 2),
    )


def _chain_panel(
    authz_confirmed, cookie_confirmed, privesc_confirmed=(), broken_auth_confirmed=()
) -> Panel:
    """Honest chaining view: co-occurring proven ingredients for one session."""
    have_authz = bool(authz_confirmed)
    have_cookie = bool(cookie_confirmed)
    have_privesc = bool(privesc_confirmed)
    have_broken_auth = bool(broken_auth_confirmed)

    def _mark(ok: bool) -> str:
        return f"[{_C_OK}]✔[/{_C_OK}]" if ok else f"[{_C_DIM}]·[/{_C_DIM}]"

    lines = [
        f"{_mark(True)} authenticated session captured (real cookies + bearer)",
        f"{_mark(have_cookie)} session cookie proven insecure "
        f"[{_C_DIM}]({len(cookie_confirmed)} insecure_cookie CONFIRMED)[/{_C_DIM}]",
        f"{_mark(have_authz)} resource reachable as this authenticated principal "
        f"[{_C_DIM}]({len(authz_confirmed)} authorization_policy_violation "
        f"CONFIRMED)[/{_C_DIM}]",
        f"{_mark(have_privesc)} privilege boundary crossed by this live session "
        f"[{_C_DIM}]({len(privesc_confirmed)} privilege_escalation "
        f"CONFIRMED)[/{_C_DIM}]",
        f"{_mark(have_broken_auth)} forged token accepted where the genuine one "
        f"works [{_C_DIM}]({len(broken_auth_confirmed)} broken_auth "
        f"CONFIRMED)[/{_C_DIM}]",
    ]
    body = Text.from_markup("\n".join(lines))

    proven_count = sum(
        (have_authz, have_cookie, have_privesc, have_broken_auth)
    )
    if proven_count >= 2:
        verdict = Text(
            "\nMultiple independently-PROVEN ingredients co-occur on this one "
            "session — the raw material of a real attack chain (weak session "
            "cookie → session theft → authenticated access → privilege "
            "escalation). Sentinel presents them as co-occurring evidence; it "
            "does NOT auto-compose a causal exploit narrative — full chaining "
            "remains the honestly-labeled frontier.",
            style=_C_WARN,
        )
    else:
        verdict = Text(
            "\nNo complete chain: the ingredients above did not all reproduce "
            "on this session. Sentinel never manufactures a chain from absent "
            "evidence.",
            style=_C_DIM,
        )

    return Panel(
        Group(body, verdict),
        title=f"[{_C_WARN}]▐ CHAINING · INGREDIENTS (HONEST)[/{_C_WARN}]",
        border_style=_C_WARN,
        padding=(1, 2),
    )


def _parse_args(arg: str):
    """login <target> [login_url] [cycles] [access_policy.json]"""
    parts = arg.split()
    target = parts[0]
    login_url = None
    policy_path = None
    max_cycles = 8
    for token in parts[1:]:
        if token.isdigit():
            max_cycles = max(1, min(100, int(token)))
        elif token.lower().startswith(("http://", "https://")):
            login_url = token
        else:
            policy_path = token
    if policy_path is None:
        policy_path = os.environ.get("SENTINEL_ACCESS_POLICY") or None
    return target, login_url, max_cycles, policy_path


def _enter_watcher() -> "threading.Event":
    """Background thread: set an Event when the operator presses Enter."""
    done = threading.Event()

    def _wait():
        try:
            for _ in sys.stdin:
                break
        except Exception:
            pass
        done.set()

    thread = threading.Thread(target=_wait, daemon=True)
    thread.start()
    return done


def _prove_session_cookies(graph, cookie_confirmed, observed_lines):
    """
    PATCH+PROVE each confirmed session cookie against the EXACT observed cookie.

    The corrective control is applied by the real `apply_cookie_mutations`
    primitive to the observed Set-Cookie, and the SAME pure judge must flip
    VALIDATED→DISPROVED on the corrected cookie. No live proxy is stood up —
    the session's cookies are already captured, so proving happens against the
    genuine observed cookie, not an invented target.
    """
    from app.security_graph.cookies import (
        remediate_cookie_and_prove,
        synthesize_cookie_remediation,
    )
    from app.security_graph.remediation.enforcer import (
        CookieAttributeRule,
        apply_cookie_mutations,
    )

    outcomes = []
    for finding in sorted(cookie_confirmed, key=lambda item: item.id):
        plan = synthesize_cookie_remediation(graph, finding)
        if plan is None:
            outcomes.append(
                remediate_cookie_and_prove(graph, finding, use_enforcer=False)
            )
            continue
        rule = plan.rule
        attribute_rule = CookieAttributeRule(
            method=rule.method,
            path=rule.path,
            cookie_name=rule.cookie_name,
            op=rule.op,
            flag=rule.flag,
            value=rule.value,
        )
        corrected_headers = apply_cookie_mutations(
            [("Set-Cookie", line) for line in observed_lines],
            rule.method,
            rule.path,
            (attribute_rule,),
        )
        after_lines = [v for n, v in corrected_headers if n == "Set-Cookie"]
        outcomes.append(
            remediate_cookie_and_prove(
                graph,
                finding,
                before_executor=_CapturedCookieExecutor(observed_lines),
                after_executor=_CapturedCookieExecutor(after_lines),
                use_enforcer=False,
            )
        )
    return outcomes


def run(arg):
    if not arg or not arg.strip():
        console.print(
            f"[{_C_BAD}]Usage:[/{_C_BAD}] login <target> [login_url] "
            f"[cycles] [access_policy.json]\n"
            f"[dim]e.g. login http://127.0.0.1:3000 "
            f"http://127.0.0.1:3000/#/login samples/juice_shop_access_policy.json"
            f"[/dim]\n"
            f"[dim]opens a real browser; log in + finish MFA, then Sentinel "
            f"auto-detects (or press Enter) and captures the session[/dim]\n"
            f"[dim]a 'privesc_matrix' in the policy (or $SENTINEL_PRIVESC_POLICY) "
            f"adds a 2-account horizontal/vertical privilege-escalation pass[/dim]\n"
            f"[dim]needs the opt-in extra: pip install -e \".[login]\" && "
            f"python -m playwright install chromium[/dim]"
        )
        return

    target, login_url, max_cycles, policy_path = _parse_args(arg.strip())
    principal_name = os.environ.get("SENTINEL_LOGIN_PRINCIPAL") or "authenticated"
    skip_remediation = bool(os.environ.get("SENTINEL_SKIP_REMEDIATION"))

    # Lazy: the browser stack and research engine are opt-in / heavy.
    from app.security_graph.session import (
        authenticated_policy,
        capture_session,
        reconstruct_set_cookie,
        session_baseline_cookie_policy,
        LoginDependencyError,
    )

    console.print()
    console.print(_banner())
    console.print(
        Text(
            "Login Tester — your credentials drive a live browser and are never "
            "stored or logged.",
            style=_C_DIM,
        )
    )

    # Operator credentials: username visible, password via getpass. Held in
    # memory only for this run; never persisted, never echoed to a log.
    try:
        username = console.input(f"[{_C_PRIMARY}]username/email > [/{_C_PRIMARY}]").strip()
        password = getpass.getpass("password > ")
    except (KeyboardInterrupt, EOFError):
        console.print(f"\n[{_C_DIM}]login cancelled[/{_C_DIM}]")
        return

    # Load an operator access policy if provided (may carry authz rules for the
    # `authenticated` principal and/or a cookie_rules section).
    base_policy = None
    if policy_path:
        from app.security_graph.policy import load_access_policy

        try:
            base_policy = load_access_policy(policy_path)
        except Exception as exc:  # noqa: BLE001 — surface cleanly
            console.print(
                Panel(
                    Text(f"Failed to load access policy '{policy_path}': {exc}",
                         style=_C_BAD),
                    title=f"[{_C_BAD}]access policy error[/{_C_BAD}]",
                    border_style=_C_BAD,
                )
            )
            base_policy = None

    console.print()
    console.print(
        Text(
            "A browser window will open. Complete login + MFA there; Sentinel "
            "auto-detects the session, or press Enter here when done.",
            style=_C_WARN,
        )
    )

    done = _enter_watcher()
    try:
        session = capture_session(
            target,
            username=username,
            password=password,
            login_url=login_url,
            manual_done=done.is_set,
            on_status=lambda m: console.print(f"[{_C_DIM}]  · {m}[/{_C_DIM}]"),
        )
    except LoginDependencyError as exc:
        console.print(
            Panel(
                Text(str(exc), style=_C_WARN),
                title=f"[{_C_WARN}]login tester unavailable[/{_C_WARN}]",
                border_style=_C_WARN,
                padding=(1, 2),
            )
        )
        return
    except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
        console.print(
            Panel(
                Text(str(exc), style=_C_BAD),
                title=f"[{_C_BAD}]login failed[/{_C_BAD}]",
                border_style=_C_BAD,
            )
        )
        return
    finally:
        # Never keep the plaintext password around beyond capture.
        password = None
        del password

    console.print()
    console.print(_session_panel(session, target, login_url))

    # --- AUTHENTICATED AUTHORIZATION -------------------------------------
    # Supply the captured session's live headers to the operator's declared
    # `authenticated` principal, then run the standard prove-chain. Declared
    # decisions are never rewritten — the judge tests the operator's rules AS
    # the logged-in user. With no operator policy there is nothing to prove and
    # we say so honestly (the cookie class still runs on the real session).
    from app.security_graph.orchestration.target import TargetResearchPipeline

    auth_policy = authenticated_policy(
        base_policy, session, principal_name=principal_name
    )

    console.print()
    console.print(
        Rule(
            f"[bold {_C_PRIMARY}]AUTHENTICATED RESEARCH · "
            f"principal '{principal_name}'[/bold {_C_PRIMARY}]",
            style=_C_PRIMARY,
        )
    )
    if auth_policy is None:
        console.print(
            Text(
                "  no access policy supplied → no authenticated authorization "
                "rules to prove. Provide one with an 'authenticated' principal "
                "to test access as the logged-in user.",
                style=_C_DIM,
            )
        )

    result = None
    authz_confirmed = []
    try:
        with console.status(
            f"[{_C_PRIMARY}]recon + authenticated research "
            f"({max_cycles} cycle budget)…[/{_C_PRIMARY}]",
            spinner="dots",
        ):
            result = TargetResearchPipeline().run(
                target, max_cycles=max_cycles, access_policy=auth_policy
            )
        console.print(_findings_panel(result))
        authz_confirmed = list(
            result.graph.findings_for(
                kind="authorization_policy_violation", status="OPEN"
            )
        )
        if authz_confirmed and not skip_remediation:
            from app.security_graph.remediation import (
                remediate_confirmed_findings,
                synthesize_remediation,
            )
            from app.commands.remediation_gate import RemediationProposal

            console.print()
            console.print(
                Rule(
                    f"[bold {_C_OK}]REMEDIATION · PATCH + PROVE · "
                    f"{len(authz_confirmed)} FINDING(S)[/bold {_C_OK}]",
                    style=_C_OK,
                )
            )
            # Show the proposed controls and take the operator's approval
            # BEFORE any shield is stood up or any fix is proven.
            proposals = []
            for finding in authz_confirmed:
                plan = synthesize_remediation(result.graph, finding)
                if plan is None:
                    control = "route-level deny (no shieldable plan derived)"
                else:
                    control = (
                        f"deny {plan.rule.principal_name} → "
                        f"{plan.rule.method} {plan.rule.path}"
                    )
                proposals.append(
                    RemediationProposal(
                        title=finding.title,
                        severity=finding.severity,
                        control=control,
                    )
                )

            if _gate_remediation(
                class_label="authenticated authorization",
                color=_C_OK,
                proposals=proposals,
            ):
                with console.status(
                    f"[{_C_OK}]synthesizing controls + proving fixes live…"
                    f"[/{_C_OK}]",
                    spinner="dots",
                ):
                    authz_outcomes = remediate_confirmed_findings(result.graph)
                for remediation in authz_outcomes:
                    console.print(_remediation_panel(remediation))
    except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
        console.print(
            Panel(
                Text(str(exc), style=_C_BAD),
                title=f"[{_C_BAD}]authenticated research failed[/{_C_BAD}]",
                border_style=_C_BAD,
            )
        )

    # --- INSECURE COOKIES ON THE CAPTURED SESSION ------------------------
    cookie_confirmed = []
    if result is not None:
        cookie_confirmed = _run_cookie_pass(
            result.graph, session, target, policy_path, skip_remediation,
            reconstruct_set_cookie, session_baseline_cookie_policy,
        )

    # --- PRIVILEGE ESCALATION (login matrix, Tier 2) ---------------------
    # Only runs when the operator declares a login matrix (a `privesc_matrix`
    # section or $SENTINEL_PRIVESC_POLICY). The account just captured is
    # principal #0; any further declared principal triggers its own live login
    # so its real session identity — never a file credential — drives the probe.
    def _capture_additional(principal_label):
        console.print()
        console.print(
            Text(
                f"Log in as matrix principal '{principal_label}'. A browser "
                "window opens; finish login + MFA, then press Enter here.",
                style=_C_WARN,
            )
        )
        try:
            extra_user = console.input(
                f"[{_C_PRIMARY}]{principal_label} username/email > "
                f"[/{_C_PRIMARY}]"
            ).strip()
            extra_pass = getpass.getpass(f"{principal_label} password > ")
        except (KeyboardInterrupt, EOFError):
            console.print(
                f"[{_C_DIM}]  capture cancelled for '{principal_label}'"
                f"[/{_C_DIM}]"
            )
            return None
        extra_done = _enter_watcher()
        try:
            extra_session = capture_session(
                target,
                username=extra_user,
                password=extra_pass,
                login_url=login_url,
                manual_done=extra_done.is_set,
                on_status=lambda m: console.print(
                    f"[{_C_DIM}]  · {m}[/{_C_DIM}]"
                ),
            )
        except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
            console.print(
                Panel(
                    Text(str(exc), style=_C_BAD),
                    title=(
                        f"[{_C_BAD}]login failed for '{principal_label}'"
                        f"[/{_C_BAD}]"
                    ),
                    border_style=_C_BAD,
                )
            )
            return None
        finally:
            extra_pass = None
            del extra_pass
        console.print(_session_panel(extra_session, target, login_url))
        return extra_session

    privesc_confirmed = []
    if result is not None:
        privesc_confirmed = _run_privesc_pass(
            result.graph, target, session, policy_path, skip_remediation,
            _capture_additional,
        )

    # --- BROKEN AUTHENTICATION (JWT forgery, Tier 3, hybrid) -------------
    # The one honestly-labelled login-seeded/hybrid class: it needs ONE live
    # input — a genuine bearer token to forge FROM, captured above, never a
    # file. Given that token it forges (alg=none / unsigned / and, with operator
    # material, signed) and runs the three-probe control/breach/baseline
    # differential. With no captured JWT bearer, no forgery is derivable and the
    # pass is honestly skipped.
    broken_auth_confirmed = []
    if result is not None:
        broken_auth_confirmed = _run_broken_auth_pass(
            result.graph, target, session, policy_path, skip_remediation,
        )

    # --- CHAINING (honest ingredients) -----------------------------------
    console.print()
    console.print(
        _chain_panel(
            authz_confirmed, cookie_confirmed, privesc_confirmed,
            broken_auth_confirmed,
        )
    )
    console.print()


def _run_cookie_pass(
    graph, session, target, policy_path, skip_remediation,
    reconstruct_set_cookie, session_baseline_cookie_policy,
):
    """Run the insecure-cookie class over the captured session's cookies."""
    from app.security_graph.cookies import (
        parse_cookie_policy,
        run_cookie_investigation,
    )

    observed_lines = [reconstruct_set_cookie(c) for c in session.cookies]

    # Prefer the operator's own cookie_rules (if the policy file carries a
    # section); else fall back to the advisory session hardening baseline,
    # scoped only to session-like cookies the browser actually set.
    cookie_policy = None
    source = "operator cookie_rules"
    if policy_path:
        try:
            from app.security_graph.cookies import load_cookie_policy

            loaded = load_cookie_policy(policy_path)
            if loaded.rules:
                cookie_policy = loaded
        except Exception:
            cookie_policy = None
    if cookie_policy is None:
        source = "Sentinel session-cookie baseline (advisory)"
        cookie_policy = parse_cookie_policy(
            session_baseline_cookie_policy(session)
        )

    console.print()
    console.print(
        Rule(
            f"[bold {_C_ACCENT}]INSECURE COOKIES · SESSION SAFETY[/bold {_C_ACCENT}]",
            style=_C_ACCENT,
        )
    )
    if not cookie_policy.rules:
        console.print(
            Text(
                "  the captured session set no session-like cookie to judge — "
                "no cookie expectation is manufactured (honest differential).",
                style=_C_DIM,
            )
        )
        return []

    console.print(Text(f"  oracle: {source}", style=_C_DIM))
    try:
        with console.status(
            f"[{_C_ACCENT}]judging captured Set-Cookie posture…[/{_C_ACCENT}]",
            spinner="dots",
        ):
            cookie_results = run_cookie_investigation(
                graph,
                cookie_policy,
                target_base=target,
                executor=_CapturedCookieExecutor(observed_lines),
            )
        if cookie_results:
            console.print(_cookie_findings_panel(cookie_results))

        cookie_confirmed = list(
            graph.findings_for(kind="insecure_cookie", status="OPEN")
        )
        if cookie_confirmed and not skip_remediation:
            from app.security_graph.cookies import synthesize_cookie_remediation
            from app.commands.remediation_gate import RemediationProposal

            console.print()
            console.print(
                Rule(
                    f"[bold {_C_OK}]COOKIE REMEDIATION · PATCH + PROVE · "
                    f"{len(cookie_confirmed)} FINDING(S)[/bold {_C_OK}]",
                    style=_C_OK,
                )
            )
            proposals = []
            for finding in cookie_confirmed:
                plan = synthesize_cookie_remediation(graph, finding)
                if plan is None:
                    control = "Set-Cookie hardening (no plan derived)"
                else:
                    detail = plan.rule.flag or plan.rule.value
                    name = plan.rule.cookie_name or "every Set-Cookie"
                    control = (
                        f"{plan.rule.op} {detail} on '{name}'  "
                        f"({plan.rule.method} {plan.rule.path})"
                    )
                proposals.append(
                    RemediationProposal(
                        title=finding.title,
                        severity=finding.severity,
                        control=control,
                    )
                )

            if _gate_remediation(
                class_label="insecure cookies",
                color=_C_OK,
                proposals=proposals,
            ):
                with console.status(
                    f"[{_C_OK}]hardening the observed cookie + proving…"
                    f"[/{_C_OK}]",
                    spinner="dots",
                ):
                    cookie_outcomes = _prove_session_cookies(
                        graph, cookie_confirmed, observed_lines
                    )
                for remediation in cookie_outcomes:
                    console.print(_cookie_remediation_panel(remediation))
        return cookie_confirmed
    except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
        console.print(
            Panel(
                Text(str(exc), style=_C_BAD),
                title=f"[{_C_BAD}]insecure cookie stage failed[/{_C_BAD}]",
                border_style=_C_BAD,
            )
        )
        return []


def _load_privesc_matrix(policy_path):
    """
    Resolve an operator LOGIN MATRIX (structure only — never credentials).

    Source order: ``$SENTINEL_PRIVESC_POLICY`` (a dedicated matrix file), else a
    ``privesc_matrix`` section embedded in the access-policy file. Returns
    ``(policy_or_None, source_or_None)``; a file with no matrix yields
    ``(None, None)`` and the privilege-escalation pass is simply not requested.
    """
    import json

    from app.security_graph.privesc import load_privesc_policy

    source = os.environ.get("SENTINEL_PRIVESC_POLICY") or None
    if source is None and policy_path:
        try:
            with open(policy_path, encoding="utf-8") as handle:
                combined = json.load(handle)
            if isinstance(combined, dict) and combined.get("privesc_matrix"):
                source = policy_path
        except Exception:  # noqa: BLE001 — a bad file is reported elsewhere
            source = None
    if not source:
        return None, None
    return load_privesc_policy(source), source


def _run_privesc_pass(
    graph, target, first_session, policy_path, skip_remediation, capture_more,
):
    """
    Tier-2 authenticated class: prove horizontal/vertical privilege escalation
    across a live LOGIN MATRIX.

    The matrix declares only STRUCTURE — the accounts, the control endpoint each
    legitimately owns, and the boundaries an attacker MUST NOT cross. Every
    session identity is supplied from a REAL browser login (never a file): the
    account just used is principal #0, and when the matrix declares further
    principals the operator is prompted to log in as each. A three-probe
    (control + breach + anonymous baseline) differential means a bare status
    code is never the verdict; a principal with no live session goes
    INCONCLUSIVE — never a manufactured finding. Returns the CONFIRMED
    escalation findings.
    """
    from app.security_graph.session import privesc_policy_from_sessions

    matrix, source = _load_privesc_matrix(policy_path)
    if matrix is None or not matrix.checks:
        return []

    console.print()
    console.print(
        Rule(
            f"[bold {_C_ACCENT}]PRIVILEGE ESCALATION · "
            f"LOGIN MATRIX[/bold {_C_ACCENT}]",
            style=_C_ACCENT,
        )
    )
    console.print(_privesc_matrix_panel(matrix, source))

    # Bind live sessions to declared principals in order: the account already
    # captured is principal #0; capture one live session per additional declared
    # principal. A credential is never read from the matrix file.
    sessions = [first_session]
    for principal in matrix.principals[1:]:
        extra = capture_more(principal.name)
        sessions.append(extra)  # None (operator cancelled) → INCONCLUSIVE

    live_matrix = privesc_policy_from_sessions(matrix, sessions)

    try:
        from app.security_graph.privesc import run_privesc_investigation

        with console.status(
            f"[{_C_ACCENT}]running control+breach differential + judging "
            f"live…[/{_C_ACCENT}]",
            spinner="dots",
        ):
            privesc_results = run_privesc_investigation(
                graph, live_matrix, target_base=target
            )
        if privesc_results:
            console.print(_privesc_findings_panel(privesc_results))

        privesc_confirmed = list(
            graph.findings_for(kind="privilege_escalation", status="OPEN")
        )
        if privesc_confirmed and not skip_remediation:
            from app.security_graph.privesc import (
                remediate_privesc_findings,
                synthesize_privesc_remediation,
            )
            from app.commands.remediation_gate import RemediationProposal

            console.print()
            console.print(
                Rule(
                    f"[bold {_C_OK}]PRIVESC REMEDIATION · PATCH + PROVE · "
                    f"{len(privesc_confirmed)} FINDING(S)[/bold {_C_OK}]",
                    style=_C_OK,
                )
            )
            proposals = []
            for finding in privesc_confirmed:
                plan = synthesize_privesc_remediation(graph, finding)
                if plan is None:
                    control = "deny escalation (no plan derived)"
                else:
                    control = (
                        f"deny {plan.rule.attacker_name} → "
                        f"{plan.rule.method} {plan.rule.path}  "
                        f"({plan.rule.type})"
                    )
                proposals.append(
                    RemediationProposal(
                        title=finding.title,
                        severity=finding.severity,
                        control=control,
                    )
                )
            if _gate_remediation(
                class_label="privilege escalation",
                color=_C_OK,
                proposals=proposals,
            ):
                with console.status(
                    f"[{_C_OK}]standing up the shield + proving the boundary "
                    f"holds…[/{_C_OK}]",
                    spinner="dots",
                ):
                    privesc_outcomes = remediate_privesc_findings(graph)
                for remediation in privesc_outcomes:
                    console.print(_privesc_remediation_panel(remediation))
        return privesc_confirmed
    except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
        console.print(
            Panel(
                Text(str(exc), style=_C_BAD),
                title=(
                    f"[{_C_BAD}]privilege escalation stage failed[/{_C_BAD}]"
                ),
                border_style=_C_BAD,
            )
        )
        return []


def _load_broken_auth_matrix(policy_path):
    """
    Resolve an operator BROKEN-AUTH MATRIX (structure only — never a token).

    Source order: ``$SENTINEL_BROKEN_AUTH_POLICY`` (a dedicated matrix file),
    else a ``broken_auth_matrix`` section embedded in the access-policy file.
    Returns ``(policy_or_None, source_or_None)``; a file with no matrix yields
    ``(None, None)`` and discovery synthesizes the surface from live recon.
    """
    import json

    from app.security_graph.broken_auth import load_broken_auth_policy

    source = os.environ.get("SENTINEL_BROKEN_AUTH_POLICY") or None
    if source is None and policy_path:
        try:
            with open(policy_path, encoding="utf-8") as handle:
                combined = json.load(handle)
            if isinstance(combined, dict) and combined.get("broken_auth_matrix"):
                source = policy_path
        except Exception:  # noqa: BLE001 — a bad file is reported elsewhere
            source = None
    if not source:
        return None, None
    return load_broken_auth_policy(source), source


def _broken_auth_material():
    """
    Optional operator material for the SIGNED-forgery strategies (advisory only).

    ``$SENTINEL_JWT_PUBLIC_KEY`` (a PEM literal or a path to one) enables the
    RS256→HS256 confusion probe; ``$SENTINEL_JWT_SECRETS`` (comma-separated
    candidates or a path to a newline-delimited dictionary) enables the
    weak-secret probe. Both are absent by default, so discovery synthesizes only
    the guard-provable ``alg_none`` / ``unsigned`` strategies — the honest zero-
    material default.
    """
    public_key = os.environ.get("SENTINEL_JWT_PUBLIC_KEY") or ""
    if public_key and os.path.isfile(public_key):
        try:
            public_key = open(public_key, encoding="utf-8").read()
        except Exception:  # noqa: BLE001
            public_key = ""

    raw_secrets = os.environ.get("SENTINEL_JWT_SECRETS") or ""
    secrets: tuple[str, ...] = ()
    if raw_secrets:
        if os.path.isfile(raw_secrets):
            try:
                secrets = tuple(
                    line.strip()
                    for line in open(raw_secrets, encoding="utf-8")
                    if line.strip()
                )
            except Exception:  # noqa: BLE001
                secrets = ()
        else:
            secrets = tuple(s.strip() for s in raw_secrets.split(",") if s.strip())

    return public_key, secrets

# __BROKEN_AUTH_PASS__


def _run_broken_auth_pass(
    graph, target, first_session, policy_path, skip_remediation,
):
    """
    Tier-3 hybrid class: prove JWT forgery acceptance on the live target.

    The ONE live input — a genuine bearer token to forge FROM — comes from the
    captured session, never a file. An operator ``broken_auth_matrix`` (structure
    only) is used if present; otherwise the token-forgery surface is SYNTHESIZED
    from live recon (guard-provable ``alg_none`` / ``unsigned`` by default; the
    signed strategies only when the operator supplies key/dictionary material).
    Every check is decided by the three-probe control/breach/baseline
    differential; a route not token-authenticated (or public) goes INCONCLUSIVE —
    never a manufactured finding. Returns the CONFIRMED broken-auth findings.
    """
    from app.security_graph.broken_auth import (
        run_broken_auth_investigation,
        synthesize_broken_auth_policy,
    )
    from app.security_graph.session import (
        broken_auth_policy_from_session,
        broken_auth_principal_from_session,
    )

    matrix, source = _load_broken_auth_matrix(policy_path)
    synthesized = False
    if matrix is not None and matrix.checks:
        live_policy = broken_auth_policy_from_session(matrix, first_session)
    else:
        synthesized = True
        public_key, secrets = _broken_auth_material()
        principal = broken_auth_principal_from_session(first_session)
        discovery = synthesize_broken_auth_policy(
            graph,
            principal=principal,
            public_key=public_key,
            secret_candidates=secrets,
        )
        live_policy = discovery.policy
        source = discovery.note

    console.print()
    console.print(
        Rule(
            f"[bold {_C_ACCENT}]BROKEN AUTHENTICATION · "
            f"JWT FORGERY[/bold {_C_ACCENT}]",
            style=_C_ACCENT,
        )
    )

    if not live_policy.checks:
        console.print(
            Text(
                "  the captured session carries no JWT bearer to forge from (or "
                "no forgery is derivable) — no broken-auth probe is synthesized "
                "and nothing is claimed (honest differential).",
                style=_C_DIM,
            )
        )
        return []

    console.print(
        _broken_auth_matrix_panel(live_policy, source or "operator matrix",
                                  synthesized=synthesized)
    )
    # __BROKEN_AUTH_PASS_BODY__

    try:
        with console.status(
            f"[{_C_ACCENT}]forging tokens + running control/breach/baseline "
            f"differential live…[/{_C_ACCENT}]",
            spinner="dots",
        ):
            broken_auth_results = run_broken_auth_investigation(
                graph, live_policy, target_base=target
            )
        if broken_auth_results:
            console.print(_broken_auth_findings_panel(broken_auth_results))

        broken_auth_confirmed = list(
            graph.findings_for(kind="broken_auth", status="OPEN")
        )
        if broken_auth_confirmed and not skip_remediation:
            from app.security_graph.broken_auth import (
                remediate_broken_auth_findings,
                synthesize_broken_auth_remediation,
            )
            from app.commands.remediation_gate import RemediationProposal

            console.print()
            console.print(
                Rule(
                    f"[bold {_C_OK}]BROKEN-AUTH REMEDIATION · PATCH + PROVE · "
                    f"{len(broken_auth_confirmed)} FINDING(S)[/bold {_C_OK}]",
                    style=_C_OK,
                )
            )
            proposals = []
            for finding in broken_auth_confirmed:
                plan = synthesize_broken_auth_remediation(graph, finding)
                if plan is None:
                    control = "jwt shape-guard (no plan derived)"
                elif plan.rule.guard_provable:
                    control = (
                        f"jwt shape-guard: refuse forged token "
                        f"({plan.rule.forgery}) → {plan.rule.method} "
                        f"{plan.rule.path}"
                    )
                else:
                    control = (
                        f"ADVISORY (signed {plan.rule.forgery}): pin algorithms + "
                        f"verify signature handler-side"
                    )
                proposals.append(
                    RemediationProposal(
                        title=finding.title,
                        severity=finding.severity,
                        control=control,
                    )
                )
            if _gate_remediation(
                class_label="broken authentication",
                color=_C_OK,
                proposals=proposals,
            ):
                with console.status(
                    f"[{_C_OK}]standing up the jwt shape-guard + proving the "
                    f"forgery is refused…[/{_C_OK}]",
                    spinner="dots",
                ):
                    broken_auth_outcomes = remediate_broken_auth_findings(graph)
                for remediation in broken_auth_outcomes:
                    console.print(_broken_auth_remediation_panel(remediation))
        return broken_auth_confirmed
    except Exception as exc:  # noqa: BLE001 — surface cleanly, never raise
        console.print(
            Panel(
                Text(str(exc), style=_C_BAD),
                title=(
                    f"[{_C_BAD}]broken authentication stage failed[/{_C_BAD}]"
                ),
                border_style=_C_BAD,
            )
        )
        return []



