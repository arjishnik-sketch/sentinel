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


def _chain_panel(authz_confirmed, cookie_confirmed) -> Panel:
    """Honest chaining view: co-occurring proven ingredients for one session."""
    have_authz = bool(authz_confirmed)
    have_cookie = bool(cookie_confirmed)

    def _mark(ok: bool) -> str:
        return f"[{_C_OK}]✔[/{_C_OK}]" if ok else f"[{_C_DIM}]·[/{_C_DIM}]"

    lines = [
        f"{_mark(True)} authenticated session captured (real cookies + bearer)",
        f"{_mark(have_cookie)} session cookie proven insecure "
        f"[{_C_DIM}]({len(cookie_confirmed)} insecure_cookie CONFIRMED)[/{_C_DIM}]",
        f"{_mark(have_authz)} resource reachable as this authenticated principal "
        f"[{_C_DIM}]({len(authz_confirmed)} authorization_policy_violation "
        f"CONFIRMED)[/{_C_DIM}]",
    ]
    body = Text.from_markup("\n".join(lines))

    if have_authz and have_cookie:
        verdict = Text(
            "\nBoth ingredients of a session-theft → authenticated-access chain "
            "are independently PROVEN on this session. Sentinel presents them "
            "as co-occurring evidence; it does NOT auto-compose a causal exploit "
            "narrative — full chaining remains the honestly-labeled frontier.",
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
            from app.security_graph.remediation import remediate_confirmed_findings

            console.print()
            console.print(
                Rule(
                    f"[bold {_C_OK}]REMEDIATION · PATCH + PROVE · "
                    f"{len(authz_confirmed)} FINDING(S)[/bold {_C_OK}]",
                    style=_C_OK,
                )
            )
            with console.status(
                f"[{_C_OK}]synthesizing controls + proving fixes live…[/{_C_OK}]",
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

    # --- CHAINING (honest ingredients) -----------------------------------
    console.print()
    console.print(_chain_panel(authz_confirmed, cookie_confirmed))
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
            console.print()
            console.print(
                Rule(
                    f"[bold {_C_OK}]COOKIE REMEDIATION · PATCH + PROVE · "
                    f"{len(cookie_confirmed)} FINDING(S)[/bold {_C_OK}]",
                    style=_C_OK,
                )
            )
            with console.status(
                f"[{_C_OK}]hardening the observed cookie + proving…[/{_C_OK}]",
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



