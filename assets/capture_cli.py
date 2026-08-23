"""
Capture REAL Sentinel CLI output as ANSI, for the pitch deck screenshots.

Runs under the runtime venv (rich + the app):
    ./.venv/bin/python assets/capture_cli.py

It stands up the local demo target (assets/_shot_target.py), drives the *real*
engine over real sockets exactly as the `investigate` and `login` commands do —
same panel builders, same deterministic judge, same loopback PATCH+PROVE shield —
and records each section to assets/brand/cli/<name>.ansi with styles preserved.
Nothing is staged: every verdict shown was produced by the engine here.

Then render to PNG with assets/render_shots.py (under the Pillow venv).
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# Fail the advisory tiebreak fast if Ollama is not up — screenshots must not
# stall on a model that is not running. The loop degrades deterministically.
os.environ.setdefault("AI_ADVISORY_TIMEOUT", "4")

from rich.console import Console  # noqa: E402
from rich.rule import Rule  # noqa: E402

from assets._shot_target import start_stub  # noqa: E402

CLI_DIR = os.path.join(HERE, "brand", "cli")
os.makedirs(CLI_DIR, exist_ok=True)


def _console() -> Console:
    return Console(record=True, width=100, color_system="truecolor",
                   force_terminal=True, highlight=False)


def _save(con: Console, name: str) -> None:
    path = os.path.join(CLI_DIR, f"{name}.ansi")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(con.export_text(styles=True))
    print("wrote", os.path.relpath(path, ROOT))


def main() -> None:
    from app.commands import investigate_cmd as inv
    from app.commands import login_cmd as lg
    from app.security_graph.policy import load_access_policy
    from app.security_graph.orchestration.target import (
        TargetResearchPipeline, evaluate_target_research_outcome,
    )
    from app.security_graph.remediation import remediate_confirmed_findings
    from app.security_graph.posture import (
        load_header_policy, run_posture_investigation, remediate_header_findings,
    )
    from app.security_graph.cookies import (
        load_cookie_policy, run_cookie_investigation, remediate_cookie_findings,
    )
    from app.security_graph.session import (
        CapturedCookie, CapturedSession, cookie_header_from,
        reconstruct_set_cookie, session_baseline_cookie_policy,
    )
    from app.security_graph.cookies import parse_cookie_policy

    server, base = start_stub()
    policy_path = os.path.join(HERE, "shot_policy.json")
    try:
        access = load_access_policy(policy_path)
        result = TargetResearchPipeline().run(base, max_cycles=6,
                                              access_policy=access)
        outcome = evaluate_target_research_outcome(result)

        # 1) FIND — banner, recon, oracle, hypotheses
        c = _console()
        c.print(); c.print(inv._banner())
        c.print(); c.print(inv._recon_panel(result))
        c.print(inv._policy_panel(access, policy_path))
        c.print(inv._hypotheses_panel(result))
        _save(c, "recon")

        # 2) DECISION BOARD — the first few cycles
        c = _console()
        c.print(Rule("[bold #22d3ee]AUTONOMOUS RESEARCH · "
                     f"{len(result.cycles)} CYCLE(S)[/bold #22d3ee]",
                     style="#22d3ee"))
        for i, cycle in enumerate(result.cycles[:3], start=1):
            c.print(inv._cycle_panel(i, cycle))
        _save(c, "cycles")

        # 3) CONFIRMED authorization findings
        c = _console()
        c.print(inv._findings_panel(result))
        _save(c, "findings")

        # 4) PATCH + PROVE (authorization)
        auth_outcomes = remediate_confirmed_findings(result.graph)
        c = _console()
        c.print(Rule(f"[bold #2dd48f]REMEDIATION · PATCH + PROVE · "
                     f"{len(auth_outcomes)} FINDING(S)[/bold #2dd48f]",
                     style="#2dd48f"))
        for o in auth_outcomes:
            c.print(inv._remediation_panel(o))
        _save(c, "patch_prove")

        # 5) SECURITY MISCONFIGURATION — header posture (find + prove)
        hpolicy = load_header_policy(policy_path)
        pres = run_posture_investigation(result.graph, hpolicy, target_base=base)
        pout = remediate_header_findings(result.graph)
        c = _console()
        c.print(Rule("[bold #e84bff]SECURITY MISCONFIGURATION · HEADER POSTURE"
                     "[/bold #e84bff]", style="#e84bff"))
        c.print(inv._header_policy_panel(hpolicy, policy_path))
        c.print(inv._posture_findings_panel(pres))
        for o in pout:
            c.print(inv._posture_remediation_panel(o))
        _save(c, "posture")

        # 6) INSECURE COOKIES (find + prove) — live, over the socket
        cpolicy = load_cookie_policy(policy_path)
        cres = run_cookie_investigation(result.graph, cpolicy, target_base=base)
        cout = remediate_cookie_findings(result.graph)
        c = _console()
        c.print(Rule("[bold #e84bff]INSECURE COOKIES · SESSION SAFETY"
                     "[/bold #e84bff]", style="#e84bff"))
        c.print(inv._cookie_policy_panel(cpolicy, policy_path))
        c.print(inv._cookie_findings_panel(cres))
        for o in cout:
            c.print(inv._cookie_remediation_panel(o))
        _save(c, "cookie")

        # 7) RESEARCH FRONTIER outcome
        c = _console()
        c.print(inv._outcome_panel(outcome, result.stopped_reason))
        _save(c, "outcome")

        # 8) LOGIN TESTER — a captured authenticated session (real render path)
        session = CapturedSession(
            cookie_header=cookie_header_from([CapturedCookie("token", "eyJ.demo.sig")]),
            bearer="eyJhbGciOiJIUzI1NiJ9.demo.sig",
            cookies=(CapturedCookie("token", "eyJ.demo.sig", path="/"),),
            final_url=f"{base}/dashboard",
        )
        observed = [reconstruct_set_cookie(x) for x in session.cookies]
        sess_graph = type(result.graph)()
        s_policy = parse_cookie_policy(session_baseline_cookie_policy(session))
        s_res = run_cookie_investigation(
            sess_graph, s_policy, target_base=base,
            executor=lg._CapturedCookieExecutor(observed),
        )
        s_confirmed = list(sess_graph.findings_for(
            kind="insecure_cookie", status="OPEN"))
        s_prove = lg._prove_session_cookies(sess_graph, s_confirmed, observed)
        auth_confirmed = list(result.graph.findings_for(
            kind="authorization_policy_violation", status="OPEN"))
        c = _console()
        c.print(Rule("[bold #22d3ee]LOGIN TESTER · AUTHENTICATED SESSION"
                     "[/bold #22d3ee]", style="#22d3ee"))
        c.print(lg._session_panel(session, base, f"{base}/login"))
        c.print(inv._cookie_findings_panel(s_res))
        for o in (lg._cookie_remediation_panel(x) for x in s_prove):
            c.print(o)
        c.print(lg._chain_panel(auth_confirmed, s_confirmed))
        _save(c, "login")

        print("\ncaptured", len(os.listdir(CLI_DIR)), "ansi sections")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
