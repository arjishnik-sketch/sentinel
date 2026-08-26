"""AUTH MATRIX — prove broken_auth / privilege_escalation from operator context.

Honesty note (the §1 contract, in force): broken_auth and privilege_escalation
are NOT single-probe differentials. They are MATRIX-driven — privesc needs a
login/identity matrix (≥2 principals with declared session headers); broken_auth
needs a forgery matrix (routes + strategy) AND a GENUINE captured bearer token to
forge FROM. That is exactly why they are deliberately absent from
``judges._SPECS`` (which only wires single-probe judges) and prove HERE instead,
in a separate stage that fires ONLY when the operator supplies the context the
class honestly needs:

  * broken_auth : a broken_auth matrix with checks AND a genuine bearer token.
    No token → honestly skipped (never a blind run that could manufacture a claim).
  * privilege_escalation : a matrix with ≥1 check and declared principal headers,
    exactly as the ``investigate`` command consumes it.

This module OWNS no verdict. It calls the SAME pure judges the security_graph
classes already ship (``run_broken_auth_investigation`` /
``run_privesc_investigation``) on a fresh graph, then adapts each returned
ProbeResult into an orchestrator :class:`~app.autonomous.orchestrator.Verdict`
(VALIDATED→CONFIRMED, via the single :func:`orchestrator.to_verdict_status` site)
carrying the proven graph as :class:`~app.autonomous.judges.JudgeEvidence` — so
the report renders these findings with full steps-to-reproduce, exactly like the
wired classes.

The token is a secret: it lives only in the injected principal headers in memory
and in the (value-masked) report; it is NEVER logged, echoed, or placed in a note.
The run / graph / load seams are injected, so the whole stage is offline-testable
with zero network.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from . import orchestrator as O
from .hypotheses import Hypothesis
from .judges import JudgeEvidence
from app.security_graph.graph import SecurityGraph
from app.security_graph.broken_auth.broken_auth_policy import (
    BrokenAuthPolicy, BrokenAuthPrincipal, load_broken_auth_policy)
from app.security_graph.broken_auth.run import run_broken_auth_investigation, _probe_headers
from app.security_graph.broken_auth.judge import broken_auth_expectation
from app.security_graph.broken_auth.seed import _aspect as _check_aspect
from app.security_graph.broken_auth.impact import exercise_impact
from app.security_graph.privesc.privesc_policy import load_privesc_policy
from app.security_graph.privesc.run import run_privesc_investigation

_TRUE = frozenset({"1", "true", "yes", "on"})


def _impact_enabled(env) -> bool:
    """The state-changing impact demonstration is OFF unless the operator explicitly
    opts in via ``SENTINEL_ENABLE_IMPACT`` — it issues a real privileged request
    against the target, so it must never fire by default."""
    return str(env.get("SENTINEL_ENABLE_IMPACT", "")).strip().lower() in _TRUE


@dataclass(frozen=True)
class AuthContext:
    """Resolved matrix context for the auth-matrix stage. Pure DATA, token-safe.

    ``notes`` is human-readable and NEVER contains the token value — only whether
    one was captured. ``token`` is held in memory for the single moment it is
    injected into the broken_auth principal headers, then discarded with this
    object at end of run."""

    broken_auth_policy: object = None      # BrokenAuthPolicy | None
    privesc_policy: object = None          # PrivEscPolicy | None
    token: "str | None" = None
    impact_enabled: bool = False
    notes: tuple = ()

    @property
    def has_broken_auth(self) -> bool:
        return bool(getattr(self.broken_auth_policy, "checks", ()) and self.token)

    @property
    def has_privesc(self) -> bool:
        return bool(getattr(self.privesc_policy, "checks", ()))

    @property
    def active(self) -> bool:
        return self.has_broken_auth or self.has_privesc


# ---- token injection (broken_auth) ------------------------------------------

def inject_bearer(policy: BrokenAuthPolicy, token: str) -> BrokenAuthPolicy:
    """Bind a genuine ``token`` as the SOLE authenticator of the matrix's principal
    — the one credential broken_auth needs, supplied live, never from a file. The
    token rides the app's REAL location, declared by the matrix's ``token_location``
    (``Authorization: Bearer`` by default, or ``Cookie: <name>=<token>`` for a
    cookie-session app), so a route authenticated by cookie is provable rather than
    a guaranteed control-probe failure. The principal's session-alive ``control``
    route is preserved. An empty token leaves the principal tokenless (honest skip)."""
    location = getattr(policy, "token_location", None)
    base = policy.principal
    if token:
        header = (location.header_for(token) if location is not None
                  else ("Authorization", f"Bearer {token}"))
        headers = (header,)
    else:
        headers = ()
    principal = BrokenAuthPrincipal(
        name=(base.name if base is not None else "authenticated"),
        headers=headers,
        role=(base.role if base is not None else "user"),
        control=(base.control if base is not None else None),
    )
    return replace(policy, principal=principal)


# ---- ProbeResult → Verdict --------------------------------------------------

def _breach_request(graph, hyp_id):
    """The (method, url) the breach probe actually issued for ``hyp_id`` — the most
    honest thing to display, since it is what was really sent. Falls back to
    (None, None) when the graph has no such experiment yet."""
    for exp in getattr(graph, "experiments", {}).values():
        if getattr(exp, "hypothesis_id", None) != hyp_id:
            continue
        action = getattr(exp, "action", "") or ""
        req = getattr(exp, "request", None)
        if "breach" in action and req is not None:
            return getattr(req, "method", None), getattr(req, "url", None)
    return None, None


def _synthetic_hypothesis(technique, result, graph, target_base, *, source):
    """A display-only :class:`Hypothesis` for one matrix ProbeResult, so the panel,
    grouping and report render matrix verdicts exactly like single-probe ones. It
    is NEVER re-adjudicated — the judge already disposed; this only labels."""
    method, url = _breach_request(graph, result.hypothesis_id)
    return Hypothesis(
        technique=technique,
        url=url or target_base,
        method=(method or "GET"),
        param=None,
        location="header" if technique == "broken_auth" else "path",
        rationale=getattr(result, "claim", "") or "",
        severity=(getattr(result, "severity", "") or "HIGH"),
        source=source,
    )


def _to_verdict(technique, result, graph, policy, target_base, *, source, impact=None):
    """Adapt one ProbeResult into a Verdict — VALIDATED→CONFIRMED via the SINGLE
    orchestrator translation site, carrying the proven graph as JudgeEvidence so
    the report reconstructs full steps-to-reproduce. When an ``impact`` observation
    is supplied (a CONFIRMED forgery whose declared action was exercised), its
    token-safe note is appended to the verdict detail; the exercised request itself
    is already recorded on ``graph`` and renders as an additional reproduction step."""
    hyp = _synthetic_hypothesis(technique, result, graph, target_base, source=source)
    evidence = JudgeEvidence(
        technique=technique, result=result, graph=graph,
        policy=policy, target_base=target_base,
    )
    detail = getattr(result, "reason", "") or ""
    note = getattr(impact, "note", "") if impact is not None else ""
    if note:
        prefix = "IMPACT DEMONSTRATED" if getattr(impact, "demonstrated", False) else "impact"
        detail = f"{detail} — {prefix}: {note}" if detail else f"{prefix}: {note}"
    return O.Verdict(
        hypothesis=hyp,
        status=O.to_verdict_status(getattr(result, "status", "INCONCLUSIVE")),
        detail=detail,
        evidence=evidence,
    )


# ---- the stage: run the real judges, adapt their results --------------------

def _join_url(target_base, path):
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _default_impact_executor(target_base):
    """A host-scoped executor for the impact stage — the SAME scope guard the
    prove-chain uses, so an impact request can never leave the engagement host."""
    from app.security_graph.broken_auth.executor import BrokenAuthProbeExecutor

    host = urlsplit(
        target_base if "://" in target_base else f"http://{target_base}"
    ).netloc.lower()
    return BrokenAuthProbeExecutor(allowed_hosts={host} if host else None)


def _run_impacts(target_base, policy, graph, results, *, _exercise=exercise_impact,
                 executor_factory=None):
    """For every CONFIRMED (VALIDATED) forgery whose check declares an ``impact``,
    exercise that privileged action with the ALREADY-forged token (recovered from
    the graph, never re-derived). Returns ``{hypothesis_id: ImpactObservation}``.
    Runs only when called (the caller gates on the opt-in flag)."""
    by_aspect = {
        _check_aspect(check): check
        for check in getattr(policy, "checks", ())
        if getattr(check, "impact", None) is not None and check.impact.declared
    }
    if not by_aspect:
        return {}

    executor_factory = executor_factory or _default_impact_executor
    executor = None
    out = {}
    for result in results:
        if getattr(result, "status", "") != "VALIDATED":
            continue
        hyp = graph.hypotheses.get(result.hypothesis_id)
        if hyp is None or hyp.identity is None:
            continue
        check = by_aspect.get(hyp.identity.action)
        if check is None:
            continue
        _, breach_headers = _probe_headers(graph, hyp)
        if not breach_headers:
            continue
        expectation = broken_auth_expectation(
            graph, resource_id=hyp.identity.resource_id, aspect=hyp.identity.action)
        breach_url = (expectation.breach_url if expectation is not None
                      else _join_url(target_base, check.path))
        breach_method = (expectation.method if expectation is not None
                         else check.method)
        if executor is None:
            executor = executor_factory(target_base)
        out[result.hypothesis_id] = _exercise(
            target_base, impact=check.impact, forged_headers=breach_headers,
            graph=graph, executor=executor, hypothesis_id=hyp.id,
            identity=hyp.identity, breach_url=breach_url, breach_method=breach_method,
            success_statuses=getattr(policy, "success_statuses", tuple(range(200, 300))))
    return out


def broken_auth_verdicts(target_base, policy, token, *, source="operator",
                         impact_enabled=False,
                         _run=run_broken_auth_investigation, graph_factory=SecurityGraph,
                         _exercise=exercise_impact, executor_factory=None):
    """Inject the live token, run the broken_auth prove-chain on a fresh graph, and
    adapt every ProbeResult (CONFIRMED/DISPROVED/INCONCLUSIVE) into a Verdict.

    When ``impact_enabled`` (the operator opted in), a CONFIRMED forgery whose check
    declares an ``impact`` also has that privileged action exercised with the forged
    token — a doubly-gated demonstration recorded on the same graph. The impact NEVER
    runs for a DISPROVED/INCONCLUSIVE result: only a proven bypass is exercised."""
    if not getattr(policy, "checks", ()) or not token:
        return []
    bound = inject_bearer(policy, token)
    graph = graph_factory()
    results = _run(graph, bound, target_base=target_base)
    impacts = {}
    if impact_enabled:
        impacts = _run_impacts(target_base, bound, graph, results,
                               _exercise=_exercise, executor_factory=executor_factory)
    return [_to_verdict("broken_auth", r, graph, bound, target_base, source=source,
                        impact=impacts.get(r.hypothesis_id))
            for r in results]


def privesc_verdicts(target_base, policy, *, source="operator",
                     _run=run_privesc_investigation, graph_factory=SecurityGraph):
    """Run the privilege-escalation prove-chain on a fresh graph (declared principal
    headers, as ``investigate`` consumes them) and adapt every ProbeResult."""
    if not getattr(policy, "checks", ()):
        return []
    graph = graph_factory()
    results = _run(graph, policy, target_base=target_base)
    return [_to_verdict("privilege_escalation", r, graph, policy, target_base,
                        source=source)
            for r in results]


def run_auth_matrix(target_base, context, *, source="operator",
                    _run_broken_auth=run_broken_auth_investigation,
                    _run_privesc=run_privesc_investigation,
                    graph_factory=SecurityGraph):
    """Prove whichever matrix classes the resolved ``context`` supports, returning a
    flat list of Verdicts. broken_auth fires only with a token; privesc fires on a
    declared matrix. May raise if a judge is genuinely broken — the CLI stage guards
    it so a fault degrades to a note, never a manufactured pass and never a crash."""
    verdicts = []
    if context.has_broken_auth:
        verdicts += broken_auth_verdicts(
            target_base, context.broken_auth_policy, context.token,
            source=source, impact_enabled=context.impact_enabled,
            _run=_run_broken_auth, graph_factory=graph_factory)
    if context.has_privesc:
        verdicts += privesc_verdicts(
            target_base, context.privesc_policy,
            source=source, _run=_run_privesc, graph_factory=graph_factory)
    return verdicts


# ---- context resolution (touches disk + env; seams injected for tests) ------

def _first_path(*candidates):
    for path in candidates:
        if path and str(path).strip():
            return str(path).strip()
    return None


def _capture_login(login_url, *, username, password, target, location):
    """Default LIVE login seam: drive a headless HTTP form login and read the
    session token from the SAME place the matrix declares the app carries it
    (``location`` — cookie or header). Returns ``(token, note)`` where ``note`` is
    a presence-only, token-SAFE one-liner. The password is used to fill the live
    form only — never logged; the captured token's VALUE never enters the note."""
    from app.security_graph.session.form_login import capture_login_session

    session = capture_login_session(
        login_url, username=username, password=password, target=target)
    return session.token_for(location), session.note


def _resolve_credentials(directive, env):
    """The (username, password) to log in with, from the operator directive first,
    then ``SENTINEL_LOGIN_USERNAME`` / ``SENTINEL_LOGIN_PASSWORD``. Returns ``None``
    when neither source supplies both. The password is a secret held only here."""
    creds = getattr(directive, "credentials", None) if directive else None
    if creds:
        return creds
    env_user = env.get("SENTINEL_LOGIN_USERNAME")
    env_pass = env.get("SENTINEL_LOGIN_PASSWORD")
    if env_user and env_pass:
        return (env_user, env_pass)
    return None


def resolve_auth_context(directive=None, *, env=None, target=None,
                         load_broken_auth=load_broken_auth_policy,
                         load_privesc=load_privesc_policy,
                         login=_capture_login) -> AuthContext:
    """Resolve matrix policies + token from an OperatorDirective and the environment.

    Precedence mirrors ``login``/``investigate``: dedicated env var, then the
    operator's ``matrix <path>``, then the combined ``SENTINEL_ACCESS_POLICY``. The
    loaders each pluck their own section from a combined doc, so one file can carry
    both matrices. A file that fails to load degrades to a token-free note, never a
    crash. The token comes from the operator's ``token`` line or
    ``SENTINEL_SESSION_TOKEN`` — its VALUE never enters a note.

    When broken_auth is requested but no token was supplied, and the operator gave
    credentials (a ``login``/``creds`` directive or ``SENTINEL_LOGIN_USERNAME`` /
    ``SENTINEL_LOGIN_PASSWORD``), Sentinel CAPTURES a token itself by driving a live
    login via the ``login`` seam — reading the token from the SAME location the
    matrix declares. The password fills the live form only; it is never logged, and
    the captured token's value never enters a note. ``login`` and the loaders are
    injected seams, so the whole resolution is offline-testable with zero network."""
    env = env if env is not None else os.environ
    matrix_path = getattr(directive, "matrix_path", None) if directive else None
    token = (getattr(directive, "token", None) if directive else None) \
        or (env.get("SENTINEL_SESSION_TOKEN") or None)
    creds = _resolve_credentials(directive, env)
    login_url = (getattr(directive, "login_url", None) if directive else None) \
        or (env.get("SENTINEL_LOGIN_URL") or None)

    ba_path = _first_path(env.get("SENTINEL_BROKEN_AUTH_POLICY"), matrix_path,
                          env.get("SENTINEL_ACCESS_POLICY"))
    pe_path = _first_path(env.get("SENTINEL_PRIVESC_POLICY"), matrix_path,
                          env.get("SENTINEL_ACCESS_POLICY"))

    notes = []
    ba_policy = None
    if ba_path:
        try:
            candidate = load_broken_auth(ba_path)
        except Exception as exc:
            notes.append(f"broken_auth matrix load failed: {type(exc).__name__}")
        else:
            if getattr(candidate, "checks", ()):
                ba_policy = candidate

    # broken_auth is requested but tokenless, and the operator supplied credentials:
    # CAPTURE a genuine token live rather than lean on an external driver. A capture
    # fault degrades to a token-safe note (never a crash, never a manufactured pass).
    if ba_policy is not None and not token and creds:
        username, password = creds
        location = getattr(ba_policy, "token_location", None)
        try:
            token, capture_note = login(
                login_url, username=username, password=password,
                target=target, location=location)
        except Exception as exc:
            notes.append(f"credential login failed: {type(exc).__name__}")
        else:
            # username is identity (safe); the password and token value are NOT.
            notes.append(f"credential login as {username!r}: {capture_note}")

    # Emitted AFTER the login attempt so it reflects the FINAL token state.
    impact_enabled = _impact_enabled(env)
    if ba_policy is not None:
        notes.append(
            f"broken_auth matrix: {len(ba_policy.checks)} check(s), "
            + ("token captured" if token else "NO token — will skip"))
        if impact_enabled and token:
            notes.append(
                "impact demonstration ENABLED (SENTINEL_ENABLE_IMPACT) — a proven "
                "forgery will exercise its declared privileged action")

    pe_policy = None
    if pe_path:
        try:
            candidate = load_privesc(pe_path)
        except Exception as exc:
            notes.append(f"privesc matrix load failed: {type(exc).__name__}")
        else:
            if getattr(candidate, "checks", ()):
                pe_policy = candidate
                notes.append(
                    f"privesc matrix: {len(candidate.checks)} check(s), "
                    f"{len(candidate.principals)} principal(s)")

    return AuthContext(broken_auth_policy=ba_policy, privesc_policy=pe_policy,
                       token=token, impact_enabled=impact_enabled,
                       notes=tuple(notes))
