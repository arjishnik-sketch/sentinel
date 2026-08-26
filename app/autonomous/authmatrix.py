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

from . import orchestrator as O
from .hypotheses import Hypothesis
from .judges import JudgeEvidence
from app.security_graph.graph import SecurityGraph
from app.security_graph.broken_auth.broken_auth_policy import (
    BrokenAuthPolicy, BrokenAuthPrincipal, load_broken_auth_policy)
from app.security_graph.broken_auth.run import run_broken_auth_investigation
from app.security_graph.privesc.privesc_policy import load_privesc_policy
from app.security_graph.privesc.run import run_privesc_investigation

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
    """Bind a genuine bearer ``token`` as the SOLE authenticator of the matrix's
    principal — the one credential broken_auth needs, supplied live, never from a
    file. Mirrors ``session.authenticated._bearer_header``: Authorization only, no
    cookie, so a route guarded by cookie can never pass the control probe and yield
    a false positive. An empty token leaves the principal tokenless (honest skip)."""
    headers = (("Authorization", f"Bearer {token}"),) if token else ()
    base = policy.principal
    principal = BrokenAuthPrincipal(
        name=(base.name if base is not None else "authenticated"),
        headers=headers,
        role=(base.role if base is not None else "user"),
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


def _to_verdict(technique, result, graph, policy, target_base, *, source):
    """Adapt one ProbeResult into a Verdict — VALIDATED→CONFIRMED via the SINGLE
    orchestrator translation site, carrying the proven graph as JudgeEvidence so
    the report reconstructs full steps-to-reproduce."""
    hyp = _synthetic_hypothesis(technique, result, graph, target_base, source=source)
    evidence = JudgeEvidence(
        technique=technique, result=result, graph=graph,
        policy=policy, target_base=target_base,
    )
    return O.Verdict(
        hypothesis=hyp,
        status=O.to_verdict_status(getattr(result, "status", "INCONCLUSIVE")),
        detail=getattr(result, "reason", "") or "",
        evidence=evidence,
    )


# ---- the stage: run the real judges, adapt their results --------------------

def broken_auth_verdicts(target_base, policy, token, *, source="operator",
                         _run=run_broken_auth_investigation, graph_factory=SecurityGraph):
    """Inject the live token, run the broken_auth prove-chain on a fresh graph, and
    adapt every ProbeResult (CONFIRMED/DISPROVED/INCONCLUSIVE) into a Verdict."""
    if not getattr(policy, "checks", ()) or not token:
        return []
    bound = inject_bearer(policy, token)
    graph = graph_factory()
    results = _run(graph, bound, target_base=target_base)
    return [_to_verdict("broken_auth", r, graph, bound, target_base, source=source)
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
            source=source, _run=_run_broken_auth, graph_factory=graph_factory)
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


def resolve_auth_context(directive=None, *, env=None,
                         load_broken_auth=load_broken_auth_policy,
                         load_privesc=load_privesc_policy) -> AuthContext:
    """Resolve matrix policies + token from an OperatorDirective and the environment.

    Precedence mirrors ``login``/``investigate``: dedicated env var, then the
    operator's ``matrix <path>``, then the combined ``SENTINEL_ACCESS_POLICY``. The
    loaders each pluck their own section from a combined doc, so one file can carry
    both matrices. A file that fails to load degrades to a token-free note, never a
    crash. The token comes from the operator's ``token`` line or
    ``SENTINEL_SESSION_TOKEN`` — its VALUE never enters a note."""
    env = env if env is not None else os.environ
    matrix_path = getattr(directive, "matrix_path", None) if directive else None
    token = (getattr(directive, "token", None) if directive else None) \
        or (env.get("SENTINEL_SESSION_TOKEN") or None)

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
                notes.append(
                    f"broken_auth matrix: {len(candidate.checks)} check(s), "
                    + ("token captured" if token else "NO token — will skip"))

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
                       token=token, notes=tuple(notes))
