"""Judge adapters — the "dispose" half of "LLM/tools propose, a pure judge
disposes".

The orchestrator proposes a :class:`~app.autonomous.hypotheses.Hypothesis` (a
technique at a place). This module adapts each PROVABLE technique to the real,
pure differential judge that already lives in ``app.security_graph.<class>``: it
builds a single-check policy (pure DATA) from the hypothesis and calls
``run_<class>_investigation`` on a fresh graph, then reports the judge's own
``.status`` (VALIDATED / DISPROVED / INCONCLUSIVE) and ``.reason`` verbatim. The
orchestrator — never this module — translates VALIDATED into CONFIRMED.

No verdict is invented here: the security_graph judge re-probes the live target
and decides. A hypothesis whose technique has no single-probe differential
(broken_auth / idor / privilege_escalation — they need a login/identity matrix)
is deliberately NOT wired, so the orchestrator surfaces it as an honest LEAD.

Every adapter takes ``(hyp, prober=None)`` to match the orchestrator's judge
protocol, and exposes ``_run`` / ``_graph`` keyword seams so the whole bridge is
offline-testable with zero network.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qsl, urlsplit

from app.security_graph.graph import SecurityGraph
from app.security_graph.injection.discover import _BENIGN_TOKEN
from app.security_graph.injection.injection_policy import InjectionCheck, InjectionPolicy
from app.security_graph.injection.run import run_injection_investigation
from app.security_graph.xss.xss_policy import XSSCheck, XSSPolicy
from app.security_graph.xss.run import run_xss_investigation
from app.security_graph.path_traversal.traversal_policy import TraversalCheck, TraversalPolicy
from app.security_graph.path_traversal.run import run_path_traversal_investigation
from app.security_graph.ssti.ssti_policy import SSTICheck, SSTIPolicy
from app.security_graph.ssti.run import run_ssti_investigation
from app.security_graph.open_redirect.open_redirect_policy import OpenRedirectCheck, OpenRedirectPolicy
from app.security_graph.open_redirect.run import run_open_redirect_investigation
from app.security_graph.cors.cors_policy import CorsCheck, CorsPolicy
from app.security_graph.cors.run import run_cors_investigation
from app.security_graph.ssrf.ssrf_policy import SsrfCheck, SsrfPolicy
from app.security_graph.ssrf.run import run_ssrf_investigation

_VALID_SEV = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

# hypothesis location vocab (query|body|path|header) -> security_graph probe
# location vocab (query|body_form|body_json|path). "path" now maps through as a
# first-class location (the injection class places the payload in one URL path
# segment); only "header" still has no single-probe judge and falls back to the
# query string.
_LOC_MAP = {
    "query": "query", "body": "body_form", "body_form": "body_form",
    "body_json": "body_json", "json": "body_json", "path": "path",
}

# INCONCLUSIVE is the honest outcome when we cannot even build a probe; it maps
# cleanly to the orchestrator's INCONCLUSIVE verdict (never to CONFIRMED).
_INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class JudgeEvidence:
    """What a judge return-carries as its verdict evidence.

    Crucially it holds the very ``graph`` the pure judge just proved on — a
    VALIDATED probe leaves the OPEN finding recorded there — so the CLI's
    PATCH→PROVE stage can remediate + re-prove on THAT graph without opening a
    second socket. ``.status`` / ``.reason`` delegate to the ProbeResult so the
    object stays duck-compatible with anything reading a bare result."""

    technique: str
    result: object            # the security_graph ProbeResult (results[0])
    graph: object             # the SecurityGraph the judge proved on
    policy: object            # the single-check policy that was run
    target_base: str

    @property
    def status(self):
        return getattr(self.result, "status", _INCONCLUSIVE)

    @property
    def reason(self):
        return getattr(self.result, "reason", "")


def _origin(url: str) -> str:
    """scheme://netloc of a hypothesis URL — the ``target_base`` the run wants."""
    sp = urlsplit(url if "://" in (url or "") else f"http://{url or ''}")
    return f"{sp.scheme}://{sp.netloc}" if sp.netloc else ""


def _path(url: str) -> str:
    sp = urlsplit(url if "://" in (url or "") else f"http://{url or ''}")
    return sp.path or "/"


def _loc(location: str) -> str:
    return _LOC_MAP.get((location or "query").lower(), "query")


def _sev(hyp, default: str) -> str:
    s = (getattr(hyp, "severity", "") or "").upper()
    return s if s in _VALID_SEV else default


def _baseline(hyp) -> str:
    """A benign anchor for the injection differential: the value the app really
    served for this param if recon saw one, else the inert benign token.

    For a path-segment injection the anchor is the concrete value already sitting
    in the injected segment — the LAST non-empty path segment of the crawled URL
    (e.g. ``…/api/users/1`` → ``1``) — so the baseline probe reproduces the very
    response recon observed, giving the differential a real anchor."""
    if (getattr(hyp, "location", "") or "").lower() == "path":
        segs = [s for s in urlsplit(hyp.url).path.split("/") if s]
        return segs[-1] if segs else _BENIGN_TOKEN
    for key, value in parse_qsl(urlsplit(hyp.url).query, keep_blank_values=True):
        if key == hyp.param and value:
            return value
    return _BENIGN_TOKEN

# ---- per-class single-check builders (pure DATA; no probing here) -----------
# Field shapes differ by class (confirmed against each *_policy.py):
#   injection : (method, path, param, baseline_value, location, severity)
#   xss/trav/ssti/ssrf : (method, path, param, location, severity)  [no baseline]
#   open_redirect : same 5-field shape, MEDIUM default
#   cors : (method, path, severity) — NO param, NO location

def _injection_check(hyp, path):
    return InjectionCheck(
        method=(hyp.method or "GET"), path=path, param=hyp.param,
        baseline_value=_baseline(hyp), location=_loc(hyp.location),
        severity=_sev(hyp, "HIGH"),
    )


def _paramcheck_builder(cls, default_sev):
    def build(hyp, path):
        return cls(
            method=(hyp.method or "GET"), path=path, param=hyp.param,
            location=_loc(hyp.location), severity=_sev(hyp, default_sev),
        )
    return build


def _cors_check(hyp, path):
    return CorsCheck(method=(hyp.method or "GET"), path=path, severity=_sev(hyp, "MEDIUM"))


@dataclass(frozen=True)
class _JudgeSpec:
    policy_cls: type
    run_fn: Callable
    build_check: Callable          # (hyp, path) -> a frozen Check
    needs_param: bool = True       # cors is the lone param-free class


# technique -> how to prove it. Keys MUST equal Hypothesis.technique for the
# provable (differential) techniques; anything absent stays an honest LEAD.
_SPECS = {
    "sql_injection": _JudgeSpec(InjectionPolicy, run_injection_investigation, _injection_check),
    "xss": _JudgeSpec(XSSPolicy, run_xss_investigation, _paramcheck_builder(XSSCheck, "MEDIUM")),
    "path_traversal": _JudgeSpec(
        TraversalPolicy, run_path_traversal_investigation,
        _paramcheck_builder(TraversalCheck, "HIGH")),
    "ssti": _JudgeSpec(SSTIPolicy, run_ssti_investigation, _paramcheck_builder(SSTICheck, "HIGH")),
    "open_redirect": _JudgeSpec(
        OpenRedirectPolicy, run_open_redirect_investigation,
        _paramcheck_builder(OpenRedirectCheck, "MEDIUM")),
    "ssrf": _JudgeSpec(SsrfPolicy, run_ssrf_investigation, _paramcheck_builder(SsrfCheck, "HIGH")),
    "cors": _JudgeSpec(CorsPolicy, run_cors_investigation, _cors_check, needs_param=False),
}

# ---- the adapter: build a one-check policy, run the real judge --------------

def _adjudicate(hyp, spec, *, _run, _graph):
    """Build a single-check policy from ``hyp`` and let the real pure judge
    decide. Returns ``(status, reason, evidence)`` — the tuple the orchestrator's
    ``_normalize`` understands. Never raises for a merely un-probeable hypothesis;
    a genuinely broken judge is allowed to raise so the orchestrator records ERROR
    (a fault is never silently a pass)."""
    if spec.needs_param and not (hyp.param and str(hyp.param).strip()):
        return (_INCONCLUSIVE, f"no parameter to probe for '{hyp.technique}'", None)
    origin = _origin(hyp.url)
    if not origin:
        return (_INCONCLUSIVE, f"cannot derive target origin from {hyp.url!r}", None)

    check = spec.build_check(hyp, _path(hyp.url))
    policy = spec.policy_cls(checks=(check,))
    graph = _graph()
    results = _run(graph, policy, target_base=origin)
    if not results:
        return (_INCONCLUSIVE, "judge produced no probe result", None)
    result = results[0]
    evidence = JudgeEvidence(
        technique=hyp.technique, result=result, graph=graph,
        policy=policy, target_base=origin,
    )
    return (getattr(result, "status", _INCONCLUSIVE), getattr(result, "reason", ""), evidence)


def make_judge(technique: str, spec: "_JudgeSpec | None" = None) -> Callable:
    """A judge callable for one technique, matching the orchestrator protocol
    ``judge(hyp, prober=None)``. ``_run`` / ``_graph`` are keyword seams tests
    override to run fully offline."""
    spec = spec or _SPECS[technique]

    def judge(hyp, prober=None, *, _run=spec.run_fn, _graph=SecurityGraph):
        return _adjudicate(hyp, spec, _run=_run, _graph=_graph)

    judge.__name__ = f"judge_{technique}"
    judge.technique = technique
    return judge


def default_judges() -> dict:
    """The full technique -> judge map the CLI injects into the orchestrator.
    Only differential techniques with a single-probe judge are wired; the rest
    (broken_auth / idor / privilege_escalation) stay honest LEADs by omission."""
    return {tech: make_judge(tech, spec) for tech, spec in _SPECS.items()}


WIRED_TECHNIQUES = tuple(_SPECS)



