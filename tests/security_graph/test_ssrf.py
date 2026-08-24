"""
Offline, network-free proof of the SSRF (out-of-band callback differential) class
and its PATCH + PROVE remediation. No real target is contacted for the unit tests:
a canned executor extracts the URL injected into the declared fetch parameter and,
via an in-memory collaborator, models whether the target performs a server-side
fetch of it — so the callback differential is pinned exactly:

  * a declared fetch surface becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when the payload probe reaches the
    collaborator on the unforgeable nonce — a token that could ONLY have come from
    our parameter value — AND the same-origin control anchor proves that nonce was
    un-hit before injection; DISPROVED when the parameter triggers no callback
    (also the post-fix state once the egress-allowlist request-guard denies the
    off-allowlist URL); and INCONCLUSIVE when a never-injected control nonce is
    recorded (a spurious/forged collaborator record) — in every non-VALIDATED case
    NO finding is manufactured;
  * a corrective request-guard (signature family ``url_allowlist``, pinned to the
    target's exact host:port) is derived only from a confirmed SSRF, and the same
    judge — re-run through the enforcement shield — proves the fix ONLY when it
    flips VALIDATED -> DISPROVED (the collaborator URL becomes 403 so no callback
    lands while the benign same-origin control is still forwarded);
  * verification NEVER mutates the confirmed hypothesis or finding.

One localhost integration test stands the real reverse proxy in front of a stub
upstream that genuinely performs a server-side fetch of the ``url`` parameter (a
real SSRF reaching Sentinel's own loopback collaborator), and proves the
request-guard blocks the off-allowlist collaborator URL (403) so the callback is
never made, while still forwarding the benign same-origin control.
"""

import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit

import pytest

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.ssrf import (
    SentinelCollaborator,
    judge_ssrf,
    parse_ssrf_policy,
    remediate_ssrf_and_prove,
    render_ssrf_artifacts,
    run_ssrf_investigation,
    synthesize_ssrf_remediation,
)
from app.security_graph.remediation.enforcer import (
    RemediationEnforcer,
    RequestGuardRule,
    _matches_url_allowlist,
    evaluate_request_guard,
)

TARGET_BASE = "http://127.0.0.1:3000"
FETCH_PATH = "/fetch"
TARGET_NETLOC = "127.0.0.1:3000"
# A DIFFERENT loopback port stands in for Sentinel's own collaborator: same host
# as the target, distinct port — so the host:port allowlist denies it while a bare
# host would not (exactly why SSRF pins the allow entry to the netloc).
COLLAB_BASE = "http://127.0.0.1:59999"
COLLAB_NETLOC = "127.0.0.1:59999"

_QUERY_CHECK = {
    "method": "GET",
    "path": FETCH_PATH,
    "param": "url",
    "location": "query",
    "severity": "HIGH",
}


# --- server-side fetch models: (value) -> (status_code, fetched?) -------------
# Each models whether a target performs a SERVER-SIDE fetch of the URL placed in
# the `url` parameter. The canned executor records the collaborator nonce ONLY
# when the model says a fetch happened AND that URL names our collaborator — so
# the out-of-band callback differential is pinned without touching a network.

def _ssrf_fetcher(value: str) -> tuple[int, bool]:
    # VULNERABLE: the backend fetches ANY absolute URL it is handed. The payload
    # (collaborator URL) reaches our loopback listener; the same-origin control
    # reaches only the target itself.
    return 200, bool(value and "://" in value)


def _non_fetching(value: str) -> tuple[int, bool]:
    # SAFE: the parameter is never turned into a server-side request -> DISPROVED.
    return 200, False


def _guarded(value: str) -> tuple[int, bool]:
    # BEHIND the egress-allowlist request-guard: a URL whose host:port is not the
    # target's own is refused (403) before any fetch, so the collaborator is never
    # reached; the benign same-origin control is forwarded and fetched (but only
    # ever reaches the target). Uses the REAL enforcer allowlist test so the
    # offline model stays faithful to the deployed shield.
    if _matches_url_allowlist(value, (TARGET_NETLOC,)):
        return 403, False
    return 200, bool(value and "://" in value)


class _CannedCollaborator:
    """In-memory stand-in for :class:`SentinelCollaborator` — no socket.

    Provides the exact surface the runner/remediation read: ``base_url``,
    ``callback_url(nonce)``, ``was_hit(nonce)``, ``wait_for_hit(nonce)``. A canned
    executor calls ``record(nonce)`` to model the target's server-side fetch of
    the collaborator URL landing on our loopback listener.
    """

    def __init__(self, base_url: str = COLLAB_BASE):
        self.base_url = base_url
        self._hits: set[str] = set()

    def callback_url(self, nonce: str) -> str:
        return f"{self.base_url}/{nonce}"

    def record(self, nonce: str) -> None:
        if nonce:
            self._hits.add(nonce)

    def was_hit(self, nonce: str) -> bool:
        return nonce in self._hits

    def wait_for_hit(self, nonce: str, *, timeout: float = 1.5,
                     interval: float = 0.02) -> bool:
        # State is set synchronously by the executor during execute(); no poll.
        return nonce in self._hits


class _LeakyCollaborator(_CannedCollaborator):
    """A forged/untrustworthy collaborator that reports EVERY nonce as hit —
    including a never-injected control nonce. The judge must refuse to attribute
    such a record (INCONCLUSIVE), never manufacture a finding from it.
    """

    def was_hit(self, nonce: str) -> bool:
        return True

    def wait_for_hit(self, nonce: str, *, timeout: float = 1.5,
                     interval: float = 0.02) -> bool:
        return True


class _CannedSsrfExecutor(ExperimentExecutor):
    """Network-free SSRF executor: extract the injected URL, model whether the
    target fetches it, and — when it does and the URL names our collaborator —
    record the callback nonce on the shared collaborator. It writes only a
    ``mode=="http"`` HTTP fact; the RUNNER reads the collaborator hit separately,
    exactly as the live path does. No socket is opened.
    """

    kind = "ssrf_check"

    def __init__(self, responder, collaborator, *, param="url", location="query"):
        self._responder = responder
        self._collab = collaborator
        self._param = param
        self._location = location

    def _injected_value(self, experiment) -> str:
        req = experiment.request
        if req is None:
            return ""
        if self._location == "query":
            parsed = dict(parse_qsl(urlsplit(req.url).query, keep_blank_values=True))
            return parsed.get(self._param, "")
        if self._location == "body_form":
            parsed = dict(parse_qsl(req.body or "", keep_blank_values=True))
            return parsed.get(self._param, "")
        import json as _json

        try:
            decoded = _json.loads(req.body or "{}")
        except (ValueError, TypeError):
            return ""
        value = decoded.get(self._param, "") if isinstance(decoded, dict) else ""
        return value if isinstance(value, str) else ""

    def _record_if_collaborator(self, value: str) -> None:
        # A server-side fetch reaches our listener ONLY when the URL names the
        # collaborator's exact host:port. The nonce is the leading path segment
        # (mirrors the real collaborator's _nonce_of).
        if urlsplit(value).netloc.lower() != urlsplit(self._collab.base_url).netloc.lower():
            return
        nonce = next((seg for seg in urlsplit(value).path.split("/") if seg), "")
        self._collab.record(nonce)

    def execute(self, experiment):
        value = self._injected_value(experiment)
        code, fetched = self._responder(value)
        if fetched:
            self._record_if_collaborator(value)
        evidence = Evidence(
            id=f"ev:ssrf:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": code,
                "response_headers": [],
                "url": experiment.request.url if experiment.request else "",
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", str(code)),),
        )


def _matrix(check=None):
    """Build a one-check SSRF matrix policy."""
    return parse_ssrf_policy(
        {"ssrf_matrix": {"checks": [check or dict(_QUERY_CHECK)]}}
    )


def _resolved_graph(responder, *, collaborator=None, check=None,
                    param="url", location="query"):
    """Seed one fetch surface and drive it to a verdict with a canned model."""
    graph = SecurityGraph()
    collab = collaborator or _CannedCollaborator()
    results = run_ssrf_investigation(
        graph,
        _matrix(check),
        target_base=TARGET_BASE,
        executor=_CannedSsrfExecutor(responder, collab, param=param, location=location),
        collaborator=collab,
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(graph.findings_for(kind="ssrf", status="OPEN"))
    assert len(findings) == 1
    return findings[0]


# --- parse -----------------------------------------------------------------

def test_parse_ssrf_matrix_reads_checks():
    policy = _matrix()
    assert len(policy.checks) == 1
    check = policy.checks[0]
    assert check.method == "GET" and check.path == FETCH_PATH
    assert check.param == "url" and check.location == "query"
    assert check.severity == "HIGH"


def test_parse_no_matrix_yields_empty_policy():
    assert parse_ssrf_policy({"access_rules": []}).checks == ()


def test_parse_rejects_bad_location():
    with pytest.raises(ValueError):
        parse_ssrf_policy(
            {"ssrf_matrix": {"checks": [
                {"method": "GET", "path": FETCH_PATH, "param": "url",
                 "location": "header"}
            ]}}
        )


def test_parse_rejects_missing_param():
    with pytest.raises(ValueError):
        parse_ssrf_policy(
            {"ssrf_matrix": {"checks": [{"method": "GET", "path": FETCH_PATH}]}}
        )


# --- seed + PURE two-probe out-of-band callback differential judge ---------

def test_ssrf_surface_is_validated_and_confirmed():
    graph, results = _resolved_graph(_ssrf_fetcher)
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert results[0].param == "url"
    assert results[0].callback_hit is True
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "ssrf"
    assert finding.severity == "HIGH"


def test_non_fetching_endpoint_is_disproved_no_finding():
    # The parameter is never fetched server-side -> no callback -> DISPROVED.
    graph, results = _resolved_graph(_non_fetching)
    assert results[0].status == "DISPROVED"
    assert results[0].callback_hit is False
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(graph.findings_for(kind="ssrf", status="OPEN"))


def test_guarded_endpoint_is_disproved_no_finding():
    # The egress-allowlist guard refuses the collaborator URL (403) so no callback
    # lands -> DISPROVED (the post-fix state), nothing manufactured.
    graph, results = _resolved_graph(_guarded)
    assert results[0].status == "DISPROVED"
    assert not list(graph.findings_for(kind="ssrf", status="OPEN"))


def test_forged_collaborator_record_is_inconclusive_no_finding():
    # A never-injected control nonce recorded by the collaborator means its
    # attribution cannot be trusted -> INCONCLUSIVE, hypothesis stays OPEN.
    graph, results = _resolved_graph(
        _ssrf_fetcher, collaborator=_LeakyCollaborator()
    )
    assert results[0].status == "INCONCLUSIVE"
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(graph.findings_for(kind="ssrf", status="OPEN"))


def test_pure_judge_reads_the_callback_differential_directly():
    # Drive to a confirmed graph, then re-run the PURE judge against the same
    # recorded probes and assert VALIDATED is a deterministic function of them.
    graph, results = _resolved_graph(_ssrf_fetcher)
    hyp = graph.hypotheses[results[0].hypothesis_id]
    judgment = judge_ssrf(
        graph,
        hypothesis=hyp,
        control_experiment_id=f"exp:ssrf-control:{hyp.id}",
        payload_experiment_id=f"exp:ssrf-payload:{hyp.id}",
    )
    assert judgment.status == "VALIDATED"
    assert judgment.contradiction_kind == "ssrf"
    assert judgment.observed is True


# --- guard purity (the virtual-patch decision) -----------------------------

def test_matches_url_allowlist_is_port_aware():
    # Same-host DIFFERENT port (the collaborator) is denied even though the host
    # matches — this is the crux of the SSRF egress allowlist.
    assert _matches_url_allowlist("http://127.0.0.1:59999/abc123", (TARGET_NETLOC,))
    # Same host:port (the target itself / the benign control) is forwarded.
    assert not _matches_url_allowlist("http://127.0.0.1:3000/", (TARGET_NETLOC,))
    # Relative / empty carry no host -> never denied.
    assert not _matches_url_allowlist("/local", (TARGET_NETLOC,))
    assert not _matches_url_allowlist("", (TARGET_NETLOC,))
    # A BARE-host allow entry does NOT block a same-host different-port fetch —
    # precisely why SSRF pins the allow entry to host:port rather than host.
    assert not _matches_url_allowlist("http://127.0.0.1:59999/abc", ("127.0.0.1",))


def test_evaluate_request_guard_denies_off_allowlist_forwards_same_origin():
    rule = RequestGuardRule(
        method="GET", path=FETCH_PATH, param="url", location="query",
        signature_family="url_allowlist", allow=(TARGET_NETLOC,),
    )
    # The benign same-origin control is forwarded.
    assert (
        evaluate_request_guard(
            "GET", FETCH_PATH, "url=http%3A%2F%2F127.0.0.1%3A3000%2F", None, (rule,)
        )
        == "forward"
    )
    # The collaborator URL (same host, different port) is denied.
    assert (
        evaluate_request_guard(
            "GET", FETCH_PATH, "url=http%3A%2F%2F127.0.0.1%3A59999%2Fabc", None,
            (rule,),
        )
        == "deny"
    )
    # A different route is untouched by this guard.
    assert (
        evaluate_request_guard(
            "GET", "/other", "url=http%3A%2F%2F127.0.0.1%3A59999%2Fabc", None,
            (rule,),
        )
        == "forward"
    )


# --- synthesize + artifacts -------------------------------------------------

def test_synthesize_ssrf_remediation_from_confirmed_finding():
    graph, _ = _resolved_graph(_ssrf_fetcher)
    plan = synthesize_ssrf_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.method == "GET" and plan.rule.path == FETCH_PATH
    assert plan.rule.param == "url" and plan.rule.location == "query"
    assert plan.rule.allow_netloc == TARGET_NETLOC
    assert plan.upstream_base == TARGET_BASE
    assert plan.endpoint_url == TARGET_BASE + FETCH_PATH


def test_synthesize_ignores_non_ssrf_finding():
    from dataclasses import replace

    graph, _ = _resolved_graph(_ssrf_fetcher)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    assert synthesize_ssrf_remediation(graph, foreign) is None


def test_render_ssrf_artifacts_non_empty_and_name_the_param():
    graph, _ = _resolved_graph(_ssrf_fetcher)
    plan = synthesize_ssrf_remediation(graph, _confirmed_finding(graph))
    artifacts = render_ssrf_artifacts(plan.rule, plan.upstream_base)
    for config in (artifacts.portable_json, artifacts.nginx,
                   artifacts.modsecurity, artifacts.caddy):
        assert config.strip()
        assert "url" in config
    assert plan.upstream_base in artifacts.portable_json
    assert TARGET_NETLOC in artifacts.portable_json


# --- remediate + PROVE (injected executors, no live proxy) -----------------

def test_remediate_ssrf_and_prove_fix_proven_and_isolated():
    graph, _ = _resolved_graph(_ssrf_fetcher)
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id
    collab = _CannedCollaborator()

    outcome = remediate_ssrf_and_prove(
        graph,
        finding,
        # before: the backend still fetches the collaborator URL -> VALIDATED
        before_executor=_CannedSsrfExecutor(_ssrf_fetcher, collab),
        # after: the egress-allowlist guard refuses the collaborator URL -> DISPROVED
        after_executor=_CannedSsrfExecutor(_guarded, collab),
        collaborator=collab,
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_ssrf_fix_failed_when_guard_does_not_block():
    graph, _ = _resolved_graph(_ssrf_fetcher)
    collab = _CannedCollaborator()
    outcome = remediate_ssrf_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedSsrfExecutor(_ssrf_fetcher, collab),
        # still fetches the collaborator URL -> callback lands -> VALIDATED
        after_executor=_CannedSsrfExecutor(_ssrf_fetcher, collab),
        collaborator=collab,
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_ssrf_fix_failed_when_ssrf_did_not_reproduce():
    # The after re-probe is DISPROVED, but the SSRF did NOT reproduce on the
    # pre-fix re-probe (before != VALIDATED). A guard cannot take credit for a
    # boundary already holding, so FIX_PROVEN requires the full flip.
    graph, _ = _resolved_graph(_ssrf_fetcher)
    collab = _CannedCollaborator()
    outcome = remediate_ssrf_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedSsrfExecutor(_non_fetching, collab),  # no repro
        after_executor=_CannedSsrfExecutor(_guarded, collab),
        collaborator=collab,
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.before_status == "DISPROVED"
    assert not outcome.verification.proven


def test_remediate_non_ssrf_finding_is_not_applicable():
    from dataclasses import replace

    graph, _ = _resolved_graph(_ssrf_fetcher)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    outcome = remediate_ssrf_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"


# --- live integration: real reverse proxy blocks the collaborator URL --------

class _SsrfFetchingHandler(BaseHTTPRequestHandler):
    """A genuinely SSRF-vulnerable target: on ``/fetch`` it takes the ``url``
    parameter and performs a SERVER-SIDE GET of it (reaching whatever host the
    value names — the real out-of-band callback), then returns 200. Every other
    path returns a plain 200 without fetching, so the same-origin control (a fetch
    of the target's own ``/``) terminates cleanly and never recurses.
    """

    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        import urllib.request as _req

        split = urlsplit(self.path)
        if split.path == FETCH_PATH:
            dest = (parse_qs(split.query, keep_blank_values=True).get("url") or [""])[0]
            if dest:
                try:
                    _req.urlopen(dest, timeout=5).read()
                except Exception:  # noqa: BLE001 — a dead fetch must not 500 the probe
                    pass
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def test_live_ssrf_confirmed_then_enforcer_proves_fix():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _SsrfFetchingHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"

        # Seed a fresh graph bound to the live stub and drive it to a confirmed
        # SSRF with the REAL executor + REAL loopback collaborator (the backend
        # genuinely fetches our collaborator on the unforgeable nonce), then prove
        # the fix through the REAL reverse proxy with the egress-allowlist guard.
        graph = SecurityGraph()
        run_ssrf_investigation(
            graph,
            _matrix(),
            target_base=upstream_base,
            executor=None,       # real SsrfProbeExecutor
            collaborator=None,   # real SentinelCollaborator on loopback
        )
        finding = _confirmed_finding(graph)

        outcome = remediate_ssrf_and_prove(graph, finding, use_enforcer=True)

        assert outcome.result == "FIX_PROVEN"
        assert outcome.verification.before_status == "VALIDATED"
        assert outcome.verification.after_status == "DISPROVED"
    finally:
        upstream.shutdown()
        upstream.server_close()

