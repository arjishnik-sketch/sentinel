"""
Offline, network-free proof of the CORS (two-probe origin differential) class
and its PATCH + PROVE remediation. No real target is contacted for the unit
tests: a canned executor reads the ``Origin`` request header injected by the
runner and returns the modelled ``Access-Control-Allow-Origin`` (ACAO) and
``Access-Control-Allow-Credentials`` (ACAC) response headers a deterministic
backend would emit, so the origin differential is pinned exactly:

  * a declared cross-origin surface becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when the attacker-Origin payload probe
    reflects the unforgeable nonce origin (or ``*``) in ACAO — a value that could
    ONLY have come from our input — AND sets ACAC ``true`` — the flag that makes
    the response readable cross-site — AND the no-Origin control anchor proves the
    reflection is origin-driven (not a static header); DISPROVED when the payload
    is not reflected, reflected WITHOUT credentials, or reflected by a STATIC
    header the control already carried (also the post-fix state); and INCONCLUSIVE
    when the payload probe evidence is missing/unreadable — in every non-VALIDATED
    case NO finding is manufactured;
  * a corrective response rewrite (strip ACAO + ACAC on the route) is derived only
    from a confirmed misconfig, and the same judge — re-run through the
    response-rewrite shield — proves the fix ONLY when it flips VALIDATED ->
    DISPROVED (the shield strips the reflection so the payload sees no ACAO);
  * verification NEVER mutates the confirmed hypothesis or finding.

Two localhost integration tests stand the real reverse proxy in front of a stub
upstream that genuinely reflects the ``Origin`` request header into ACAO and sets
ACAC (a real origin-reflecting CORS backend), and prove the shield strips both
headers from the forwarded response so the nonce reflection is gone.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Endpoint, Evidence, ExecutionResult
from app.security_graph.cors import (
    judge_cors,
    parse_cors_policy,
    remediate_cors_and_prove,
    render_cors_artifacts,
    run_cors_investigation,
    synthesize_cors_policy,
    synthesize_cors_remediation,
)
from app.security_graph.remediation.enforcer import (
    RemediationEnforcer,
    ResponseHeaderRule,
)

TARGET_BASE = "http://127.0.0.1:3000"
CORS_PATH = "/api/data"

_ACAO = "Access-Control-Allow-Origin"
_ACAC = "Access-Control-Allow-Credentials"

_CHECK = {"method": "GET", "path": CORS_PATH, "severity": "MEDIUM"}


# --- deterministic backend models: (origin request header) -> response headers -
# Each models how a target would respond to a GET with (payload) or without
# (control) the attacker ``Origin`` header. The judge reads only ACAO/ACAC, so
# the origin differential is pinned without any network.

def _reflecting_cors(origin: str) -> dict:
    # A VULNERABLE origin-reflecting backend: echoes whatever Origin it is given
    # into ACAO and allows credentials. The no-Origin control emits no ACAO, so
    # the reflection is provably origin-driven -> VALIDATED.
    if origin:
        return {_ACAO: origin, _ACAC: "true", "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}


def _no_cors(origin: str) -> dict:
    # A SAFE backend: never emits an ACAO -> no reflection -> DISPROVED.
    return {"Content-Type": "application/json"}


def _reflect_without_credentials(origin: str) -> dict:
    # Reflects the Origin but does NOT allow credentials — a browser cannot read a
    # credentialed cross-origin response, so it is not an exploitable leak.
    if origin:
        return {_ACAO: origin, "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}


def _static_wildcard(origin: str) -> dict:
    # A STATIC ``*`` present even on the no-Origin control -> not origin-driven
    # (the shape a public read-only API legitimately emits) -> DISPROVED.
    return {_ACAO: "*", _ACAC: "true", "Content-Type": "application/json"}


def _dynamic_wildcard(origin: str) -> dict:
    # Emits ``*`` + credentials ONLY when an Origin is present; the no-Origin
    # control carries no ACAO -> origin-driven wildcard -> VALIDATED.
    if origin:
        return {_ACAO: "*", _ACAC: "true"}
    return {}


def _stripped_cors(origin: str) -> dict:
    # Models the response-rewrite shield: ACAO/ACAC removed from the forwarded
    # response -> the payload probe sees no reflection -> DISPROVED.
    return {"Content-Type": "application/json"}
class _CannedCorsExecutor(ExperimentExecutor):
    """Network-free CORS executor: read the injected ``Origin`` request header and
    return a modelled ACAO/ACAC response-header set. The judge reads only the
    ``response_headers`` dict from the single ``mode=="http"`` evidence, so this
    pins the two-probe origin differential without touching a network.
    """

    kind = "cors_check"

    def __init__(self, responder):
        self._responder = responder

    def _origin(self, experiment) -> str:
        req = experiment.request
        if req is None:
            return ""
        for name, value in (req.headers or ()):
            if str(name).lower() == "origin":
                return str(value)
        return ""

    def execute(self, experiment):
        response_headers = dict(self._responder(self._origin(experiment)))
        evidence = Evidence(
            id=f"ev:cors:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": 200,
                "response_headers": response_headers,
                "url": experiment.request.url if experiment.request else "",
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", "200"),),
        )


class _UnreadableCorsExecutor(ExperimentExecutor):
    """Emits evidence that is NOT a readable HTTP fact (mode != "http"), so the
    judge cannot recover ACAO/ACAC and must yield INCONCLUSIVE rather than guess.
    """

    kind = "cors_check"

    def execute(self, experiment):
        evidence = Evidence(
            id=f"ev:cors-opaque:{experiment.id}",
            source="http_response",
            data={"mode": "opaque"},
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
        )
def _matrix(check=None):
    """Build a one-check CORS matrix policy."""
    return parse_cors_policy(
        {"cors_matrix": {"checks": [check or dict(_CHECK)]}}
    )


def _resolved_graph(responder, *, check=None, executor=None):
    """Seed one cross-origin surface and drive it to a verdict with a canned model."""
    graph = SecurityGraph()
    results = run_cors_investigation(
        graph,
        _matrix(check),
        target_base=TARGET_BASE,
        executor=executor or _CannedCorsExecutor(responder),
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(graph.findings_for(kind="cors_misconfig", status="OPEN"))
    assert len(findings) == 1
    return findings[0]


# --- parse -----------------------------------------------------------------

def test_parse_cors_matrix_reads_checks():
    policy = _matrix()
    assert len(policy.checks) == 1
    check = policy.checks[0]
    assert check.method == "GET" and check.path == CORS_PATH
    assert check.severity == "MEDIUM"


def test_parse_no_matrix_yields_empty_policy():
    assert parse_cors_policy({"access_rules": []}).checks == ()


def test_parse_rejects_missing_path():
    with pytest.raises(ValueError):
        parse_cors_policy(
            {"cors_matrix": {"checks": [{"method": "GET"}]}}
        )


def test_parse_rejects_bad_severity():
    with pytest.raises(ValueError):
        parse_cors_policy(
            {"cors_matrix": {"checks": [
                {"method": "GET", "path": CORS_PATH, "severity": "WHENEVER"}
            ]}}
        )
# --- seed + PURE two-probe origin differential judge -----------------------

def test_credentialed_origin_reflection_is_validated_and_confirmed():
    graph, results = _resolved_graph(_reflecting_cors)
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert results[0].path == CORS_PATH
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "cors_misconfig"
    assert finding.severity == "MEDIUM"


def test_no_cors_headers_is_disproved_no_finding():
    graph, results = _resolved_graph(_no_cors)
    assert results[0].status == "DISPROVED"
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(graph.findings_for(kind="cors_misconfig", status="OPEN"))


def test_reflection_without_credentials_is_disproved_no_finding():
    # A browser cannot read a credentialed cross-origin response, so a reflected
    # origin WITHOUT ACAC is not an exploitable leak -> DISPROVED.
    graph, results = _resolved_graph(_reflect_without_credentials)
    assert results[0].status == "DISPROVED"
    assert not list(graph.findings_for(kind="cors_misconfig", status="OPEN"))


def test_static_wildcard_is_disproved_no_finding():
    # ``*`` present even on the no-Origin control is a STATIC header, not driven
    # by our attacker Origin -> DISPROVED, nothing manufactured.
    graph, results = _resolved_graph(_static_wildcard)
    assert results[0].status == "DISPROVED"
    assert not list(graph.findings_for(kind="cors_misconfig", status="OPEN"))


def test_origin_driven_wildcard_with_credentials_is_validated():
    # ``*`` + credentials emitted ONLY when the Origin is present (absent on the
    # control) -> an origin-driven wildcard reflection -> VALIDATED.
    graph, results = _resolved_graph(_dynamic_wildcard)
    assert results[0].status == "VALIDATED"
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"


def test_missing_payload_evidence_is_inconclusive_no_finding():
    graph, results = _resolved_graph(None, executor=_UnreadableCorsExecutor())
    assert results[0].status == "INCONCLUSIVE"
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(graph.findings_for(kind="cors_misconfig", status="OPEN"))
def test_pure_judge_reads_the_origin_differential_directly():
    # Drive to a confirmed graph, then re-run the PURE judge against the same
    # recorded probes and assert VALIDATED is a deterministic function of them.
    graph, results = _resolved_graph(_reflecting_cors)
    hyp = graph.hypotheses[results[0].hypothesis_id]
    judgment = judge_cors(
        graph,
        hypothesis=hyp,
        control_experiment_id=f"exp:cors-control:{hyp.id}",
        payload_experiment_id=f"exp:cors-payload:{hyp.id}",
    )
    assert judgment.status == "VALIDATED"
    assert judgment.contradiction_kind == "cors_misconfig"
    assert judgment.observed is True


# --- synthesize + artifacts -------------------------------------------------

def test_synthesize_cors_remediation_from_confirmed_finding():
    graph, _ = _resolved_graph(_reflecting_cors)
    plan = synthesize_cors_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.method == "GET" and plan.rule.path == CORS_PATH
    assert plan.upstream_base == TARGET_BASE
    assert plan.endpoint_url == TARGET_BASE + CORS_PATH
    assert plan.nonce_origin.startswith("https://sentinel-")


def test_synthesize_ignores_non_cors_finding():
    from dataclasses import replace

    graph, _ = _resolved_graph(_reflecting_cors)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    assert synthesize_cors_remediation(graph, foreign) is None


def test_render_cors_artifacts_non_empty_and_name_the_headers():
    graph, _ = _resolved_graph(_reflecting_cors)
    plan = synthesize_cors_remediation(graph, _confirmed_finding(graph))
    artifacts = render_cors_artifacts(plan.rule, plan.upstream_base)
    for config in (artifacts.portable_json, artifacts.nginx,
                   artifacts.caddy, artifacts.envoy):
        assert config.strip()
        assert _ACAO in config
        assert _ACAC in config
    assert plan.upstream_base in artifacts.portable_json
# --- remediate + PROVE (injected executors, no live proxy) -----------------

def test_remediate_cors_and_prove_fix_proven_and_isolated():
    graph, _ = _resolved_graph(_reflecting_cors)
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id

    outcome = remediate_cors_and_prove(
        graph,
        finding,
        # before: still reflects the attacker origin with credentials -> VALIDATED
        before_executor=_CannedCorsExecutor(_reflecting_cors),
        # after: the response-rewrite shield stripped ACAO/ACAC -> DISPROVED
        after_executor=_CannedCorsExecutor(_stripped_cors),
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_cors_fix_failed_when_still_reflecting():
    graph, _ = _resolved_graph(_reflecting_cors)
    outcome = remediate_cors_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedCorsExecutor(_reflecting_cors),
        # still reflects with credentials -> after VALIDATED -> not proven
        after_executor=_CannedCorsExecutor(_reflecting_cors),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_cors_fix_failed_when_reflection_did_not_reproduce():
    # The after re-probe is DISPROVED, but the misconfig did NOT reproduce on the
    # pre-fix re-probe (before != VALIDATED). A shield cannot take credit for a
    # boundary already holding, so FIX_PROVEN requires the full flip.
    graph, _ = _resolved_graph(_reflecting_cors)
    outcome = remediate_cors_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedCorsExecutor(_no_cors),  # no repro
        after_executor=_CannedCorsExecutor(_stripped_cors),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.before_status == "DISPROVED"
    assert not outcome.verification.proven


def test_remediate_non_cors_finding_is_not_applicable():
    from dataclasses import replace

    graph, _ = _resolved_graph(_reflecting_cors)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    outcome = remediate_cors_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"
# --- zero-oracle discovery --------------------------------------------------

def test_synthesize_cors_policy_from_recon_surface():
    graph = SecurityGraph()
    # An observed sensitive GET surface plus a static asset that must be skipped.
    graph.add_endpoint(
        Endpoint(id="e1", method="GET", url=f"{TARGET_BASE}/api/account")
    )
    graph.add_endpoint(
        Endpoint(id="e2", method="GET", url=f"{TARGET_BASE}/static/app.js")
    )
    discovery = synthesize_cors_policy(graph)
    paths = {check.path for check in discovery.policy.checks}
    assert "/api/account" in paths      # observed sensitive surface probed
    assert "/static/app.js" not in paths  # static asset skipped
    assert "/" in paths                 # baseline root surface always present
    assert discovery.observed_count >= 1
    assert discovery.note


def test_synthesize_cors_policy_empty_graph_has_root_baseline():
    discovery = synthesize_cors_policy(SecurityGraph())
    assert [check.path for check in discovery.policy.checks] == ["/"]
    assert discovery.generic_count == 1


# --- live integration: real reverse proxy strips the reflected CORS headers --

class _ReflectingCorsHandler(BaseHTTPRequestHandler):
    """The pre-fix vulnerable target: a genuine origin-reflecting CORS backend
    that echoes the ``Origin`` request header into ``Access-Control-Allow-Origin``
    and sets ``Access-Control-Allow-Credentials: true`` (so an attacker-Origin
    payload provably reflects the nonce origin -> VALIDATED), and emits no ACAO
    for a request without an Origin (the no-Origin control -> origin-driven).
    """

    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        origin = self.headers.get("Origin")
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
def test_live_enforcer_strips_reflected_cors_and_proves_fix():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectingCorsHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"

        # Seed a fresh graph bound to the live stub and drive it to a confirmed
        # CORS misconfig with the REAL CorsProbeExecutor, then prove the fix
        # through the REAL reverse proxy stripping ACAO/ACAC.
        graph = SecurityGraph()
        run_cors_investigation(
            graph,
            _matrix(),
            target_base=upstream_base,
            executor=None,  # real CorsProbeExecutor
        )
        finding = _confirmed_finding(graph)

        outcome = remediate_cors_and_prove(graph, finding, use_enforcer=True)

        assert outcome.result == "FIX_PROVEN"
        assert outcome.verification.before_status == "VALIDATED"
        assert outcome.verification.after_status == "DISPROVED"
    finally:
        upstream.shutdown()
        upstream.server_close()


def test_live_enforcer_removes_acao_acac_from_forwarded_response():
    # Directly observe the raw shield behaviour the DISPROVED verdict rests on:
    # the enforcer forwards the attacker Origin to the reflecting upstream, then
    # strips ACAO/ACAC from the forwarded response, so a browser can no longer
    # read a credentialed cross-origin response.
    import urllib.request

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectingCorsHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"
        header_rules = (
            ResponseHeaderRule("GET", CORS_PATH, _ACAC, "remove"),
            ResponseHeaderRule("GET", CORS_PATH, _ACAO, "remove"),
        )
        # Sanity: the upstream itself really is a reflecting CORS backend.
        direct = urllib.request.Request(
            f"{upstream_base}{CORS_PATH}",
            headers={"Origin": "https://sentinel-abc123.example"},
        )
        with urllib.request.urlopen(direct, timeout=10) as resp:
            direct_headers = {k.lower(): v for k, v in resp.headers.items()}
        assert direct_headers.get("access-control-allow-origin") == (
            "https://sentinel-abc123.example"
        )
        assert direct_headers.get("access-control-allow-credentials") == "true"

        with RemediationEnforcer(
            (), upstream_base, header_rules=header_rules
        ) as shield:
            request = urllib.request.Request(
                f"{shield.base_url}{CORS_PATH}",
                headers={"Origin": "https://sentinel-abc123.example"},
            )
            with urllib.request.urlopen(request, timeout=10) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read()
        assert "access-control-allow-origin" not in headers
        assert "access-control-allow-credentials" not in headers
        assert body == b'{"ok": true}'
    finally:
        upstream.shutdown()
        upstream.server_close()
