"""
Offline, network-free proof of the path-traversal / LFI (OS-canary differential)
class and its PATCH + PROVE remediation. No real target is contacted for the unit
tests: a canned executor extracts the value injected into the declared parameter
and returns a modelled response BODY, so the differential is pinned exactly:

  * a declared path-traversal surface becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when a payload response contains an
    OS-file INVARIANT (``root:x:0:0:`` for /etc/passwd, a ``[fonts]`` section for
    win.ini) that is ABSENT from the benign, traversal-free control; DISPROVED
    when no payload leaks an invariant (the parameter canonicalises / confines to
    a safe root), which is also the post-fix state once the request-guard blocks
    the escape shapes; and INCONCLUSIVE when the control anchor is contaminated
    (the control response ALREADY carries the invariant with no escape) — in every
    non-VALIDATED case NO finding is manufactured;
  * a corrective request-guard (signature family ``traversal``) is derived only
    from a confirmed traversal, and the same judge — re-run through the
    enforcement shield — proves the fix ONLY when it flips VALIDATED -> DISPROVED
    (the escape payloads become 403 so no invariant reaches the response while the
    benign control filename is still forwarded);
  * verification NEVER mutates the confirmed hypothesis or finding.

One localhost integration test stands the real reverse proxy in front of a stub
upstream that genuinely leaks /etc/passwd through directory escape, and proves the
request-guard blocks the escape payloads (403) so no invariant leaks, while still
forwarding the benign control filename.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.path_traversal import (
    CONTROL_VALUE,
    judge_path_traversal,
    leaked_canary,
    parse_traversal_policy,
    remediate_path_traversal_and_prove,
    render_path_traversal_artifacts,
    run_path_traversal_investigation,
    synthesize_path_traversal_remediation,
    traversal_payloads,
)
from app.security_graph.remediation.enforcer import (
    RemediationEnforcer,
    RequestGuardRule,
    _matches_signature,
    evaluate_request_guard,
)


TARGET_BASE = "http://127.0.0.1:3000"
DOWNLOAD_PATH = "/download"

_QUERY_CHECK = {
    "method": "GET",
    "path": DOWNLOAD_PATH,
    "param": "file",
    "location": "query",
    "severity": "HIGH",
}

# The OS-file invariants a leaked system file uniquely carries.
_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
)
_WININI = "; for 16-bit app support\n[fonts]\n[extensions]\nMAPI=1\n"


# --- deterministic sink models (no network, no real filesystem) ------------

def _leaking_body(value: str) -> str:
    # VULNERABLE: the parameter is resolved to a filesystem path with no
    # confinement, so a directory-escape payload aimed at a system file leaks its
    # contents verbatim -> the OS invariant appears -> VALIDATED. The benign
    # control filename resolves to an ordinary (or missing) in-directory file and
    # carries NO invariant.
    low = value.lower()
    if "etc/passwd" in low:
        return _PASSWD
    if "win.ini" in low:
        return _WININI
    return f"<html><body>contents of: {value} (no such file)</body></html>"


def _safe_body(value: str) -> str:
    # SAFE: the parameter is canonicalised and confined to a safe root, so an
    # escape payload never reaches a system file -> no invariant ever appears ->
    # DISPROVED. The raw value may be echoed, but never the invariant content.
    return f"<html><body>contents of: {value} (confined to root)</body></html>"


def _contaminated_control_body(value: str) -> str:
    # The passwd invariant is ALREADY on the page independent of any escape: even
    # the benign, traversal-free control response carries `root:x:0:0:`, so the
    # canary anchor is contaminated -> INCONCLUSIVE (a leak under a payload cannot
    # be attributed to traversal).
    return f"<html><body>{_PASSWD}<!-- echo: {value} --></body></html>"


def _guarded_body(value: str) -> str:
    # BEHIND the request-guard: a value carrying a directory-escape signature is
    # refused before it reaches the file sink (403, no invariant), so no system
    # file can leak; the benign control filename is forwarded. Uses the REAL
    # enforcer signature test so the offline model stays faithful.
    if _matches_signature(value, "traversal"):
        return '{"error":"Forbidden","by":"sentinel-remediation"}'
    return f"<html><body>contents of: {value}</body></html>"

class _CannedTraversalExecutor(ExperimentExecutor):
    """Network-free path-traversal executor: extract the injected value and
    return a modelled response BODY. The judge reads only ``response_body_text``
    from the single ``mode=="http"`` evidence, so this pins the OS-canary
    differential without touching a network or a real filesystem.
    """

    kind = "path_traversal_check"

    def __init__(self, responder, *, param="file", location="query"):
        self._responder = responder
        self._param = param
        self._location = location

    def _injected_value(self, experiment) -> str:
        req = experiment.request
        if req is None:
            return ""
        if self._location == "query":
            parsed = dict(
                parse_qsl(urlsplit(req.url).query, keep_blank_values=True)
            )
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

    def execute(self, experiment):
        value = self._injected_value(experiment)
        body = self._responder(value)
        evidence = Evidence(
            id=f"ev:traversal:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": 200,
                "response_body_length": len(body),
                "response_body_text": body,
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


def _matrix(check=None):
    """Build a one-check path-traversal matrix policy."""
    return parse_traversal_policy(
        {"path_traversal_matrix": {"checks": [check or dict(_QUERY_CHECK)]}}
    )


def _resolved_graph(responder, *, check=None, param="file", location="query"):
    """Seed one path-traversal surface and drive it to a verdict with a model."""
    graph = SecurityGraph()
    results = run_path_traversal_investigation(
        graph,
        _matrix(check),
        target_base=TARGET_BASE,
        executor=_CannedTraversalExecutor(
            responder, param=param, location=location
        ),
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(graph.findings_for(kind="path_traversal", status="OPEN"))
    assert len(findings) == 1
    return findings[0]
# --- parse -----------------------------------------------------------------

def test_parse_traversal_matrix_reads_checks():
    policy = _matrix()
    assert len(policy.checks) == 1
    check = policy.checks[0]
    assert check.method == "GET" and check.path == DOWNLOAD_PATH
    assert check.param == "file" and check.location == "query"
    assert check.severity == "HIGH"


def test_parse_no_matrix_yields_empty_policy():
    # A combined document with no path_traversal_matrix section -> "not requested".
    assert parse_traversal_policy({"access_rules": []}).checks == ()


def test_parse_rejects_bad_location():
    with pytest.raises(ValueError):
        parse_traversal_policy(
            {"path_traversal_matrix": {"checks": [
                {"method": "GET", "path": DOWNLOAD_PATH, "param": "file",
                 "location": "header"}
            ]}}
        )


def test_parse_rejects_missing_param():
    with pytest.raises(ValueError):
        parse_traversal_policy(
            {"path_traversal_matrix": {"checks": [
                {"method": "GET", "path": DOWNLOAD_PATH}
            ]}}
        )


# --- control + payload + invariant helpers ---------------------------------

def test_control_value_is_benign_and_traversal_free():
    assert CONTROL_VALUE == "sentinel-baseline.txt"
    # No directory-escape and no OS-file name -> cannot leak a system file, and is
    # not matched by the enforcer's traversal request-guard.
    assert not _matches_signature(CONTROL_VALUE, "traversal")
    assert leaked_canary(_leaking_body(CONTROL_VALUE)) is None


def test_every_payload_is_an_escape_shape_the_guard_blocks():
    payloads = dict(traversal_payloads())
    assert set(payloads) == {
        "posix_dotdot", "posix_nested", "posix_abs",
        "posix_nullbyte", "win_dotdot", "win_abs",
    }
    for value in payloads.values():
        # Each payload names a cross-OS canary AND is caught by the traversal
        # request-guard family (so the fix is provable by the same shapes).
        assert _matches_signature(value, "traversal")


def test_leaked_canary_detects_os_invariants_only():
    assert leaked_canary(_PASSWD) == "etc_passwd"
    assert leaked_canary(_WININI) == "win_ini"
    assert leaked_canary("green tea 500ml, no system files here") is None
# --- seed + PURE OS-canary-differential judge ------------------------------

def test_leaking_traversal_is_validated_and_confirmed():
    graph, results = _resolved_graph(_leaking_body)
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert results[0].param == "file"
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "path_traversal"
    assert finding.severity == "HIGH"


def test_safe_confined_surface_is_disproved_no_finding():
    # No payload leaks an OS invariant (canonicalised / confined to root) ->
    # DISPROVED, nothing manufactured.
    graph, results = _resolved_graph(_safe_body)
    assert results[0].status == "DISPROVED"
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(graph.findings_for(kind="path_traversal", status="OPEN"))


def test_contaminated_control_is_inconclusive_no_finding():
    # The invariant already appears in the benign control (no escape sent), so the
    # canary anchor is contaminated -> INCONCLUSIVE, never a manufactured verdict.
    graph, results = _resolved_graph(_contaminated_control_body)
    assert results[0].status == "INCONCLUSIVE"
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(graph.findings_for(kind="path_traversal", status="OPEN"))


def test_guarded_surface_is_disproved_no_finding():
    # Behind the request-guard the escape payloads are blocked (403, no invariant)
    # while the benign control filename is still served -> DISPROVED.
    graph, results = _resolved_graph(_guarded_body)
    assert results[0].status == "DISPROVED"
    assert not list(graph.findings_for(kind="path_traversal", status="OPEN"))


def test_pure_judge_reads_the_canary_differential_directly():
    # Drive to a confirmed graph, then re-run the PURE judge against the same
    # recorded probes and assert VALIDATED is a deterministic function of them.
    graph, results = _resolved_graph(_leaking_body)
    hyp = graph.hypotheses[results[0].hypothesis_id]
    labels = [label for label, _ in traversal_payloads()]
    payload_ids = tuple(
        (label, f"exp:traversal-payload-{label}:{hyp.id}") for label in labels
    )
    judgment = judge_path_traversal(
        graph,
        hypothesis=hyp,
        control_experiment_id=f"exp:traversal-control:{hyp.id}",
        payload_experiment_ids=payload_ids,
    )
    assert judgment.status == "VALIDATED"
    assert judgment.contradiction_kind == "path_traversal"
    assert judgment.observed is True
# --- guard purity (the virtual-patch decision) -----------------------------

def test_matches_traversal_signature_catches_escape_not_benign():
    assert _matches_signature("../../../../etc/passwd", "traversal")
    assert _matches_signature("..\\..\\..\\windows\\win.ini", "traversal")
    assert _matches_signature("/etc/passwd", "traversal")
    assert _matches_signature("%2e%2e/%2e%2e/etc/passwd", "traversal")
    assert not _matches_signature("sentinel-baseline.txt", "traversal")
    assert not _matches_signature("report-2026.pdf", "traversal")


def test_evaluate_request_guard_denies_escape_forwards_benign():
    rule = RequestGuardRule(
        method="GET", path=DOWNLOAD_PATH, param="file", location="query",
        signature_family="traversal",
    )
    # The benign control filename (no escape) is forwarded.
    assert (
        evaluate_request_guard(
            "GET", DOWNLOAD_PATH, "file=sentinel-baseline.txt", None, (rule,)
        )
        == "forward"
    )
    # A directory-escape payload (URL-encoded ../../etc/passwd) is denied.
    payload = "file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    assert (
        evaluate_request_guard("GET", DOWNLOAD_PATH, payload, None, (rule,))
        == "deny"
    )
    # A different route is untouched by this guard.
    assert (
        evaluate_request_guard("GET", "/other", payload, None, (rule,))
        == "forward"
    )


# --- synthesize + artifacts -------------------------------------------------

def test_synthesize_traversal_remediation_from_confirmed_finding():
    graph, _ = _resolved_graph(_leaking_body)
    plan = synthesize_path_traversal_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.method == "GET" and plan.rule.path == DOWNLOAD_PATH
    assert plan.rule.param == "file" and plan.rule.location == "query"
    assert plan.upstream_base == TARGET_BASE
    assert plan.endpoint_url == TARGET_BASE + DOWNLOAD_PATH
    assert plan.control == CONTROL_VALUE


def test_synthesize_ignores_non_traversal_finding():
    from dataclasses import replace

    graph, _ = _resolved_graph(_leaking_body)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    assert synthesize_path_traversal_remediation(graph, foreign) is None


def test_render_traversal_artifacts_non_empty_and_name_the_param():
    graph, _ = _resolved_graph(_leaking_body)
    plan = synthesize_path_traversal_remediation(graph, _confirmed_finding(graph))
    artifacts = render_path_traversal_artifacts(plan.rule, plan.upstream_base)
    for config in (artifacts.portable_json, artifacts.nginx,
                   artifacts.modsecurity, artifacts.caddy):
        assert config.strip()
        assert "file" in config
    assert plan.upstream_base in artifacts.portable_json
    assert "traversal" in artifacts.portable_json
# --- remediate + PROVE (injected executors, no live proxy) -----------------

def test_remediate_traversal_and_prove_fix_proven_and_isolated():
    graph, _ = _resolved_graph(_leaking_body)
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id

    outcome = remediate_path_traversal_and_prove(
        graph,
        finding,
        # before: still leaks the OS invariant -> VALIDATED
        before_executor=_CannedTraversalExecutor(_leaking_body),
        # after: request-guard blocks the escape payloads -> no invariant -> DISPROVED
        after_executor=_CannedTraversalExecutor(_guarded_body),
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_traversal_fix_failed_when_guard_does_not_block():
    graph, _ = _resolved_graph(_leaking_body)
    outcome = remediate_path_traversal_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedTraversalExecutor(_leaking_body),
        after_executor=_CannedTraversalExecutor(_leaking_body),  # still leaks
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_traversal_fix_failed_when_traversal_did_not_reproduce():
    # The after re-probe is DISPROVED, but the traversal did NOT reproduce on the
    # pre-fix re-probe (before != VALIDATED). A guard cannot take credit for a
    # boundary already holding, so FIX_PROVEN requires the full flip.
    graph, _ = _resolved_graph(_leaking_body)
    outcome = remediate_path_traversal_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedTraversalExecutor(_safe_body),  # no reproduction
        after_executor=_CannedTraversalExecutor(_guarded_body),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.before_status == "DISPROVED"
    assert not outcome.verification.proven


def test_remediate_non_traversal_finding_is_not_applicable():
    from dataclasses import replace

    graph, _ = _resolved_graph(_leaking_body)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    outcome = remediate_path_traversal_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"
# --- live integration: real reverse proxy blocks escape, keeps benign -------

class _LeakingHandler(BaseHTTPRequestHandler):
    """The pre-fix vulnerable target: a file-download endpoint that resolves the
    ``file`` parameter to a path with NO confinement, so a directory-escape
    payload aimed at a system file leaks its contents verbatim (VALIDATED) before
    the fix, while the benign control filename resolves to an ordinary (missing)
    in-directory file carrying no OS invariant.
    """

    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        split = urlsplit(self.path)
        params = parse_qs(split.query, keep_blank_values=True)
        value = (params.get("file") or [""])[0]
        body = _leaking_body(value).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def test_live_enforcer_blocks_traversal_but_forwards_benign():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _LeakingHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"

        # Seed a fresh graph bound to the live stub and drive it to a confirmed
        # path traversal with the REAL HTTP executor, then prove the fix through
        # the REAL reverse proxy with the request-guard active.
        graph = SecurityGraph()
        run_path_traversal_investigation(
            graph,
            _matrix(),
            target_base=upstream_base,
            executor=None,  # real PathTraversalProbeExecutor, scope-bound to stub
        )
        finding = _confirmed_finding(graph)

        outcome = remediate_path_traversal_and_prove(
            graph, finding, use_enforcer=True
        )

        assert outcome.result == "FIX_PROVEN"
        assert outcome.verification.before_status == "VALIDATED"
        assert outcome.verification.after_status == "DISPROVED"
    finally:
        upstream.shutdown()
        upstream.server_close()


def test_live_enforcer_returns_403_for_payload_200_for_benign():
    # Directly observe the raw shield behaviour the DISPROVED verdict rests on:
    # an escape payload is refused (403) before it reaches the leaking upstream,
    # while the benign control filename is forwarded (200).
    import urllib.error
    import urllib.request
    from urllib.parse import urlencode

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _LeakingHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"
        guard = RequestGuardRule(
            method="GET", path=DOWNLOAD_PATH, param="file", location="query",
            signature_family="traversal",
        )
        with RemediationEnforcer((), upstream_base, guard_rules=(guard,)) as shield:
            benign = urllib.request.urlopen(
                f"{shield.base_url}{DOWNLOAD_PATH}?{urlencode({'file': CONTROL_VALUE})}",
                timeout=10,
            )
            assert benign.status == 200

            payload = urlencode({"file": "../../../../../../etc/passwd"})
            try:
                urllib.request.urlopen(
                    f"{shield.base_url}{DOWNLOAD_PATH}?{payload}", timeout=10
                )
                assert False, "the request-guard should have refused the payload"
            except urllib.error.HTTPError as exc:
                assert exc.code == 403
    finally:
        upstream.shutdown()
        upstream.server_close()
