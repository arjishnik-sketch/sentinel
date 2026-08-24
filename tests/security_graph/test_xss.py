"""
Offline, network-free proof of the reflected-XSS (reflection differential) class
and its PATCH + PROVE remediation. No real target is contacted for the unit
tests: a canned executor extracts the value injected into the declared parameter
and returns a modelled response BODY, so the differential is pinned exactly:

  * a declared reflected-XSS surface becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when a payload response contains the
    raw active markup VERBATIM (the ``<tag`` and our marker inside it survived
    un-escaped) AND the control proved the app reflects the bare marker — so the
    HTML-significant characters provably passed through output encoding; DISPROVED
    when every payload is HTML-escaped/stripped (the raw ``<tag>`` never appears),
    which is also the post-fix state once the request-guard blocks the breakout
    shapes; and INCONCLUSIVE when the control's reflection anchor is contaminated
    (the raw payload markup already appears with only the bare marker injected) —
    in every non-VALIDATED case NO finding is manufactured;
  * a corrective request-guard (signature family ``xss``) is derived only from a
    confirmed reflected XSS, and the same judge — re-run through the enforcement
    shield — proves the fix ONLY when it flips VALIDATED -> DISPROVED (the breakout
    payloads become 403 so the raw markup never reflects while the benign control
    marker is still forwarded);
  * verification NEVER mutates the confirmed hypothesis or finding.

One localhost integration test stands the real reverse proxy in front of a stub
upstream that genuinely reflects the parameter un-escaped, and proves the
request-guard blocks the breakout payloads (403) so the raw markup never reflects,
while still forwarding the benign control marker.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.xss import (
    judge_reflected_xss,
    make_marker,
    marker_payloads,
    parse_xss_policy,
    remediate_xss_and_prove,
    render_xss_artifacts,
    run_xss_investigation,
    synthesize_xss_remediation,
)
from app.security_graph.remediation.enforcer import (
    RemediationEnforcer,
    RequestGuardRule,
    _matches_signature,
    evaluate_request_guard,
)


TARGET_BASE = "http://127.0.0.1:3000"
SEARCH_PATH = "/rest/products/search"

_QUERY_CHECK = {
    "method": "GET",
    "path": SEARCH_PATH,
    "param": "q",
    "location": "query",
    "severity": "HIGH",
}


# --- deterministic sink models (no network, no real browser) ---------------

def _html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def _unescaped_reflecting_body(value: str) -> str:
    # VULNERABLE: the value is reflected verbatim into the HTML, so a payload's
    # raw <tag> markup (carrying our marker) survives un-escaped -> VALIDATED,
    # while the benign marker control merely reflects.
    return f"<html><body>Results for: {value}</body></html>"


def _escaping_body(value: str) -> str:
    # SAFE: the value is HTML-escaped at the sink, so <script> becomes
    # &lt;script&gt; and the raw payload never appears -> DISPROVED. The marker
    # (no HTML-significant chars) is untouched, so the control still reflects.
    return f"<html><body>Results for: {_html_escape(value)}</body></html>"


def _contaminated_control_body(value: str) -> str:
    # The raw <script>…</script> markup is ALREADY on the page independent of any
    # injected markup: even the bare-marker control response carries the exact
    # script_tag payload string, so the reflection anchor is contaminated ->
    # INCONCLUSIVE. Derived from the injected value so it needs no knowledge of
    # the seeded marker.
    return f"<html><body><script>{value}</script></body></html>"


def _guarded_body(value: str) -> str:
    # BEHIND the request-guard: a value carrying an XSS breakout signature is
    # refused before it reaches the sink (403, payload NOT echoed), so no raw
    # markup can reflect; the benign marker control is forwarded and reflected.
    # Uses the REAL enforcer signature test so the offline model stays faithful.
    if _matches_signature(value, "xss"):
        return '{"error":"Forbidden","by":"sentinel-remediation"}'
    return f"<html><body>Results for: {value}</body></html>"

class _CannedXSSExecutor(ExperimentExecutor):
    """Network-free XSS executor: extract the injected value and return a
    modelled response BODY. The judge reads only ``response_body_text`` from the
    single ``mode=="http"`` evidence, so this pins the reflection differential
    without touching a network.
    """

    kind = "xss_check"

    def __init__(self, responder, *, param="q", location="query"):
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
            id=f"ev:xss:{experiment.id}",
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
    """Build a one-check XSS matrix policy."""
    return parse_xss_policy(
        {"xss_matrix": {"checks": [check or dict(_QUERY_CHECK)]}}
    )


def _resolved_graph(responder, *, check=None, param="q", location="query"):
    """Seed one reflected-XSS surface and drive it to a verdict with a model."""
    graph = SecurityGraph()
    results = run_xss_investigation(
        graph,
        _matrix(check),
        target_base=TARGET_BASE,
        executor=_CannedXSSExecutor(responder, param=param, location=location),
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(graph.findings_for(kind="xss", status="OPEN"))
    assert len(findings) == 1
    return findings[0]


# --- parse -----------------------------------------------------------------

def test_parse_xss_matrix_reads_checks():
    policy = _matrix()
    assert len(policy.checks) == 1
    check = policy.checks[0]
    assert check.method == "GET" and check.path == SEARCH_PATH
    assert check.param == "q" and check.location == "query"
    assert check.severity == "HIGH"


def test_parse_no_matrix_yields_empty_policy():
    # A combined document with no xss_matrix section is "not requested".
    assert parse_xss_policy({"access_rules": []}).checks == ()


def test_parse_rejects_bad_location():
    with pytest.raises(ValueError):
        parse_xss_policy(
            {"xss_matrix": {"checks": [
                {"method": "GET", "path": SEARCH_PATH, "param": "q",
                 "location": "header"}
            ]}}
        )


def test_parse_rejects_missing_param():
    with pytest.raises(ValueError):
        parse_xss_policy(
            {"xss_matrix": {"checks": [
                {"method": "GET", "path": SEARCH_PATH}
            ]}}
        )


# --- marker + payload helpers ----------------------------------------------

def test_make_marker_is_benign_alphanumeric():
    marker = make_marker()
    assert marker.startswith("s") and marker.isalnum()
    # No HTML-significant character, so output-encoding leaves it untouched.
    assert not any(c in marker for c in "<>&\"'/= ")


def test_marker_payloads_wrap_the_same_marker_in_active_markup():
    marker = "smarker123456"
    payloads = dict(marker_payloads(marker))
    assert set(payloads) == {
        "script_tag", "svg_onload", "img_onerror", "body_onload"
    }
    for value in payloads.values():
        assert marker in value                  # the marker is inside every payload
        assert "<" in value and ">" in value    # raw active markup

# --- seed + PURE reflection-differential judge -----------------------------

def test_unescaped_reflection_is_validated_and_confirmed():
    graph, results = _resolved_graph(_unescaped_reflecting_body)
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert results[0].param == "q"
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "xss"
    assert finding.severity == "HIGH"


def test_html_escaped_surface_is_disproved_no_finding():
    # The value is HTML-escaped, so the raw <tag> never appears -> every payload
    # collapses -> DISPROVED, nothing manufactured.
    graph, results = _resolved_graph(_escaping_body)
    assert results[0].status == "DISPROVED"
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(graph.findings_for(kind="xss", status="OPEN"))


def test_contaminated_control_is_inconclusive_no_finding():
    # The raw payload markup already appears in the control (only the bare marker
    # was sent), so the reflection anchor is contaminated -> INCONCLUSIVE.
    graph, results = _resolved_graph(_contaminated_control_body)
    assert results[0].status == "INCONCLUSIVE"
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(graph.findings_for(kind="xss", status="OPEN"))


def test_guarded_surface_is_disproved_no_finding():
    # Behind the request-guard the breakout payloads are blocked (403, not
    # echoed) so no raw markup reflects, while the benign marker control is
    # still served -> DISPROVED.
    graph, results = _resolved_graph(_guarded_body)
    assert results[0].status == "DISPROVED"
    assert not list(graph.findings_for(kind="xss", status="OPEN"))


def test_pure_judge_reads_the_reflection_differential_directly():
    # Drive to a confirmed graph, then re-run the PURE judge against the same
    # recorded probes and assert VALIDATED is a deterministic function of them.
    graph, results = _resolved_graph(_unescaped_reflecting_body)
    hyp = graph.hypotheses[results[0].hypothesis_id]
    labels = [label for label, _ in marker_payloads("x")]
    payload_ids = tuple(
        (label, f"exp:xss-payload-{label}:{hyp.id}") for label in labels
    )
    judgment = judge_reflected_xss(
        graph,
        hypothesis=hyp,
        control_experiment_id=f"exp:xss-control:{hyp.id}",
        payload_experiment_ids=payload_ids,
    )
    assert judgment.status == "VALIDATED"
    assert judgment.contradiction_kind == "xss"
    assert judgment.observed is True


# --- guard purity (the virtual-patch decision) -----------------------------

def test_matches_xss_signature_catches_markup_not_benign():
    assert _matches_signature("<script>smarker</script>", "xss")
    assert _matches_signature("<svg onload=smarker>", "xss")
    assert _matches_signature("<img src=x onerror=smarker>", "xss")
    assert _matches_signature("<body onload=smarker>", "xss")
    assert not _matches_signature("smarker123456", "xss")
    assert not _matches_signature("green tea 500ml", "xss")


def test_evaluate_request_guard_denies_markup_forwards_benign():
    rule = RequestGuardRule(
        method="GET", path=SEARCH_PATH, param="q", location="query",
        signature_family="xss",
    )
    # The benign control marker (no markup) is forwarded.
    assert (
        evaluate_request_guard("GET", SEARCH_PATH, "q=green+tea", None, (rule,))
        == "forward"
    )
    # A breakout payload (URL-encoded <script>…</script>) is denied.
    payload = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    assert (
        evaluate_request_guard("GET", SEARCH_PATH, payload, None, (rule,))
        == "deny"
    )
    # A different route is untouched by this guard.
    assert (
        evaluate_request_guard("GET", "/other", payload, None, (rule,))
        == "forward"
    )

# --- synthesize + artifacts -------------------------------------------------

def test_synthesize_xss_remediation_from_confirmed_finding():
    graph, _ = _resolved_graph(_unescaped_reflecting_body)
    plan = synthesize_xss_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.method == "GET" and plan.rule.path == SEARCH_PATH
    assert plan.rule.param == "q" and plan.rule.location == "query"
    assert plan.upstream_base == TARGET_BASE
    assert plan.endpoint_url == TARGET_BASE + SEARCH_PATH


def test_synthesize_ignores_non_xss_finding():
    from dataclasses import replace

    graph, _ = _resolved_graph(_unescaped_reflecting_body)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    assert synthesize_xss_remediation(graph, foreign) is None


def test_render_xss_artifacts_non_empty_and_name_the_param():
    graph, _ = _resolved_graph(_unescaped_reflecting_body)
    plan = synthesize_xss_remediation(graph, _confirmed_finding(graph))
    artifacts = render_xss_artifacts(plan.rule, plan.upstream_base)
    for config in (artifacts.portable_json, artifacts.nginx,
                   artifacts.modsecurity, artifacts.caddy):
        assert config.strip()
        assert "q" in config
    assert plan.upstream_base in artifacts.portable_json


# --- remediate + PROVE (injected executors, no live proxy) -----------------

def test_remediate_xss_and_prove_fix_proven_and_isolated():
    graph, _ = _resolved_graph(_unescaped_reflecting_body)
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id

    outcome = remediate_xss_and_prove(
        graph,
        finding,
        # before: still reflects raw markup -> VALIDATED
        before_executor=_CannedXSSExecutor(_unescaped_reflecting_body),
        # after: request-guard blocks the breakout payloads -> no raw markup -> DISPROVED
        after_executor=_CannedXSSExecutor(_guarded_body),
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_xss_fix_failed_when_guard_does_not_block():
    graph, _ = _resolved_graph(_unescaped_reflecting_body)
    outcome = remediate_xss_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedXSSExecutor(_unescaped_reflecting_body),
        after_executor=_CannedXSSExecutor(_unescaped_reflecting_body),  # still reflects
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_xss_fix_failed_when_xss_did_not_reproduce():
    # The after re-probe is DISPROVED, but the XSS did NOT reproduce on the
    # pre-fix re-probe (before != VALIDATED). A guard cannot take credit for a
    # boundary already holding, so FIX_PROVEN requires the full flip.
    graph, _ = _resolved_graph(_unescaped_reflecting_body)
    outcome = remediate_xss_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedXSSExecutor(_escaping_body),  # no reproduction
        after_executor=_CannedXSSExecutor(_guarded_body),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.before_status == "DISPROVED"
    assert not outcome.verification.proven


def test_remediate_non_xss_finding_is_not_applicable():
    from dataclasses import replace

    graph, _ = _resolved_graph(_unescaped_reflecting_body)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    outcome = remediate_xss_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"

# --- live integration: real reverse proxy blocks payloads, keeps benign -----

class _ReflectingHandler(BaseHTTPRequestHandler):
    """The pre-fix vulnerable target: a genuinely reflected-XSS endpoint that
    echoes the ``q`` parameter verbatim (un-escaped) into the HTML body, so a
    breakout payload's raw markup provably reflects (VALIDATED) before the fix,
    while the benign marker control is merely reflected.
    """

    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        split = urlsplit(self.path)
        params = parse_qs(split.query, keep_blank_values=True)
        value = (params.get("q") or [""])[0]
        body = _unescaped_reflecting_body(value).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def test_live_enforcer_blocks_xss_but_forwards_benign():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectingHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"

        # Seed a fresh graph bound to the live stub and drive it to a confirmed
        # reflected XSS with the REAL HTTP executor, then prove the fix through
        # the REAL reverse proxy with the request-guard active.
        graph = SecurityGraph()
        run_xss_investigation(
            graph,
            _matrix(),
            target_base=upstream_base,
            executor=None,  # real XSSProbeExecutor, scope-bound to the stub
        )
        finding = _confirmed_finding(graph)

        outcome = remediate_xss_and_prove(graph, finding, use_enforcer=True)

        assert outcome.result == "FIX_PROVEN"
        assert outcome.verification.before_status == "VALIDATED"
        assert outcome.verification.after_status == "DISPROVED"
    finally:
        upstream.shutdown()
        upstream.server_close()


def test_live_enforcer_returns_403_for_payload_200_for_benign():
    # Directly observe the raw shield behaviour the DISPROVED verdict rests on:
    # a breakout payload is refused (403) before it reaches the reflecting
    # upstream, while the benign control marker is forwarded (200).
    import urllib.error
    import urllib.request
    from urllib.parse import urlencode

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectingHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"
        guard = RequestGuardRule(
            method="GET", path=SEARCH_PATH, param="q", location="query",
            signature_family="xss",
        )
        with RemediationEnforcer((), upstream_base, guard_rules=(guard,)) as shield:
            benign = urllib.request.urlopen(
                f"{shield.base_url}{SEARCH_PATH}?{urlencode({'q': 'green tea'})}",
                timeout=10,
            )
            assert benign.status == 200

            payload = urlencode({"q": "<script>alert(1)</script>"})
            try:
                urllib.request.urlopen(
                    f"{shield.base_url}{SEARCH_PATH}?{payload}", timeout=10
                )
                assert False, "the request-guard should have refused the payload"
            except urllib.error.HTTPError as exc:
                assert exc.code == 403
    finally:
        upstream.shutdown()
        upstream.server_close()






