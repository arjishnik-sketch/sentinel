"""
Offline, network-free proof of the SSTI (arithmetic-evaluation differential)
class and its PATCH + PROVE remediation. No real target is contacted for the
unit tests: a canned executor extracts the value injected into the declared
parameter and returns a modelled response BODY that a deterministic
template-engine model produces, so the differential is pinned exactly:

  * a declared SSTI surface becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when a template payload makes the
    body contain the *computed product* while the literal expression vanishes
    AND the control proved the app merely reflects the literal (product absent)
    — the product can only have come from the backend evaluating the template;
    DISPROVED when every readable payload is reflected verbatim (the literal
    survives, no product), which is also the post-fix state once the
    request-guard blocks the delimiters; and INCONCLUSIVE when the control's
    arithmetic anchor is contaminated (the product already appears with no
    delimiters) — in every non-VALIDATED case NO finding is manufactured;
  * a corrective request-guard (signature family ``ssti``) is derived only from
    a confirmed SSTI, and the same judge — re-run through the enforcement shield
    — proves the fix ONLY when it flips VALIDATED -> DISPROVED (the payloads
    become 403 so the product never renders while the benign control literal is
    still forwarded);
  * verification NEVER mutates the confirmed hypothesis or finding.

One localhost integration test stands the real reverse proxy in front of a stub
upstream that genuinely evaluates the template (a payload's arithmetic is
computed), and proves the request-guard blocks the delimiter payloads (403) so
the product never renders, while still forwarding the benign control literal.
"""

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.ssti import (
    judge_template_injection,
    parse_ssti_policy,
    remediate_ssti_and_prove,
    render_ssti_artifacts,
    run_ssti_investigation,
    synthesize_ssti_remediation,
    template_payloads,
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


# --- a deterministic template-engine model (no network, no real engine) -----

# Evaluate  a*b  wrapped in any of the common server-side template delimiters.
_DELIM_EXPR = re.compile(
    r"(?:\{\{|\$\{|#\{|<%=?)\s*(\d+)\s*\*\s*(\d+)\s*(?:\}\}|\}|%>)"
)


def _render(value: str) -> str:
    """A VULNERABLE template engine: evaluate ``a*b`` inside a template
    delimiter, and leave everything else — notably the delimiter-free control
    literal — reflected verbatim.
    """
    return _DELIM_EXPR.sub(
        lambda m: str(int(m.group(1)) * int(m.group(2))), value
    )


def _vulnerable_body(value: str) -> str:
    # The engine renders the value: a template payload's a*b is computed, so the
    # product appears and the literal expression is gone; the control literal is
    # merely reflected verbatim (product absent).
    return f"<html><body>Results for: {_render(value)}</body></html>"


def _reflecting_body(value: str) -> str:
    # A SAFE endpoint: the value is reflected verbatim, never evaluated. A
    # template payload survives inside its delimiters (literal present, product
    # absent), so every payload collapses -> DISPROVED.
    return f"<html><body>Results for: {value}</body></html>"


def _contaminated_control_body(value: str) -> str:
    # The computed product ALSO appears with no template delimiters (the control
    # literal), so the arithmetic anchor is contaminated -> INCONCLUSIVE. Derived
    # from the injected value so it needs no knowledge of the seeded operands.
    match = re.search(r"(\d+)\s*\*\s*(\d+)", value)
    leaked = str(int(match.group(1)) * int(match.group(2))) if match else ""
    return f"<html><body>{_render(value)} :: cached total {leaked}</body></html>"


def _guarded_body(value: str) -> str:
    # BEHIND the request-guard: a value carrying a template delimiter is refused
    # before it reaches the engine, so no payload can render the product; the
    # benign control literal is forwarded and reflected. Uses the real enforcer
    # signature test so the offline model stays faithful.
    if _matches_signature(value, "ssti"):
        return "<html><body>403 forbidden</body></html>"
    return f"<html><body>Results for: {_render(value)}</body></html>"


class _CannedSSTIExecutor(ExperimentExecutor):
    """Network-free SSTI executor: extract the injected value and return a
    modelled response BODY. The judge reads only ``response_body_text`` from the
    single ``mode=="http"`` evidence, so this pins the arithmetic differential
    without touching a network.
    """

    kind = "template_injection_check"

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
            id=f"ev:ssti:{experiment.id}",
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
    """Build a one-check SSTI matrix policy."""
    return parse_ssti_policy(
        {"ssti_matrix": {"checks": [check or dict(_QUERY_CHECK)]}}
    )


def _resolved_graph(responder, *, check=None, param="q", location="query"):
    """Seed one SSTI surface and drive it to a verdict with a canned model."""
    graph = SecurityGraph()
    results = run_ssti_investigation(
        graph,
        _matrix(check),
        target_base=TARGET_BASE,
        executor=_CannedSSTIExecutor(responder, param=param, location=location),
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(graph.findings_for(kind="template_injection", status="OPEN"))
    assert len(findings) == 1
    return findings[0]


# --- parse -----------------------------------------------------------------

def test_parse_ssti_matrix_reads_checks():
    policy = _matrix()
    assert len(policy.checks) == 1
    check = policy.checks[0]
    assert check.method == "GET" and check.path == SEARCH_PATH
    assert check.param == "q" and check.location == "query"
    assert check.severity == "HIGH"


def test_parse_no_matrix_yields_empty_policy():
    # A combined document with no ssti_matrix section is "not requested".
    assert parse_ssti_policy({"access_rules": []}).checks == ()


def test_parse_rejects_bad_location():
    with pytest.raises(ValueError):
        parse_ssti_policy(
            {"ssti_matrix": {"checks": [
                {"method": "GET", "path": SEARCH_PATH, "param": "q",
                 "location": "header"}
            ]}}
        )


def test_parse_rejects_missing_param():
    with pytest.raises(ValueError):
        parse_ssti_policy(
            {"ssti_matrix": {"checks": [
                {"method": "GET", "path": SEARCH_PATH}
            ]}}
        )


# --- seed + PURE arithmetic-evaluation-differential judge ------------------

def test_evaluated_surface_is_validated_and_confirmed():
    graph, results = _resolved_graph(_vulnerable_body)
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert results[0].param == "q"
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "template_injection"
    assert finding.severity == "HIGH"


def test_reflected_surface_is_disproved_no_finding():
    # The value is reflected verbatim, never evaluated -> every payload keeps
    # the literal, none yields the product -> DISPROVED, nothing manufactured.
    graph, results = _resolved_graph(_reflecting_body)
    assert results[0].status == "DISPROVED"
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(graph.findings_for(kind="template_injection", status="OPEN"))


def test_contaminated_control_is_inconclusive_no_finding():
    # The product already appears in the control (no delimiters), so the
    # arithmetic anchor is contaminated -> INCONCLUSIVE, nothing manufactured.
    graph, results = _resolved_graph(_contaminated_control_body)
    assert results[0].status == "INCONCLUSIVE"
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(graph.findings_for(kind="template_injection", status="OPEN"))


def test_guarded_surface_is_disproved_no_finding():
    # Behind the request-guard the delimiter payloads are blocked so the product
    # never renders, while the benign control literal is still served -> DISPROVED.
    graph, results = _resolved_graph(_guarded_body)
    assert results[0].status == "DISPROVED"
    assert not list(graph.findings_for(kind="template_injection", status="OPEN"))


def test_pure_judge_reads_the_arithmetic_differential_directly():
    # Drive to a confirmed graph, then re-run the PURE judge against the same
    # recorded probes and assert VALIDATED is a deterministic function of them.
    graph, results = _resolved_graph(_vulnerable_body)
    hyp = graph.hypotheses[results[0].hypothesis_id]
    labels = [label for label, _ in template_payloads("1*1")]
    payload_ids = tuple(
        (label, f"exp:ssti-payload-{label}:{hyp.id}") for label in labels
    )
    judgment = judge_template_injection(
        graph,
        hypothesis=hyp,
        control_experiment_id=f"exp:ssti-control:{hyp.id}",
        payload_experiment_ids=payload_ids,
    )
    assert judgment.status == "VALIDATED"
    assert judgment.contradiction_kind == "template_injection"
    assert judgment.observed is True


# --- guard purity (the virtual-patch decision) -----------------------------

def test_matches_ssti_signature_catches_delimiters_not_benign():
    assert _matches_signature("{{1009*9973}}", "ssti")
    assert _matches_signature("${1009*9973}", "ssti")
    assert _matches_signature("#{1009*9973}", "ssti")
    assert _matches_signature("<%= 1009*9973 %>", "ssti")
    assert not _matches_signature("1009*9973", "ssti")
    assert not _matches_signature("green tea 500ml", "ssti")


def test_evaluate_request_guard_denies_delimiter_forwards_benign():
    rule = RequestGuardRule(
        method="GET", path=SEARCH_PATH, param="q", location="query",
        signature_family="ssti",
    )
    # The benign control literal (no delimiters) is forwarded.
    assert (
        evaluate_request_guard("GET", SEARCH_PATH, "q=1009*9973", None, (rule,))
        == "forward"
    )
    # A template-delimiter payload (URL-encoded {{...}}) is denied.
    assert (
        evaluate_request_guard(
            "GET", SEARCH_PATH, "q=%7B%7B1009*9973%7D%7D", None, (rule,)
        )
        == "deny"
    )
    # A different route is untouched by this guard.
    assert (
        evaluate_request_guard(
            "GET", "/other", "q=%7B%7B1009*9973%7D%7D", None, (rule,)
        )
        == "forward"
    )


# --- synthesize + artifacts -------------------------------------------------

def test_synthesize_ssti_remediation_from_confirmed_finding():
    graph, _ = _resolved_graph(_vulnerable_body)
    plan = synthesize_ssti_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.method == "GET" and plan.rule.path == SEARCH_PATH
    assert plan.rule.param == "q" and plan.rule.location == "query"
    assert plan.upstream_base == TARGET_BASE
    assert plan.endpoint_url == TARGET_BASE + SEARCH_PATH


def test_synthesize_ignores_non_ssti_finding():
    from dataclasses import replace

    graph, _ = _resolved_graph(_vulnerable_body)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    assert synthesize_ssti_remediation(graph, foreign) is None


def test_render_ssti_artifacts_non_empty_and_name_the_param():
    graph, _ = _resolved_graph(_vulnerable_body)
    plan = synthesize_ssti_remediation(graph, _confirmed_finding(graph))
    artifacts = render_ssti_artifacts(plan.rule, plan.upstream_base)
    for config in (artifacts.portable_json, artifacts.nginx,
                   artifacts.modsecurity, artifacts.caddy):
        assert config.strip()
        assert "q" in config
    assert plan.upstream_base in artifacts.portable_json


# --- remediate + PROVE (injected executors, no live proxy) -----------------

def test_remediate_ssti_and_prove_fix_proven_and_isolated():
    graph, _ = _resolved_graph(_vulnerable_body)
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id

    outcome = remediate_ssti_and_prove(
        graph,
        finding,
        # before: still evaluates the template -> VALIDATED
        before_executor=_CannedSSTIExecutor(_vulnerable_body),
        # after: request-guard blocks the delimiters -> product never renders -> DISPROVED
        after_executor=_CannedSSTIExecutor(_guarded_body),
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_ssti_fix_failed_when_guard_does_not_block():
    graph, _ = _resolved_graph(_vulnerable_body)
    outcome = remediate_ssti_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedSSTIExecutor(_vulnerable_body),
        after_executor=_CannedSSTIExecutor(_vulnerable_body),  # still evaluates
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_ssti_fix_failed_when_ssti_did_not_reproduce():
    # The after re-probe is DISPROVED, but the SSTI did NOT reproduce on the
    # pre-fix re-probe (before != VALIDATED). A guard cannot take credit for a
    # boundary already holding, so FIX_PROVEN requires the full flip.
    graph, _ = _resolved_graph(_vulnerable_body)
    outcome = remediate_ssti_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedSSTIExecutor(_reflecting_body),  # no reproduction
        after_executor=_CannedSSTIExecutor(_guarded_body),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.before_status == "DISPROVED"
    assert not outcome.verification.proven


def test_remediate_non_ssti_finding_is_not_applicable():
    from dataclasses import replace

    graph, _ = _resolved_graph(_vulnerable_body)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    outcome = remediate_ssti_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"


# --- live integration: real reverse proxy blocks payloads, keeps benign -----

class _EvaluatingTemplateHandler(BaseHTTPRequestHandler):
    """The pre-fix vulnerable target: a genuinely SSTI-vulnerable endpoint that
    evaluates ``a*b`` inside a template delimiter, so a template payload provably
    renders the computed product (VALIDATED) before the fix, while the benign
    control literal is merely reflected.
    """

    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        split = urlsplit(self.path)
        params = parse_qs(split.query, keep_blank_values=True)
        value = (params.get("q") or [""])[0]
        body = _vulnerable_body(value).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def test_live_enforcer_blocks_ssti_but_forwards_benign():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _EvaluatingTemplateHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"

        # Seed a fresh graph bound to the live stub and drive it to a confirmed
        # SSTI with the REAL HTTP executor, then prove the fix through the REAL
        # reverse proxy with the request-guard active.
        graph = SecurityGraph()
        run_ssti_investigation(
            graph,
            _matrix(),
            target_base=upstream_base,
            executor=None,  # real SSTIProbeExecutor, scope-bound to the stub
        )
        finding = _confirmed_finding(graph)

        outcome = remediate_ssti_and_prove(graph, finding, use_enforcer=True)

        assert outcome.result == "FIX_PROVEN"
        assert outcome.verification.before_status == "VALIDATED"
        assert outcome.verification.after_status == "DISPROVED"
    finally:
        upstream.shutdown()
        upstream.server_close()


def test_live_enforcer_returns_403_for_payload_200_for_benign():
    # Directly observe the raw shield behaviour the DISPROVED verdict rests on:
    # a template-delimiter payload is refused (403) before it reaches the
    # evaluating upstream, while the benign control literal is forwarded (200).
    import urllib.request
    from urllib.parse import urlencode

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _EvaluatingTemplateHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"
        guard = RequestGuardRule(
            method="GET", path=SEARCH_PATH, param="q", location="query",
            signature_family="ssti",
        )
        with RemediationEnforcer((), upstream_base, guard_rules=(guard,)) as shield:
            benign = urllib.request.urlopen(
                f"{shield.base_url}{SEARCH_PATH}?{urlencode({'q': '1009*9973'})}",
                timeout=10,
            )
            assert benign.status == 200

            payload = urlencode({"q": "{{1009*9973}}"})
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
