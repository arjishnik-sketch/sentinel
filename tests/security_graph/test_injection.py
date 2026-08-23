"""
Offline, network-free proof of the SQL-injection (boolean-differential) class
and its PATCH + PROVE remediation. No real target is contacted for the unit
tests: a canned executor extracts the value injected into the declared
parameter and returns a ``(status_code, response_body_length)`` fingerprint that
models a real backend's behaviour, so the three-way boolean differential is
pinned deterministically:

  * a declared injectable surface becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when a length-matched (TRUE, FALSE)
    pair makes the response track the injected boolean (TRUE != FALSE) AND one
    arm reproduces the legitimate baseline exactly (the difference is real
    query-result variation, not a reflected payload — the pair is equal length);
    DISPROVED when every readable pair collapses (TRUE == FALSE), which is also
    the post-fix state once the request-guard blocks the payloads; and
    INCONCLUSIVE when the declared benign baseline is not a legitimate response
    (no anchor) — in every non-VALIDATED case NO finding is manufactured;
  * a corrective request-guard is derived only from a confirmed injection, and
    the same judge — re-run through the enforcement shield — proves the fix ONLY
    when it flips VALIDATED -> DISPROVED (the injection reproduced pre-fix and
    stops reproducing under the guard because TRUE and FALSE both become 403);
  * verification NEVER mutates the confirmed hypothesis or finding.

One localhost integration test stands the real reverse proxy in front of a stub
upstream that is genuinely injectable (a boolean payload toggles the response),
and proves the request-guard blocks the boolean payloads (403 -> TRUE and FALSE
collapse) while still forwarding the benign baseline (200) — the honest fix.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.injection import (
    boolean_payload_pairs,
    judge_injection,
    parse_injection_policy,
    remediate_injection_and_prove,
    render_injection_artifacts,
    run_injection_investigation,
    synthesize_injection_remediation,
)
from app.security_graph.remediation.enforcer import (
    RemediationEnforcer,
    RequestGuardRule,
    _matches_sqli_signature,
    evaluate_request_guard,
)


TARGET_BASE = "http://127.0.0.1:3000"
SEARCH_PATH = "/rest/products/search"
BASELINE_VALUE = "apple"

# Response-body sizes standing in for query-result set sizes. The judge reads
# only the (status, length) fingerprint, so these model "how many rows the
# injected query returned" without any real database.
_BASE_BODY = 512   # rows matching the benign term "apple"
_ALL_BODY = 4096   # every row (an OR-tautology dumps the whole table)
_ZERO_BODY = 64    # no rows (an AND-contradiction empties the result set)
_ERR_BODY = 96     # the shield's fixed 403 guard-denial body

_QUERY_CHECK = {
    "method": "GET",
    "path": SEARCH_PATH,
    "param": "q",
    "baseline_value": BASELINE_VALUE,
    "location": "query",
    "severity": "HIGH",
}


# --- deterministic backend response models ---------------------------------

def _injectable_body(value: str) -> tuple[int, int]:
    """Model a VULNERABLE string-context search: the value is concatenated into

        SELECT id FROM products WHERE name LIKE '%<value>%'

    A boolean payload therefore alters the result set. The benign value returns
    the term's rows (the anchor); an OR-tautology returns every row; an
    OR-contradiction returns just the term's rows (== baseline); an AND-tautology
    keeps the term's rows; an AND-contradiction empties the set. Body length
    stands in for the row count, so a length-matched TRUE/FALSE pair produces a
    real, reflected-payload-independent differential.
    """
    quote = "'" if "'" in value else ('"' if '"' in value else None)
    if quote is None:
        return 200, _BASE_BODY  # a benign literal search (the baseline)
    tail = value.split(quote, 1)[1].lower()
    truthy = ("1'='1" in tail) or ("1=1" in tail) or ('1"="1' in tail)
    falsy = ("1'='2" in tail) or ("1=2" in tail) or ('1"="2' in tail)
    has_or = " or " in f" {tail} "
    has_and = " and " in f" {tail} "
    if has_or and truthy:
        return 200, _ALL_BODY
    if has_or and falsy:
        return 200, _BASE_BODY
    if has_and and truthy:
        return 200, _BASE_BODY
    if has_and and falsy:
        return 200, _ZERO_BODY
    return 200, _BASE_BODY


def _safe_body(value: str) -> tuple[int, int]:
    """Model a PARAMETERISED (prepared-statement) endpoint: the value is bound as

    a literal and never evaluated as SQL. The response merely reflects the
    searched term, so length-matched TRUE/FALSE payloads yield identical
    responses and every pair collapses -> DISPROVED (no injection).
    """
    return 200, _BASE_BODY + len(value)


def _guarded_body(value: str) -> tuple[int, int]:
    """Model the endpoint BEHIND the request-guard: a value carrying a SQLi

    signature is refused (403) before it reaches the backend, while the benign
    baseline is forwarded (200). TRUE and FALSE both become 403 -> they collapse.
    Uses the real enforcer signature test so the offline model stays faithful.
    """
    if _matches_sqli_signature(value):
        return 403, _ERR_BODY
    return 200, _BASE_BODY


def _broken_baseline_body(value: str) -> tuple[int, int]:
    """The declared benign value does NOT return a legitimate response (500), so

    the differential has no anchor -> the judge must return INCONCLUSIVE.
    """
    return 500, _BASE_BODY


class _CannedInjectionExecutor(ExperimentExecutor):
    """A network-free injection executor: extract the injected value and return

    a modelled ``(status_code, response_body_length)`` fingerprint. The judge
    reads exactly those two facts from the single ``mode=="http"`` evidence, so
    this pins the boolean differential without touching a network.
    """

    kind = "injection_check"

    def __init__(self, responder, *, param="q", location="query"):
        self._responder = responder
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

    def execute(self, experiment):
        value = self._injected_value(experiment)
        status, length = self._responder(value)
        evidence = Evidence(
            id=f"ev:injection:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": status,
                "response_body_length": length,
                "url": experiment.request.url if experiment.request else "",
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", str(status)),),
        )


def _matrix(check=None):
    """Build a one-check injection matrix policy."""
    return parse_injection_policy(
        {"injection_matrix": {"checks": [check or dict(_QUERY_CHECK)]}}
    )


def _resolved_graph(responder, *, check=None, param="q", location="query"):
    """Seed one injectable surface and drive it to a verdict with a canned model."""
    graph = SecurityGraph()
    results = run_injection_investigation(
        graph,
        _matrix(check),
        target_base=TARGET_BASE,
        executor=_CannedInjectionExecutor(responder, param=param, location=location),
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(graph.findings_for(kind="injection", status="OPEN"))
    assert len(findings) == 1
    return findings[0]


# --- parse -----------------------------------------------------------------

def test_parse_injection_matrix_reads_checks():
    policy = _matrix()
    assert len(policy.checks) == 1
    check = policy.checks[0]
    assert check.method == "GET" and check.path == SEARCH_PATH
    assert check.param == "q" and check.location == "query"
    assert check.baseline_value == BASELINE_VALUE and check.severity == "HIGH"


def test_parse_no_matrix_yields_empty_policy():
    # A combined document with no injection_matrix section is "not requested".
    assert parse_injection_policy({"access_rules": []}).checks == ()


def test_parse_rejects_missing_baseline_value():
    with pytest.raises(ValueError):
        parse_injection_policy(
            {"injection_matrix": {"checks": [
                {"method": "GET", "path": SEARCH_PATH, "param": "q"}
            ]}}
        )


def test_parse_rejects_bad_location_and_missing_param():
    with pytest.raises(ValueError):
        parse_injection_policy(
            {"injection_matrix": {"checks": [
                {"method": "GET", "path": SEARCH_PATH, "param": "q",
                 "baseline_value": "apple", "location": "header"}
            ]}}
        )
    with pytest.raises(ValueError):
        parse_injection_policy(
            {"injection_matrix": {"checks": [
                {"method": "GET", "path": SEARCH_PATH, "baseline_value": "apple"}
            ]}}
        )


# --- seed + PURE three-way boolean-differential judge ----------------------

def test_injectable_surface_is_validated_and_confirmed():
    graph, results = _resolved_graph(_injectable_body)
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert results[0].param == "q"
    assert results[0].baseline_status_code == 200
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "injection"
    assert finding.severity == "HIGH"


def test_parameterised_surface_is_disproved_no_finding():
    # Every length-matched pair collapses -> no boolean toggled the query.
    graph, results = _resolved_graph(_safe_body)
    assert results[0].status == "DISPROVED"
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(graph.findings_for(kind="injection", status="OPEN"))


def test_broken_baseline_is_inconclusive_no_finding():
    # The declared benign value did not return a legitimate response, so the
    # differential has no anchor -> INCONCLUSIVE, nothing manufactured.
    graph, results = _resolved_graph(_broken_baseline_body)
    assert results[0].status == "INCONCLUSIVE"
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(graph.findings_for(kind="injection", status="OPEN"))


def test_guarded_surface_is_disproved_no_finding():
    # Behind the request-guard the boolean payloads are blocked (403) so TRUE
    # and FALSE collapse while the benign baseline is still served -> DISPROVED.
    graph, results = _resolved_graph(_guarded_body)
    assert results[0].status == "DISPROVED"
    assert not list(graph.findings_for(kind="injection", status="OPEN"))


def test_pure_judge_reads_the_boolean_differential_directly():
    # Drive to a confirmed graph, then re-run the PURE judge against the same
    # recorded probes and assert VALIDATED is a deterministic function of them.
    graph, results = _resolved_graph(_injectable_body)
    hyp = graph.hypotheses[results[0].hypothesis_id]
    pairs, _ = boolean_payload_pairs(BASELINE_VALUE)
    pair_ids = tuple(
        (f"exp:injection-true-{i}:{hyp.id}", f"exp:injection-false-{i}:{hyp.id}")
        for i in range(len(pairs))
    )
    judgment = judge_injection(
        graph,
        hypothesis=hyp,
        baseline_experiment_id=f"exp:injection-baseline:{hyp.id}",
        pair_experiment_ids=pair_ids,
    )
    assert judgment.status == "VALIDATED"
    assert judgment.contradiction_kind == "injection"
    assert judgment.observed is True


# --- guard purity (the virtual-patch decision) -----------------------------

def test_matches_sqli_signature_catches_payloads_not_benign():
    assert _matches_sqli_signature("apple' OR '1'='1")
    assert _matches_sqli_signature("apple' OR '1'='2")
    assert _matches_sqli_signature("1 UNION SELECT password FROM users")
    assert not _matches_sqli_signature("apple")
    assert not _matches_sqli_signature("green tea 500ml")


def test_evaluate_request_guard_denies_payload_forwards_benign():
    rule = RequestGuardRule(method="GET", path=SEARCH_PATH, param="q", location="query")
    assert evaluate_request_guard("GET", SEARCH_PATH, "q=apple", None, (rule,)) == "forward"
    assert (
        evaluate_request_guard("GET", SEARCH_PATH, "q=apple'+OR+'1'%3D'1", None, (rule,))
        == "deny"
    )
    # A different route is untouched by this guard.
    assert evaluate_request_guard("GET", "/other", "q=apple'+OR+'1'%3D'1", None, (rule,)) == "forward"


# --- synthesize + artifacts -------------------------------------------------

def test_synthesize_injection_remediation_from_confirmed_finding():
    graph, _ = _resolved_graph(_injectable_body)
    plan = synthesize_injection_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.method == "GET" and plan.rule.path == SEARCH_PATH
    assert plan.rule.param == "q" and plan.rule.location == "query"
    assert plan.upstream_base == TARGET_BASE
    assert plan.endpoint_url == TARGET_BASE + SEARCH_PATH
    assert plan.baseline_value == BASELINE_VALUE


def test_synthesize_ignores_non_injection_finding():
    from dataclasses import replace

    graph, _ = _resolved_graph(_injectable_body)
    foreign = replace(_confirmed_finding(graph), kind="authorization_policy_violation")
    assert synthesize_injection_remediation(graph, foreign) is None


def test_render_injection_artifacts_non_empty_and_name_the_param():
    graph, _ = _resolved_graph(_injectable_body)
    plan = synthesize_injection_remediation(graph, _confirmed_finding(graph))
    artifacts = render_injection_artifacts(plan.rule, plan.upstream_base)
    for config in (artifacts.portable_json, artifacts.nginx,
                   artifacts.modsecurity, artifacts.caddy):
        assert config.strip()
        assert "q" in config
    assert plan.upstream_base in artifacts.portable_json


# --- remediate + PROVE (injected executors, no live proxy) -----------------

def test_remediate_injection_and_prove_fix_proven_and_isolated():
    graph, _ = _resolved_graph(_injectable_body)
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id

    outcome = remediate_injection_and_prove(
        graph,
        finding,
        # before: still injectable -> VALIDATED
        before_executor=_CannedInjectionExecutor(_injectable_body),
        # after: request-guard blocks the payloads (403) -> collapse -> DISPROVED
        after_executor=_CannedInjectionExecutor(_guarded_body),
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_injection_fix_failed_when_guard_does_not_block():
    graph, _ = _resolved_graph(_injectable_body)
    outcome = remediate_injection_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedInjectionExecutor(_injectable_body),
        after_executor=_CannedInjectionExecutor(_injectable_body),  # still injectable
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_injection_fix_failed_when_injection_did_not_reproduce():
    # The after re-probe is DISPROVED, but the injection did NOT reproduce on the
    # pre-fix re-probe (before != VALIDATED). A guard cannot take credit for a
    # boundary already holding, so FIX_PROVEN requires the full flip.
    graph, _ = _resolved_graph(_injectable_body)
    outcome = remediate_injection_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedInjectionExecutor(_safe_body),   # no reproduction
        after_executor=_CannedInjectionExecutor(_guarded_body),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.before_status == "DISPROVED"
    assert not outcome.verification.proven


def test_remediate_non_injection_finding_is_not_applicable():
    from dataclasses import replace

    graph, _ = _resolved_graph(_injectable_body)
    foreign = replace(_confirmed_finding(graph), kind="authorization_policy_violation")
    outcome = remediate_injection_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"


# --- live integration: real reverse proxy blocks the payloads, keeps benign --

class _InjectableSearchHandler(BaseHTTPRequestHandler):
    """The pre-fix vulnerable target: a genuinely injectable string-context

    search. It reads ``q`` and returns a body whose LENGTH encodes the row count
    the injected query selects, so a boolean payload provably toggles the
    response (VALIDATED) before the fix, while the benign value returns its
    stable baseline row set.
    """

    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        split = urlsplit(self.path)
        params = parse_qs(split.query, keep_blank_values=True)
        value = (params.get("q") or [""])[0]
        status, length = _injectable_body(value)
        body = b"x" * length
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def test_live_enforcer_blocks_injection_but_forwards_benign():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _InjectableSearchHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"

        # Seed a fresh graph bound to the live stub and drive it to a confirmed
        # injection with the REAL HTTP executor, then prove the fix through the
        # REAL reverse proxy with the request-guard active.
        graph = SecurityGraph()
        run_injection_investigation(
            graph,
            _matrix(),
            target_base=upstream_base,
            executor=None,  # real InjectionProbeExecutor, scope-bound to the stub
        )
        finding = _confirmed_finding(graph)

        outcome = remediate_injection_and_prove(graph, finding, use_enforcer=True)

        assert outcome.result == "FIX_PROVEN"
        assert outcome.verification.before_status == "VALIDATED"
        assert outcome.verification.after_status == "DISPROVED"
        # The benign baseline is still forwarded through the shield (not
        # over-blocked); the payloads collapsing to 403 is what earns DISPROVED.
        assert outcome.verification.observed_status_code == 200
        assert outcome.verification.before_status_code == 200
    finally:
        upstream.shutdown()
        upstream.server_close()


def test_live_enforcer_returns_403_for_payload_200_for_benign():
    # Directly observe the raw shield behaviour the DISPROVED verdict rests on:
    # a boolean payload is refused (403) before it reaches the injectable
    # upstream, while the benign baseline is forwarded and served (200).
    import urllib.request
    from urllib.parse import urlencode

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _InjectableSearchHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"
        guard = RequestGuardRule(
            method="GET", path=SEARCH_PATH, param="q", location="query"
        )
        with RemediationEnforcer((), upstream_base, guard_rules=(guard,)) as shield:
            benign = urllib.request.urlopen(
                f"{shield.base_url}{SEARCH_PATH}?{urlencode({'q': BASELINE_VALUE})}",
                timeout=10,
            )
            assert benign.status == 200

            payload = urlencode({"q": f"{BASELINE_VALUE}' OR '1'='1"})
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
