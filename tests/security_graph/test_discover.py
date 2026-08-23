"""
Offline, network-free proof of ZERO-ORACLE injection DISCOVERY.

This is the honesty proof for the "point Sentinel at a URL and it finds the bugs"
capability. It exercises
:func:`app.security_graph.injection.discover.synthesize_injection_policy` — the
pure function that derives an injectable surface from live reconnaissance instead
of an operator-declared matrix — and then drives the SYNTHESIZED policy through
the exact same seed -> probe -> judge chain the operator matrix uses, with a
canned backend, to prove:

  * synthesis draws real candidates from observed ``recon_parameter`` values
    (anchored to the value the app actually served) and from a fixed, target-
    agnostic generic-parameter list on query-surface endpoints;
  * synthesis is deterministic, deduped, capped, and skips static assets and
    non-GET endpoints; an empty graph yields an empty policy (nothing invented);
  * the SAME pure boolean-differential judge still gates every synthesized
    candidate — an injectable parameter is CONFIRMED, a parameterised one is
    DISPROVED with NO finding. Discovery changes only *where to look*, never how
    a verdict is reached.
"""

from urllib.parse import parse_qsl, urlsplit

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Endpoint, Evidence, ExecutionResult, Observation
from app.security_graph.injection import run_injection_investigation
from app.security_graph.injection.discover import synthesize_injection_policy


TARGET_BASE = "http://127.0.0.1:3000"
SEARCH_PATH = "/rest/products/search"

_BASE_BODY = 512
_ALL_BODY = 4096
_ZERO_BODY = 64


# --- graph fixtures ---------------------------------------------------------

def _obs_param(graph, n, parameter, url):
    graph.add_observation(
        Observation(
            id=f"recon:parameter:{n}",
            kind="recon_parameter",
            subject=f"endpoint:{url}",
            data={"parameter": parameter, "url": url, "target": TARGET_BASE},
        )
    )


def _endpoint(graph, method, url):
    graph.add_endpoint(Endpoint(id=f"endpoint:{url}", method=method, url=url))


# --- backend response models (reused shape from test_injection) -------------

def _injectable_body(value):
    quote = "'" if "'" in value else ('"' if '"' in value else None)
    if quote is None:
        return 200, _BASE_BODY
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


def _safe_body(value):
    return 200, _BASE_BODY + len(value)


class _CannedInjectionExecutor(ExperimentExecutor):
    """Extract the injected query value and return a modelled fingerprint.

    ``responder`` maps the injected value of the target parameter to a
    ``(status, length)`` pair; every other parameter is treated as inert (benign
    baseline), so a generic-parameter sweep only 'confirms' the one parameter the
    modelled backend actually evaluates.
    """

    kind = "injection_check"

    def __init__(self, responder, *, param):
        self._responder = responder
        self._param = param

    def execute(self, experiment):
        req = experiment.request
        url = req.url if req else ""
        parsed = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        value = parsed.get(self._param, "")
        # Only the modelled parameter is injectable; anything else is inert.
        status, length = (
            self._responder(value) if self._param in parsed else (200, _BASE_BODY)
        )
        evidence = Evidence(
            id=f"ev:injection:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": status,
                "response_body_length": length,
                "url": url,
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", str(status)),),
        )


# __APPEND_MARKER__

# --- pure synthesis ---------------------------------------------------------

def test_empty_graph_synthesizes_no_checks():
    discovery = synthesize_injection_policy(SecurityGraph())
    assert discovery.policy.checks == ()
    assert discovery.observed_count == 0 and discovery.generic_count == 0
    assert discovery.total_candidates == 0


def test_observed_parameter_becomes_a_candidate_anchored_to_its_value():
    graph = SecurityGraph()
    _obs_param(graph, 1, "q", f"{TARGET_BASE}{SEARCH_PATH}?q=apple")
    discovery = synthesize_injection_policy(graph, include_generic=False)

    assert len(discovery.policy.checks) == 1
    check = discovery.policy.checks[0]
    assert check.method == "GET" and check.path == SEARCH_PATH
    assert check.param == "q" and check.location == "query"
    # The baseline is the value the app actually served, never invented.
    assert check.baseline_value == "apple"
    assert discovery.observed_count == 1 and discovery.generic_count == 0


def test_observed_parameter_without_value_falls_back_to_benign_token():
    graph = SecurityGraph()
    _obs_param(graph, 1, "search", f"{TARGET_BASE}/items?search=")
    discovery = synthesize_injection_policy(graph, include_generic=False)
    assert discovery.policy.checks[0].baseline_value == "sentinel"


def test_generic_params_attach_to_query_surface_endpoints():
    graph = SecurityGraph()
    _endpoint(graph, "GET", f"{TARGET_BASE}/rest/products")  # query surface
    discovery = synthesize_injection_policy(graph, max_checks=99)

    params = {c.param for c in discovery.policy.checks}
    # Every generic parameter is attached to the query-surface endpoint.
    assert "q" in params and "search" in params and "id" in params
    assert all(c.path == "/rest/products" for c in discovery.policy.checks)
    assert discovery.generic_count == len(discovery.policy.checks)


def test_static_assets_and_non_get_endpoints_are_skipped():
    graph = SecurityGraph()
    _endpoint(graph, "GET", f"{TARGET_BASE}/static/app.js")     # asset
    _endpoint(graph, "GET", f"{TARGET_BASE}/main.css")          # asset
    _endpoint(graph, "POST", f"{TARGET_BASE}/rest/products")    # non-GET
    discovery = synthesize_injection_policy(graph, max_checks=99)
    assert discovery.policy.checks == ()


def test_observed_dedupes_with_generic_and_takes_priority():
    graph = SecurityGraph()
    # 'q' is observed on the search endpoint with a real anchor value...
    _obs_param(graph, 1, "q", f"{TARGET_BASE}{SEARCH_PATH}?q=apple")
    # ...and the same endpoint is also a generic query surface.
    _endpoint(graph, "GET", f"{TARGET_BASE}{SEARCH_PATH}")
    discovery = synthesize_injection_policy(graph, max_checks=99)

    q_checks = [c for c in discovery.policy.checks
                if c.path == SEARCH_PATH and c.param == "q"]
    # 'q' appears exactly once and keeps its observed anchor (not re-added generic).
    assert len(q_checks) == 1
    assert q_checks[0].baseline_value == "apple"
    # Observed candidates are ordered before generic ones.
    assert discovery.policy.checks[0].param == "q"
    assert discovery.policy.checks[0].baseline_value == "apple"


def test_max_checks_caps_and_reports_the_overflow():
    graph = SecurityGraph()
    _endpoint(graph, "GET", f"{TARGET_BASE}/rest/products")
    discovery = synthesize_injection_policy(graph, max_checks=3)
    assert len(discovery.policy.checks) == 3
    assert discovery.total_candidates > 3
    assert "capped from" in discovery.note


def test_query_surfaces_are_probed_before_plain_endpoints():
    graph = SecurityGraph()
    _endpoint(graph, "GET", f"{TARGET_BASE}/aaa-plain")          # not a surface
    _endpoint(graph, "GET", f"{TARGET_BASE}/zzz-search")         # query surface
    discovery = synthesize_injection_policy(graph, max_checks=99)
    # The query surface's candidates come first despite sorting later by path.
    assert discovery.policy.checks[0].path == "/zzz-search"


# --- end-to-end: synthesized policy through the SAME pure judge -------------

def test_synthesized_injectable_surface_is_confirmed():
    graph = SecurityGraph()
    _obs_param(graph, 1, "q", f"{TARGET_BASE}{SEARCH_PATH}?q=apple")
    discovery = synthesize_injection_policy(graph, include_generic=False)

    results = run_injection_investigation(
        graph,
        discovery.policy,
        target_base=TARGET_BASE,
        executor=_CannedInjectionExecutor(_injectable_body, param="q"),
    )
    assert len(results) == 1 and results[0].status == "VALIDATED"
    findings = list(graph.findings_for(kind="injection", status="OPEN"))
    assert len(findings) == 1 and findings[0].severity == "HIGH"


def test_synthesized_parameterised_surface_is_disproved_no_finding():
    graph = SecurityGraph()
    _obs_param(graph, 1, "name", f"{TARGET_BASE}/api/Products?name=apple")
    discovery = synthesize_injection_policy(graph, include_generic=False)

    results = run_injection_investigation(
        graph,
        discovery.policy,
        target_base=TARGET_BASE,
        executor=_CannedInjectionExecutor(_safe_body, param="name"),
    )
    assert results[0].status == "DISPROVED"
    assert not list(graph.findings_for(kind="injection", status="OPEN"))


def test_generic_sweep_confirms_only_the_injectable_parameter():
    # A generic sweep on a query surface: only the ONE parameter the backend
    # actually evaluates is confirmed; every inert generic collapses -> no
    # finding. Discovery cannot manufacture a verdict the judge does not earn.
    graph = SecurityGraph()
    _endpoint(graph, "GET", f"{TARGET_BASE}{SEARCH_PATH}")
    discovery = synthesize_injection_policy(graph, max_checks=99)

    results = run_injection_investigation(
        graph,
        discovery.policy,
        target_base=TARGET_BASE,
        executor=_CannedInjectionExecutor(_injectable_body, param="q"),
    )
    validated = [r for r in results if r.status == "VALIDATED"]
    assert [r.param for r in validated] == ["q"]
    findings = list(graph.findings_for(kind="injection", status="OPEN"))
    assert len(findings) == 1


# --- observed params harvested from discovered endpoint URLs ----------------

def test_endpoint_url_query_yields_an_observed_candidate():
    # An API route recon mines from JavaScript arrives as an endpoint whose URL
    # carries the query parameter (e.g. .../search?q=). Discovery harvests that
    # parameter as a high-priority OBSERVED candidate — how it reaches an SPA's
    # real query surface, which never appears as a crawlable ?p= link.
    graph = SecurityGraph()
    _endpoint(graph, "GET", f"{TARGET_BASE}{SEARCH_PATH}?q=")
    discovery = synthesize_injection_policy(graph, include_generic=False)

    observed = [c for c in discovery.policy.checks]
    assert any(c.path == SEARCH_PATH and c.param == "q" for c in observed)
    assert discovery.observed_count >= 1


def test_endpoint_url_query_anchor_uses_served_value():
    graph = SecurityGraph()
    _endpoint(graph, "GET", f"{TARGET_BASE}/items?filter=widget")
    discovery = synthesize_injection_policy(graph, include_generic=False)
    check = next(c for c in discovery.policy.checks if c.param == "filter")
    assert check.baseline_value == "widget"


