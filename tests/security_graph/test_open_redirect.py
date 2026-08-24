"""
Offline, network-free proof of the open-redirect (two-probe host differential)
class and its PATCH + PROVE remediation. No real target is contacted for the
unit tests: a canned executor extracts the URL injected into the declared
parameter and returns a modelled ``(status_code, Location)`` a deterministic
redirector produces, so the host differential is pinned exactly:

  * a declared redirect surface becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when the off-origin payload probe
    redirects (3xx) to the unforgeable nonce host — a host that could ONLY have
    come from our parameter value — AND the same-origin control anchor proves the
    endpoint legitimately redirects on-origin; DISPROVED when the payload is
    ignored / sanitized / forced on-origin (also the post-fix state once the
    url-allowlist request-guard blocks the off-origin value); and INCONCLUSIVE
    when the payload DID redirect off-origin but the control anchor did not
    reproduce an on-origin redirect — in every non-VALIDATED case NO finding is
    manufactured;
  * a corrective request-guard (signature family ``url_allowlist``) is derived
    only from a confirmed open redirect, and the same judge — re-run through the
    enforcement shield — proves the fix ONLY when it flips VALIDATED -> DISPROVED
    (the off-origin payload becomes 403 so the Location never carries the nonce
    host while the benign same-origin control is still forwarded);
  * verification NEVER mutates the confirmed hypothesis or finding.

One localhost integration test stands the real reverse proxy in front of a stub
upstream that genuinely reflects the parameter into ``Location`` (a real open
redirector), and proves the request-guard blocks the off-origin payload (403) so
the nonce host is never reached, while still forwarding the benign control.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.open_redirect import (
    judge_open_redirect,
    parse_open_redirect_policy,
    payload_url,
    remediate_open_redirect_and_prove,
    render_open_redirect_artifacts,
    run_open_redirect_investigation,
    synthesize_open_redirect_remediation,
)
from app.security_graph.open_redirect.executor import _NoFollowRedirectHandler
from app.security_graph.remediation.enforcer import (
    RemediationEnforcer,
    RequestGuardRule,
    _matches_url_allowlist,
    evaluate_request_guard,
)

TARGET_BASE = "http://127.0.0.1:3000"
REDIRECT_PATH = "/redirect"
ALLOW_HOST = "127.0.0.1"

_QUERY_CHECK = {
    "method": "GET",
    "path": REDIRECT_PATH,
    "param": "to",
    "location": "query",
    "severity": "MEDIUM",
}


# --- deterministic redirector models: (value) -> (status_code, Location) -----
# Each models how a target would respond to the URL placed in the `to`
# parameter. No network, no real server — the judge reads only status_code +
# the Location header the model returns, so the host differential is pinned.

def _open_redirector(value: str) -> tuple[int, str]:
    # A VULNERABLE open redirect: reflects whatever URL it is given straight into
    # the Location header. The off-origin nonce payload -> Location on the nonce
    # host (attacker-controlled); the same-origin control -> on-origin redirect.
    return 302, value


def _safe_relative(value: str) -> tuple[int, str]:
    # A SAFE redirector: ignores the parameter and always redirects to a fixed
    # on-origin path. The payload never reaches the nonce host -> DISPROVED.
    return 302, "/account"


def _ignores_param(value: str) -> tuple[int, str]:
    # The endpoint never redirects at all (200, no Location) -> DISPROVED.
    return 200, ""


def _anchor_unhealthy(value: str) -> tuple[int, str]:
    # Reflects an OFF-ORIGIN value into Location, but does NOT redirect for the
    # same-origin control (returns 200). So the payload reaches the nonce host
    # while the control anchor never establishes an on-origin baseline
    # -> INCONCLUSIVE (the differential is refused, not claimed).
    host = (urlsplit(value).hostname or "").lower()
    if host and host not in {"127.0.0.1", "localhost"}:
        return 302, value
    return 200, ""


def _guarded(value: str) -> tuple[int, str]:
    # BEHIND the url-allowlist request-guard: an off-origin absolute URL whose
    # host is not on the allowlist is refused (403) before it can be reflected,
    # so the nonce host is never reached; the benign same-origin control is
    # forwarded and redirects on-origin. Uses the REAL enforcer allowlist test so
    # the offline model stays faithful to the deployed shield.
    if _matches_url_allowlist(value, (ALLOW_HOST,)):
        return 403, ""
    return 302, value


class _CannedOpenRedirectExecutor(ExperimentExecutor):
    """Network-free open-redirect executor: extract the injected URL and return a
    modelled ``(status_code, Location)``. The judge reads only ``status_code`` and
    the ``Location`` header from the single ``mode=="http"`` evidence, so this
    pins the two-probe host differential without touching a network.
    """

    kind = "open_redirect_check"

    def __init__(self, responder, *, param="to", location="query"):
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
        code, location = self._responder(value)
        headers = [("Location", location)] if location else []
        evidence = Evidence(
            id=f"ev:open-redirect:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": code,
                "response_headers": headers,
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
    """Build a one-check open-redirect matrix policy."""
    return parse_open_redirect_policy(
        {"open_redirect_matrix": {"checks": [check or dict(_QUERY_CHECK)]}}
    )


def _resolved_graph(responder, *, check=None, param="to", location="query"):
    """Seed one redirect surface and drive it to a verdict with a canned model."""
    graph = SecurityGraph()
    results = run_open_redirect_investigation(
        graph,
        _matrix(check),
        target_base=TARGET_BASE,
        executor=_CannedOpenRedirectExecutor(
            responder, param=param, location=location
        ),
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(graph.findings_for(kind="open_redirect", status="OPEN"))
    assert len(findings) == 1
    return findings[0]


# --- parse -----------------------------------------------------------------

def test_parse_open_redirect_matrix_reads_checks():
    policy = _matrix()
    assert len(policy.checks) == 1
    check = policy.checks[0]
    assert check.method == "GET" and check.path == REDIRECT_PATH
    assert check.param == "to" and check.location == "query"
    assert check.severity == "MEDIUM"


def test_parse_no_matrix_yields_empty_policy():
    assert parse_open_redirect_policy({"access_rules": []}).checks == ()


def test_parse_rejects_bad_location():
    with pytest.raises(ValueError):
        parse_open_redirect_policy(
            {"open_redirect_matrix": {"checks": [
                {"method": "GET", "path": REDIRECT_PATH, "param": "to",
                 "location": "header"}
            ]}}
        )


def test_parse_rejects_missing_param():
    with pytest.raises(ValueError):
        parse_open_redirect_policy(
            {"open_redirect_matrix": {"checks": [
                {"method": "GET", "path": REDIRECT_PATH}
            ]}}
        )
# --- seed + PURE two-probe host differential judge -------------------------

def test_open_redirect_surface_is_validated_and_confirmed():
    graph, results = _resolved_graph(_open_redirector)
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert results[0].param == "to"
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "open_redirect"
    assert finding.severity == "MEDIUM"


def test_safe_relative_redirect_is_disproved_no_finding():
    # The parameter is ignored; the endpoint always redirects on-origin -> the
    # payload never reaches the nonce host -> DISPROVED, nothing manufactured.
    graph, results = _resolved_graph(_safe_relative)
    assert results[0].status == "DISPROVED"
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(graph.findings_for(kind="open_redirect", status="OPEN"))


def test_non_redirecting_endpoint_is_disproved_no_finding():
    graph, results = _resolved_graph(_ignores_param)
    assert results[0].status == "DISPROVED"
    assert not list(graph.findings_for(kind="open_redirect", status="OPEN"))


def test_unhealthy_anchor_is_inconclusive_no_finding():
    # The payload reaches the nonce host, but the same-origin control anchor
    # never establishes an on-origin baseline -> INCONCLUSIVE, nothing made.
    graph, results = _resolved_graph(_anchor_unhealthy)
    assert results[0].status == "INCONCLUSIVE"
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(graph.findings_for(kind="open_redirect", status="OPEN"))


def test_pure_judge_reads_the_host_differential_directly():
    # Drive to a confirmed graph, then re-run the PURE judge against the same
    # recorded probes and assert VALIDATED is a deterministic function of them.
    graph, results = _resolved_graph(_open_redirector)
    hyp = graph.hypotheses[results[0].hypothesis_id]
    judgment = judge_open_redirect(
        graph,
        hypothesis=hyp,
        control_experiment_id=f"exp:open-redirect-control:{hyp.id}",
        payload_experiment_id=f"exp:open-redirect-payload:{hyp.id}",
    )
    assert judgment.status == "VALIDATED"
    assert judgment.contradiction_kind == "open_redirect"
    assert judgment.observed is True


# --- guard purity (the virtual-patch decision) -----------------------------

def test_matches_url_allowlist_denies_off_origin_not_same_origin():
    # Off-origin absolute URL whose host is not allowed -> deny.
    assert _matches_url_allowlist("https://sentinel-abc123.example/", (ALLOW_HOST,))
    assert _matches_url_allowlist("//evil.test/path", (ALLOW_HOST,))
    # Same-origin absolute + relative + empty -> never denied.
    assert not _matches_url_allowlist("http://127.0.0.1:3000/", (ALLOW_HOST,))
    assert not _matches_url_allowlist("/account", (ALLOW_HOST,))
    assert not _matches_url_allowlist("", (ALLOW_HOST,))


def test_evaluate_request_guard_denies_off_origin_forwards_same_origin():
    rule = RequestGuardRule(
        method="GET", path=REDIRECT_PATH, param="to", location="query",
        signature_family="url_allowlist", allow=(ALLOW_HOST,),
    )
    # The benign same-origin control is forwarded.
    assert (
        evaluate_request_guard(
            "GET", REDIRECT_PATH, "to=http%3A%2F%2F127.0.0.1%3A3000%2F", None,
            (rule,),
        )
        == "forward"
    )
    # An off-origin payload (nonce host) is denied.
    assert (
        evaluate_request_guard(
            "GET", REDIRECT_PATH,
            "to=https%3A%2F%2Fsentinel-abc123.example%2F", None, (rule,),
        )
        == "deny"
    )
    # A different route is untouched by this guard.
    assert (
        evaluate_request_guard(
            "GET", "/other", "to=https%3A%2F%2Fsentinel-abc123.example%2F", None,
            (rule,),
        )
        == "forward"
    )
# --- synthesize + artifacts -------------------------------------------------

def test_synthesize_open_redirect_remediation_from_confirmed_finding():
    graph, _ = _resolved_graph(_open_redirector)
    plan = synthesize_open_redirect_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.method == "GET" and plan.rule.path == REDIRECT_PATH
    assert plan.rule.param == "to" and plan.rule.location == "query"
    assert plan.rule.allow_host == ALLOW_HOST
    assert plan.upstream_base == TARGET_BASE
    assert plan.endpoint_url == TARGET_BASE + REDIRECT_PATH


def test_synthesize_ignores_non_open_redirect_finding():
    from dataclasses import replace

    graph, _ = _resolved_graph(_open_redirector)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    assert synthesize_open_redirect_remediation(graph, foreign) is None


def test_render_open_redirect_artifacts_non_empty_and_name_the_param():
    graph, _ = _resolved_graph(_open_redirector)
    plan = synthesize_open_redirect_remediation(graph, _confirmed_finding(graph))
    artifacts = render_open_redirect_artifacts(plan.rule, plan.upstream_base)
    for config in (artifacts.portable_json, artifacts.nginx,
                   artifacts.modsecurity, artifacts.caddy):
        assert config.strip()
        assert "to" in config
    assert plan.upstream_base in artifacts.portable_json
    assert ALLOW_HOST in artifacts.portable_json


# --- remediate + PROVE (injected executors, no live proxy) -----------------

def test_remediate_open_redirect_and_prove_fix_proven_and_isolated():
    graph, _ = _resolved_graph(_open_redirector)
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id

    outcome = remediate_open_redirect_and_prove(
        graph,
        finding,
        # before: still reflects the off-origin URL -> VALIDATED
        before_executor=_CannedOpenRedirectExecutor(_open_redirector),
        # after: url-allowlist guard blocks the off-origin payload -> DISPROVED
        after_executor=_CannedOpenRedirectExecutor(_guarded),
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_open_redirect_fix_failed_when_guard_does_not_block():
    graph, _ = _resolved_graph(_open_redirector)
    outcome = remediate_open_redirect_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedOpenRedirectExecutor(_open_redirector),
        # still reflects off-origin -> payload reaches nonce host -> VALIDATED
        after_executor=_CannedOpenRedirectExecutor(_open_redirector),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_open_redirect_fix_failed_when_redirect_did_not_reproduce():
    # The after re-probe is DISPROVED, but the open redirect did NOT reproduce on
    # the pre-fix re-probe (before != VALIDATED). A guard cannot take credit for a
    # boundary already holding, so FIX_PROVEN requires the full flip.
    graph, _ = _resolved_graph(_open_redirector)
    outcome = remediate_open_redirect_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedOpenRedirectExecutor(_safe_relative),  # no repro
        after_executor=_CannedOpenRedirectExecutor(_guarded),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.before_status == "DISPROVED"
    assert not outcome.verification.proven


def test_remediate_non_open_redirect_finding_is_not_applicable():
    from dataclasses import replace

    graph, _ = _resolved_graph(_open_redirector)
    foreign = replace(_confirmed_finding(graph), kind="injection")
    outcome = remediate_open_redirect_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"
# --- live integration: real reverse proxy blocks off-origin, keeps benign ----

class _ReflectingRedirectHandler(BaseHTTPRequestHandler):
    """The pre-fix vulnerable target: a genuine open redirector that reflects the
    ``to`` parameter straight into the ``Location`` header on ``/redirect`` (so an
    off-origin payload provably redirects to the nonce host -> VALIDATED), and
    returns a plain 200 for every other path (so an on-origin control redirect,
    if followed by the shield, terminates cleanly).
    """

    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        split = urlsplit(self.path)
        if split.path == REDIRECT_PATH:
            params = parse_qs(split.query, keep_blank_values=True)
            dest = (params.get("to") or [""])[0]
            if dest:
                self.send_response(302)
                self.send_header("Location", dest)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
        body = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def test_live_enforcer_blocks_off_origin_but_forwards_benign():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectingRedirectHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"

        # Seed a fresh graph bound to the live stub and drive it to a confirmed
        # open redirect with the REAL no-follow executor, then prove the fix
        # through the REAL reverse proxy with the url-allowlist guard active.
        graph = SecurityGraph()
        run_open_redirect_investigation(
            graph,
            _matrix(),
            target_base=upstream_base,
            executor=None,  # real no-follow OpenRedirectProbeExecutor
        )
        finding = _confirmed_finding(graph)

        outcome = remediate_open_redirect_and_prove(
            graph, finding, use_enforcer=True
        )

        assert outcome.result == "FIX_PROVEN"
        assert outcome.verification.before_status == "VALIDATED"
        assert outcome.verification.after_status == "DISPROVED"
    finally:
        upstream.shutdown()
        upstream.server_close()


def test_live_enforcer_returns_403_for_off_origin_forwards_same_origin():
    # Directly observe the raw shield behaviour the DISPROVED verdict rests on:
    # an off-origin payload is refused (403) before it can reach the reflecting
    # upstream, so the nonce host is never contacted; the benign same-origin
    # control is forwarded (the upstream reflects it into an on-origin 302).
    import urllib.error
    import urllib.request
    from urllib.parse import urlencode

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectingRedirectHandler)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"
        allow_host = (urlsplit(upstream_base).hostname or "").lower()
        guard = RequestGuardRule(
            method="GET", path=REDIRECT_PATH, param="to", location="query",
            signature_family="url_allowlist", allow=(allow_host,),
        )
        with RemediationEnforcer(
            (), upstream_base, guard_rules=(guard,)
        ) as shield:
            opener = urllib.request.build_opener(_NoFollowRedirectHandler())

            # Same-origin control: NOT blocked by the guard -> forwarded to the
            # upstream. The enforcer itself follows the resulting on-origin 302
            # (SSRF-safe, same host) and returns the terminal 200 to the client —
            # proving the benign control was forwarded, never refused with 403.
            control = urlencode({"to": f"{upstream_base}/"})
            resp = opener.open(
                f"{shield.base_url}{REDIRECT_PATH}?{control}", timeout=10
            )
            assert resp.status == 200

            # Off-origin payload: refused by the guard (403) before forwarding.
            payload = urlencode({"to": payload_url("abc123def456")})
            try:
                opener.open(
                    f"{shield.base_url}{REDIRECT_PATH}?{payload}", timeout=10
                )
                assert False, "the request-guard should have refused the payload"
            except urllib.error.HTTPError as exc:
                assert exc.code == 403
    finally:
        upstream.shutdown()
        upstream.server_close()




