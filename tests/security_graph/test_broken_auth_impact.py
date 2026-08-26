"""Offline, network-free proof of the IMPACT demonstration stage
(app.security_graph.broken_auth.impact) and its wiring into the AUTH MATRIX.

Proving a token forgery is Sentinel's core job; DEMONSTRATING its impact — using
the forged admin token to perform a real privileged action discovered on the live
admin page — is an explicit, doubly-gated extra step (a check must declare it AND
the operator must opt in). This is the one place the engine issues a state-changing
request, so it stays honest by being a differential itself: the forged token
performs the action AND an anonymous caller is denied the same action.

These tests pin that behaviour with an injected fake executor (zero network):
dynamic discovery off a PortSwigger-shaped admin page, the exact per-object action
chosen by declared params, the forged-vs-anonymous differential, faults degrading
to a token-safe observation, and — end to end — a CONFIRMED forgery whose declared
impact is exercised with the recovered forged token and rendered in the report with
the credential masked. The forged token's VALUE never appears in a note or report.
"""

import base64
import hashlib
import hmac
import json

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.broken_auth.broken_auth_policy import (
    ImpactAction, parse_broken_auth_policy)
from app.security_graph.broken_auth.impact import (
    ImpactObservation, exercise_impact, select_action, _score, _with_query,
    _form_body)
from app.security_graph.broken_auth.run import run_broken_auth_investigation

from app.autonomous import authmatrix as AM
from app.autonomous import orchestrator as O
from app.autonomous import report as R

TARGET = "http://lab.test"

# A PortSwigger-shaped admin panel: one delete link per user. The operator declares
# INTENT (match "delete", username=carlos); the exact URL is read off THIS page.
ADMIN_HTML = """
<html><body><section>
  <h1>Users</h1>
  <div>wiener - <a href="/admin/delete?username=wiener">Delete</a></div>
  <div>carlos - <a href="/admin/delete?username=carlos">Delete</a></div>
</section></body></html>
"""


class _SimpleIdentity:
    """The three attrs impact._run_probe reads off a hypothesis identity."""
    def __init__(self, action="alg_none:GET:/admin"):
        self.principal_id = "principal:authenticated"
        self.resource_id = "resource:broken_auth:GET:/admin"
        self.action = action


class _FakeImpactExecutor(ExperimentExecutor):
    """Serves the admin page on discovery; scores the privileged action by whether
    a credential header rides the request — the forged token performs it, the
    anonymous negative control is denied. Records response_body_text so the dynamic
    discovery has a live page to parse. No sockets."""

    kind = "broken_auth_check"

    def __init__(self, page=ADMIN_HTML, *, forged_status=200, anon_status=401):
        self._page = page
        self._forged = forged_status
        self._anon = anon_status
        self.calls = []

    def execute(self, experiment):
        action = experiment.action or ""
        req = experiment.request
        has_cred = bool(req.headers if req is not None else ())
        self.calls.append((action, req.method if req else None,
                           req.url if req else None, tuple(req.headers) if req else ()))
        if action.endswith("impact_discover"):
            status, body = 200, self._page
        elif not has_cred:                       # anonymous negative control
            status, body = self._anon, ""
        else:                                     # forged privileged action
            status, body = self._forged, ""
        evidence = Evidence(
            id=f"ev:{experiment.id}", source="http_response",
            data={"mode": "http", "status_code": status,
                  "response_body_text": body, "url": req.url if req else ""},
            confidence=1.0)
        return ExecutionResult(
            experiment_id=experiment.id, status="COMPLETED",
            evidence=(evidence,), metadata=(("status_code", str(status)),))


FORGED_HEADERS = (("Cookie", "session=FORGED.JWT.VALUE"),)
DECLARED = ImpactAction(match="delete", params=(("username", "carlos"),))


# ---- pure helpers -----------------------------------------------------------

def test_score_requires_match_and_rewards_param_presence():
    params = (("username", "carlos"),)
    assert _score("/admin/delete?username=carlos", "delete", params) == 1
    assert _score("/admin/delete?username=wiener", "delete", params) == 0
    assert _score("/admin/logout", "delete", params) == -1  # no 'delete' -> miss


def test_with_query_overrides_declared_param():
    url = _with_query("http://x/delete?username=wiener", (("username", "carlos"),))
    assert url == "http://x/delete?username=carlos"


def test_form_body_maps_declared_params_onto_carried_inputs():
    inputs = [{"name": "csrf", "value": "tok"}, {"name": "username", "value": ""}]
    body = _form_body(inputs, (("username", "carlos"),))
    assert body == "csrf=tok&username=carlos"


# ---- dynamic discovery ------------------------------------------------------

def test_select_action_prefers_the_exact_per_object_link():
    cand = select_action(ADMIN_HTML, TARGET + "/admin", DECLARED)
    assert cand is not None
    assert cand.method == "GET"
    assert cand.url.endswith("/admin/delete?username=carlos")


def test_select_action_returns_none_when_nothing_matches():
    html = '<a href="/admin/logout">Log out</a>'
    assert select_action(html, TARGET + "/admin", DECLARED) is None


def test_select_action_builds_form_post_body():
    html = ('<form action="/admin/delete" method="POST">'
            '<input name="csrf" value="tok"><input name="username"></form>')
    cand = select_action(html, TARGET + "/admin",
                         ImpactAction(match="delete", params=(("username", "carlos"),)))
    assert cand is not None and cand.method == "POST"
    assert cand.url.endswith("/admin/delete")
    assert "username=carlos" in cand.body and "csrf=tok" in cand.body


# ---- exercise_impact: fetch -> discover -> forge-do -> anon-deny ------------

def _exercise(executor, impact=DECLARED, *, hyp_id="hyp-1"):
    graph = SecurityGraph()
    obs = exercise_impact(
        TARGET, impact=impact, forged_headers=FORGED_HEADERS, graph=graph,
        executor=executor, hypothesis_id=hyp_id, identity=_SimpleIdentity(),
        breach_url=TARGET + "/admin", breach_method="GET")
    return graph, obs


def test_exercise_demonstrates_impact_as_a_differential():
    graph, obs = _exercise(_FakeImpactExecutor(forged_status=200, anon_status=401))
    assert obs.demonstrated is True
    assert obs.performed is True and obs.privileged is True
    assert obs.url.endswith("/admin/delete?username=carlos")
    assert obs.forged_status == 200 and obs.anon_status == 401
    # three probes recorded on the SAME graph, scoped to the confirmed hypothesis
    tags = sorted(e.action for e in graph.experiments.values())
    assert tags == ["probe_broken_auth_impact", "probe_broken_auth_impact_denied",
                    "probe_broken_auth_impact_discover"]


def test_exercise_forged_token_value_never_enters_the_note():
    _, obs = _exercise(_FakeImpactExecutor())
    assert "FORGED.JWT.VALUE" not in obs.note
    assert "delete" in obs.note  # the (declared, non-secret) action is described


def test_exercise_records_forged_credential_header_for_masking():
    # The forged credential rides the recorded request (so the report masks it),
    # but it is the executor/report that redacts — never the observation note.
    graph, _ = _exercise(_FakeImpactExecutor())
    do = [e for e in graph.experiments.values()
          if e.action == "probe_broken_auth_impact"][0]
    assert ("Cookie", "session=FORGED.JWT.VALUE") in do.request.headers


def test_exercise_anon_allowed_is_not_privileged():
    # If the anonymous caller can ALSO perform the action, the state change is not
    # attributable to the forged privilege -> performed, but NOT demonstrated.
    _, obs = _exercise(_FakeImpactExecutor(forged_status=200, anon_status=200))
    assert obs.performed is True
    assert obs.privileged is False and obs.demonstrated is False


def test_exercise_no_matching_action_reports_bypass_only():
    executor = _FakeImpactExecutor(page='<a href="/admin/logout">Log out</a>')
    _, obs = _exercise(executor)
    assert obs.attempted is True and obs.demonstrated is False
    assert "no privileged action" in obs.note


def test_exercise_undeclared_impact_is_a_noop():
    _, obs = _exercise(_FakeImpactExecutor(), impact=ImpactAction())
    assert obs.attempted is False
    assert "no impact action declared" in obs.note


def test_exercise_fault_degrades_to_token_safe_observation():
    class _Boom(ExperimentExecutor):
        kind = "broken_auth_check"
        def execute(self, experiment):
            raise RuntimeError("network down")

    _, obs = _exercise(_Boom())
    assert obs.attempted is True and obs.demonstrated is False
    assert "failed" in obs.note  # degraded, never raised


def test_exercise_explicit_action_skips_discovery():
    from app.security_graph.broken_auth.broken_auth_policy import ControlRoute

    executor = _FakeImpactExecutor()
    graph = SecurityGraph()
    impact = ImpactAction(match="delete", params=(("username", "carlos"),),
                          action=ControlRoute(method="GET", path="/admin/delete"))
    obs = exercise_impact(
        TARGET, impact=impact, forged_headers=FORGED_HEADERS, graph=graph,
        executor=executor, hypothesis_id="hyp-1", identity=_SimpleIdentity(),
        breach_url=TARGET + "/admin")
    assert obs.performed is True
    # no discovery fetch was issued (the route was declared explicitly)
    assert not any(a.endswith("impact_discover") for a, *_ in executor.calls)
    assert obs.url.endswith("/admin/delete?username=carlos")


# ---- policy parsing: the optional impact block ------------------------------

def _parse_with_impact(impact):
    return parse_broken_auth_policy({"broken_auth_matrix": {
        "principal": {"name": "authenticated"},
        "checks": [{"forgery": "alg_none", "route": {"path": "/admin"},
                    "impact": impact}]}})


def test_parse_reads_impact_match_params_and_discover():
    policy = _parse_with_impact({
        "match": "delete", "params": {"username": "carlos"},
        "discover": {"method": "GET", "path": "/admin"}})
    impact = policy.checks[0].impact
    assert impact is not None and impact.declared
    assert impact.match == "delete"
    assert impact.params == (("username", "carlos"),)
    assert impact.discover.path == "/admin"


def test_parse_empty_impact_block_degrades_to_none():
    # A bare {} names nothing to do -> prove-only, never a parse error.
    assert _parse_with_impact({}).checks[0].impact is None


def test_parse_absent_impact_is_none():
    policy = parse_broken_auth_policy({"broken_auth_matrix": {
        "principal": {"name": "authenticated"},
        "checks": [{"forgery": "alg_none", "route": {"path": "/admin"}}]}})
    assert policy.checks[0].impact is None


# ---- end to end: a CONFIRMED forgery has its declared impact demonstrated ----

def _b64url(obj):
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hs256(header, payload, secret):
    hseg, pseg = _b64url(header), _b64url(payload)
    sig = hmac.new(secret.encode(), f"{hseg}.{pseg}".encode(), hashlib.sha256).digest()
    return f"{hseg}.{pseg}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


GENUINE = _hs256({"alg": "HS256", "typ": "JWT"},
                 {"sub": "wiener", "role": "user"}, "secret")


class _CombinedExecutor(ExperimentExecutor):
    """Grants the whole chain: the three-probe forgery differential (genuine token
    works, forged token ALSO works, anonymous denied) AND the impact demonstration
    (admin page on discovery, forged delete performed, anonymous delete denied). One
    executor, keyed on the probe tag + whether a credential rides the request."""

    kind = "broken_auth_check"

    def __init__(self, page=ADMIN_HTML):
        self._page = page

    def execute(self, experiment):
        action = experiment.action or ""
        req = experiment.request
        auth = ""
        for name, value in (req.headers if req is not None else ()):
            if str(name).lower() == "authorization":
                auth = str(value)
                break
        has_cred = bool(auth)
        if action.endswith("impact_discover"):
            status, body = 200, self._page
        elif "impact" in action:               # impact / impact_denied
            status, body = (200 if has_cred else 401), ""
        else:                                   # control / breach / baseline
            status, body = (200 if has_cred else 401), ""
        evidence = Evidence(
            id=f"ev:{experiment.id}", source="http_response",
            data={"mode": "http", "status_code": status,
                  "response_body_text": body, "url": req.url if req else ""},
            confidence=1.0)
        return ExecutionResult(
            experiment_id=experiment.id, status="COMPLETED",
            evidence=(evidence,), metadata=(("status_code", str(status)),))


def _impact_policy():
    return parse_broken_auth_policy({"broken_auth_matrix": {
        "principal": {"name": "authenticated",
                      "headers": [["Authorization", f"Bearer {GENUINE}"]],
                      "role": "user"},
        "checks": [{"forgery": "alg_none", "route": {"method": "GET", "path": "/admin"},
                    "impact": {"match": "delete", "params": {"username": "carlos"},
                               "discover": {"method": "GET", "path": "/admin"}}}]}})


def test_broken_auth_verdicts_demonstrate_impact_when_enabled():
    executor = _CombinedExecutor()
    verdicts = AM.broken_auth_verdicts(
        TARGET, _impact_policy(), GENUINE, impact_enabled=True,
        _run=lambda g, p, *, target_base: run_broken_auth_investigation(
            g, p, target_base=target_base, executor=executor),
        graph_factory=SecurityGraph,
        executor_factory=lambda _tb: executor)

    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.status == O.VERDICT_CONFIRMED
    assert "IMPACT DEMONSTRATED" in v.detail
    assert "carlos" in v.detail  # the declared per-object action, not a secret
    # the impact probes landed on the proven graph, scoped to the same hypothesis
    graph = v.evidence.graph
    assert any(e.action == "probe_broken_auth_impact" for e in graph.experiments.values())


def test_broken_auth_verdicts_skip_impact_when_disabled():
    executor = _CombinedExecutor()
    verdicts = AM.broken_auth_verdicts(
        TARGET, _impact_policy(), GENUINE, impact_enabled=False,
        _run=lambda g, p, *, target_base: run_broken_auth_investigation(
            g, p, target_base=target_base, executor=executor),
        graph_factory=SecurityGraph,
        executor_factory=lambda _tb: executor)
    assert verdicts[0].status == O.VERDICT_CONFIRMED
    assert "IMPACT" not in verdicts[0].detail
    graph = verdicts[0].evidence.graph
    assert not any("impact" in (e.action or "") for e in graph.experiments.values())


def test_impact_never_runs_for_a_disproved_forgery():
    # The forged token is REFUSED -> DISPROVED -> the impact must never fire (no
    # exercising a bypass that was not proven).
    exercised = {"n": 0}

    def spy_exercise(*a, **k):
        exercised["n"] += 1
        return ImpactObservation()

    class _Refuses(_CombinedExecutor):
        def execute(self, experiment):
            action = experiment.action or ""
            if not action.endswith("breach"):
                return super().execute(experiment)
            # forged (breach) token refused -> validation holds -> DISPROVED
            ev = Evidence(id=f"ev:{experiment.id}", source="http_response",
                          data={"mode": "http", "status_code": 403,
                                "response_body_text": "", "url": ""}, confidence=1.0)
            return ExecutionResult(experiment_id=experiment.id, status="COMPLETED",
                                   evidence=(ev,), metadata=(("status_code", "403"),))

    executor = _Refuses()
    verdicts = AM.broken_auth_verdicts(
        TARGET, _impact_policy(), GENUINE, impact_enabled=True,
        _run=lambda g, p, *, target_base: run_broken_auth_investigation(
            g, p, target_base=target_base, executor=executor),
        graph_factory=SecurityGraph, _exercise=spy_exercise,
        executor_factory=lambda _tb: executor)
    assert verdicts[0].status == O.VERDICT_DISPROVED
    assert exercised["n"] == 0


def test_report_masks_forged_credential_but_shows_the_delete_step():
    executor = _CombinedExecutor()
    verdicts = AM.broken_auth_verdicts(
        TARGET, _impact_policy(), GENUINE, impact_enabled=True,
        _run=lambda g, p, *, target_base: run_broken_auth_investigation(
            g, p, target_base=target_base, executor=executor),
        graph_factory=SecurityGraph,
        executor_factory=lambda _tb: executor)
    report = O.Report(plan=O.Plan(surface=None), verdicts=tuple(verdicts))
    model = R.build_report(report, target=TARGET)
    rendered = json.dumps(model, default=lambda o: getattr(o, "__dict__", str(o)))
    # the genuine/forged token VALUE never surfaces; the declared action does
    assert GENUINE not in rendered
    assert "administrator" not in rendered or "sub" not in rendered  # no leaked claim dump
    assert "/admin/delete" in rendered and "carlos" in rendered


