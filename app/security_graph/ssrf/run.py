"""
Drive the SSRF prove-chain to a verdict.

Mirror of :mod:`app.security_graph.open_redirect.run`, but each OPEN `ssrf`
hypothesis is resolved with an **out-of-band callback differential** rather than a
response-header one. For each hypothesis it:

  * recovers the declared fetch surface the seeder wrote into the graph,
  * mints a FRESH payload nonce and a FRESH never-injected control nonce for THIS
    probe round (a stateful collaborator therefore cannot leak a stale hit into a
    later re-probe — the after-remediation round uses different nonces again),
  * executes the live *control* anchor probe (the parameter set to the target's
    own origin — a benign same-origin fetch that must NOT reach our collaborator)
    plus the *payload* probe (the parameter set to Sentinel's OWN loopback
    collaborator URL carrying the payload nonce),
  * reads the collaborator's hit record after each probe and writes it as
    ``ssrf_callback`` evidence on the experiment — the only thing the pure judge
    reads (never the target's HTTP status),
  * lets the PURE :func:`judge_ssrf` decide from the callback differential, and
  * applies the judgment (VALIDATED -> CONFIRMED) exactly as the cycle does.

Finally it materialises confirmed hypotheses into findings via the same generic
:func:`materialize_confirmed_findings`. A finding appears only when the live
payload provably reached Sentinel's collaborator on the unforgeable nonce while
the never-injected control nonce stayed un-hit. This runner holds no
target-specific logic; the injected URL is ALWAYS Sentinel's own loopback
collaborator — never a metadata IP, an RFC-1918 host, or any third party.
"""

from __future__ import annotations

from dataclasses import dataclass
import random
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..analysis import apply_validation_judgment, materialize_confirmed_findings
from ..graph import SecurityGraph
from ..models import Evidence, Experiment, Hypothesis, HttpRequestSpec, ValidationJudgment
from .collaborator import SentinelCollaborator
from .executor import SsrfProbeExecutor
from .judge import SsrfExpectation, ssrf_expectation, judge_ssrf
from .ssrf_policy import SsrfPolicy, make_nonce
from .seed import seed_ssrf_policy


@dataclass(frozen=True)
class SsrfProbeResult:
    """What one SSRF hypothesis resolved to, for rendering."""

    hypothesis_id: str
    experiment_id: str
    claim: str
    severity: str
    status: str            # judge status: VALIDATED / DISPROVED / INCONCLUSIVE
    param: str
    location: str
    callback_hit: bool | None
    payload_status_code: int | None
    control_status_code: int | None
    reason: str


def _expectation_for(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> SsrfExpectation | None:
    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    return ssrf_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )


def _same_origin_control(endpoint_url: str) -> str:
    """The target's own origin as a benign same-origin fetch destination (anchor).

    A server that fetches this reaches only ITSELF, never our collaborator — so
    the anchor establishes the HTTP baseline and the pre-injection callback state
    without ever hitting Sentinel's loopback listener.
    """
    split = urlsplit(endpoint_url)
    scheme = split.scheme or "http"
    return f"{scheme}://{split.netloc}/"


def _distinct_nonces(rng: random.Random | None) -> tuple[str, str]:
    """A fresh (payload, control) nonce pair, guaranteed distinct."""
    payload_nonce = make_nonce(rng)
    control_nonce = make_nonce(rng)
    while control_nonce == payload_nonce:
        control_nonce = make_nonce(rng)
    return payload_nonce, control_nonce


def _inject(
    expectation: SsrfExpectation,
    value: str,
) -> tuple[str, str | None, tuple[tuple[str, str], ...]]:
    """
    Build (url, body, headers) that place `value` in the declared parameter.

    Pure and target-agnostic: the fetch-URL value goes exactly where the operator
    said the parameter lives (query string / urlencoded body / JSON body). The
    request URL is ALWAYS on the target — only the parameter value names our
    loopback collaborator.
    """
    url = expectation.endpoint_url
    if expectation.location == "query":
        split = urlsplit(url)
        params = dict(parse_qsl(split.query, keep_blank_values=True))
        params[expectation.param] = value
        new_query = urlencode(params)
        url = urlunsplit(
            (split.scheme, split.netloc, split.path, new_query, split.fragment)
        )
        return url, None, ()
    if expectation.location == "body_form":
        body = urlencode({expectation.param: value})
        return url, body, (("Content-Type", "application/x-www-form-urlencoded"),)
    # body_json
    import json

    body = json.dumps({expectation.param: value})
    return url, body, (("Content-Type", "application/json"),)


def _run_probe(
    graph: SecurityGraph,
    executor,
    collaborator,
    hypothesis: Hypothesis,
    expectation: SsrfExpectation,
    *,
    tag: str,
    value: str,
    payload_nonce: str,
    control_nonce: str,
) -> tuple[str, int | None]:
    """
    Build → execute → capture-callback → complete one probe.

    Returns (experiment_id, target_status_code). After delivering the probe to
    the target, it snapshots the collaborator's hit record and writes it as
    ``ssrf_callback`` evidence — the pure judge reads that, never the status code.
    On the PAYLOAD probe it polls briefly (a server-side fetch may land just after
    the target's own response returns); on the CONTROL probe it reads immediately,
    establishing the pre-injection baseline.
    """
    identity = hypothesis.identity
    url, body, headers = _inject(expectation, value)
    experiment = Experiment(
        id=f"exp:ssrf-{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="ssrf_check",
        description=f"ssrf {tag} probe for {hypothesis.id}.",
        status="PLANNED",
        request=HttpRequestSpec(
            method=expectation.method,
            url=url,
            headers=headers,
            body=body,
            principal_id=identity.principal_id,
            resource_id=identity.resource_id,
            action=identity.action,
        ),
        capability_id="ssrf.ssrf_check",
        action=f"probe_ssrf_{tag}",
    )
    graph.add_experiment(experiment)

    result = executor.execute(experiment)
    evidence_ids = []
    for evidence in result.evidence:
        graph.add_evidence(evidence)
        evidence_ids.append(evidence.id)

    # -- out-of-band callback snapshot (the SSRF signal) -------------------
    if tag == "payload":
        payload_hit = bool(collaborator.wait_for_hit(payload_nonce))
    else:
        payload_hit = bool(collaborator.was_hit(payload_nonce))
    control_hit = bool(collaborator.was_hit(control_nonce))

    callback_id = f"evidence:ssrf-callback-{tag}:{hypothesis.id}"
    graph.add_evidence(
        Evidence(
            id=callback_id,
            source="sentinel_collaborator",
            data={
                "mode": "ssrf_callback",
                "role": tag,
                "collaborator_base": collaborator.base_url,
                "payload_nonce": payload_nonce,
                "control_nonce": control_nonce,
                "payload_nonce_hit": payload_hit,
                "control_nonce_hit": control_hit,
            },
            confidence=1.0,
        )
    )
    evidence_ids.append(callback_id)

    completed = Experiment(
        id=experiment.id,
        hypothesis_id=experiment.hypothesis_id,
        kind=experiment.kind,
        description=experiment.description,
        status=result.status,
        evidence_ids=tuple(evidence_ids),
        request=experiment.request,
        capability_id=experiment.capability_id,
        action=experiment.action,
    )
    graph.add_experiment(completed)

    raw_code = dict(result.metadata).get("status_code")
    code = int(raw_code) if raw_code is not None else None
    return experiment.id, code


def _probe_and_judge(
    graph: SecurityGraph,
    executor,
    collaborator,
    hypothesis: Hypothesis,
    *,
    rng: random.Random | None = None,
) -> tuple[ValidationJudgment | None, int | None, int | None]:
    expectation = _expectation_for(graph, hypothesis)
    if expectation is None:
        return None, None, None

    payload_nonce, control_nonce = _distinct_nonces(rng)

    # Control anchor FIRST: it establishes that the payload nonce is un-hit
    # before we ever inject it (temporal attribution) and that the endpoint
    # accepts a URL parameter — without touching our collaborator.
    control_id, control_code = _run_probe(
        graph, executor, collaborator, hypothesis, expectation,
        tag="control", value=_same_origin_control(expectation.endpoint_url),
        payload_nonce=payload_nonce, control_nonce=control_nonce,
    )
    payload_id, payload_code = _run_probe(
        graph, executor, collaborator, hypothesis, expectation,
        tag="payload", value=collaborator.callback_url(payload_nonce),
        payload_nonce=payload_nonce, control_nonce=control_nonce,
    )

    judgment = judge_ssrf(
        graph,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_id=payload_id,
    )
    return judgment, control_code, payload_code


def _callback_hit(graph: SecurityGraph, experiment_id: str) -> bool | None:
    """Read back the payload-nonce hit the runner recorded, for rendering only."""
    experiment = graph.experiments.get(experiment_id)
    if experiment is None:
        return None
    for evidence_id in experiment.evidence_ids:
        evidence = graph.evidence.get(evidence_id)
        if evidence is None:
            continue
        data = evidence.data
        if isinstance(data, dict) and data.get("mode") == "ssrf_callback":
            return bool(data.get("payload_nonce_hit"))
    return None


def _result_for(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
    expectation: SsrfExpectation | None,
    judgment: ValidationJudgment | None,
    control_code: int | None,
    payload_code: int | None,
) -> SsrfProbeResult:
    severity = expectation.severity if expectation is not None else "HIGH"
    param = expectation.param if expectation is not None else ""
    location = expectation.location if expectation is not None else ""

    if judgment is None:
        return SsrfProbeResult(
            hypothesis_id=hypothesis.id,
            experiment_id=f"exp:ssrf-payload:{hypothesis.id}",
            claim=hypothesis.claim,
            severity=severity,
            status="INCONCLUSIVE",
            param=param,
            location=location,
            callback_hit=None,
            payload_status_code=payload_code,
            control_status_code=control_code,
            reason="ssrf surface metadata unavailable",
        )

    return SsrfProbeResult(
        hypothesis_id=hypothesis.id,
        experiment_id=judgment.experiment_id,
        claim=hypothesis.claim,
        severity=severity,
        status=judgment.status,
        param=param,
        location=location,
        callback_hit=_callback_hit(graph, judgment.experiment_id),
        payload_status_code=payload_code,
        control_status_code=control_code,
        reason=judgment.reason,
    )


def _investigate_with(
    graph: SecurityGraph,
    executor,
    collaborator,
    hypotheses,
    rng: random.Random | None,
) -> list[SsrfProbeResult]:
    results: list[SsrfProbeResult] = []
    for hypothesis in hypotheses:
        expectation = _expectation_for(graph, hypothesis)
        judgment, control_code, payload_code = _probe_and_judge(
            graph, executor, collaborator, hypothesis, rng=rng
        )
        if judgment is not None:
            graph.add_validation_judgment(judgment)
            apply_validation_judgment(graph, judgment)
        results.append(
            _result_for(
                graph, hypothesis, expectation, judgment, control_code, payload_code
            )
        )

    materialize_confirmed_findings(graph)
    return results


# __APPEND__


def investigate_ssrf(
    graph: SecurityGraph,
    *,
    executor=None,
    collaborator=None,
    rng: random.Random | None = None,
) -> list[SsrfProbeResult]:
    """
    Probe (payload + same-origin control) → judge → confirm every OPEN `ssrf`
    hypothesis, then materialise findings.

    When no ``collaborator`` is supplied a real :class:`SentinelCollaborator` is
    stood up on loopback for the duration and torn down afterwards. Tests inject a
    canned collaborator (and executor) so no socket is opened.
    """
    hypotheses = sorted(
        graph.hypotheses_for(kind="ssrf", status="OPEN"),
        key=lambda item: item.id,
    )
    if not hypotheses:
        return []

    exec_ = executor or SsrfProbeExecutor()

    if collaborator is not None:
        return _investigate_with(graph, exec_, collaborator, hypotheses, rng)

    with SentinelCollaborator() as collab:
        return _investigate_with(graph, exec_, collab, hypotheses, rng)


def run_ssrf_investigation(
    graph: SecurityGraph,
    policy: SsrfPolicy,
    *,
    target_base: str,
    executor=None,
    collaborator=None,
    rng: random.Random | None = None,
) -> list[SsrfProbeResult]:
    """
    Seed an SSRF matrix and run the full SSRF prove-chain.

    Live probing is bounded to the engagement host by default. Returns one
    :class:`SsrfProbeResult` per hypothesis (including DISPROVED and INCONCLUSIVE
    ones, so the honest differential is fully visible).
    """
    if not policy.checks:
        return []

    seed_ssrf_policy(graph, policy, target_base=target_base)

    if executor is None:
        host = urlsplit(
            target_base if "://" in target_base else f"http://{target_base}"
        ).netloc.lower()
        executor = SsrfProbeExecutor(allowed_hosts={host} if host else None)

    return investigate_ssrf(
        graph, executor=executor, collaborator=collaborator, rng=rng
    )
