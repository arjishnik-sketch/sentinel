"""
Drive the reflected-XSS prove-chain to a verdict.

Mirror of :mod:`app.security_graph.ssti.run`, but each OPEN `xss` hypothesis is
resolved with a **reflection differential** rather than an arithmetic one. For
each hypothesis it:

  * recovers the declared surface and the seeded benign marker the seeder wrote
    into the graph,
  * executes the live *control* probe (the bare marker, no markup) plus a set of
    *payload* probes (that same marker wrapped in each active-markup breakout
    shape), reusing the HTTP fact executor,
  * lets the PURE :func:`judge_reflected_xss` decide from the differential, and
  * applies the judgment (VALIDATED -> CONFIRMED) exactly as the cycle does.

Finally it materialises confirmed hypotheses into findings via the same generic
:func:`materialize_confirmed_findings`. A finding appears only when a live
payload provably reflected raw active markup (carrying our marker) un-escaped
while the control proved the app reflects the bare marker. This runner holds no
target-specific logic: it acts entirely on the recovered surface metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..analysis import apply_validation_judgment, materialize_confirmed_findings
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, ValidationJudgment
from .executor import XSSProbeExecutor
from .judge import XSSExpectation, xss_expectation, judge_reflected_xss
from .seed import seed_xss_policy
from .xss_policy import XSSPolicy, marker_payloads


@dataclass(frozen=True)
class XSSProbeResult:
    """What one reflected-XSS hypothesis resolved to, for rendering."""

    hypothesis_id: str
    experiment_id: str
    claim: str
    severity: str
    status: str            # judge status: VALIDATED / DISPROVED / INCONCLUSIVE
    param: str
    location: str
    control_status_code: int | None
    reason: str


def _expectation_for(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> XSSExpectation | None:
    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    return xss_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )


def _inject(
    expectation: XSSExpectation,
    value: str,
) -> tuple[str, str | None, tuple[tuple[str, str], ...]]:
    """
    Build (url, body, headers) that place `value` in the declared parameter.

    Pure and target-agnostic: the payload goes exactly where the operator said
    the parameter lives (query string / urlencoded body / JSON body).
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
    hypothesis: Hypothesis,
    expectation: XSSExpectation,
    *,
    tag: str,
    value: str,
) -> tuple[str, int | None]:
    """Build → execute → complete one probe. Returns (experiment_id, status)."""
    identity = hypothesis.identity
    url, body, headers = _inject(expectation, value)
    experiment = Experiment(
        id=f"exp:xss-{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="xss_check",
        description=f"XSS {tag} probe for {hypothesis.id}.",
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
        capability_id="xss.xss_check",
        action=f"probe_xss_{tag}",
    )
    graph.add_experiment(experiment)

    result = executor.execute(experiment)
    for evidence in result.evidence:
        graph.add_evidence(evidence)

    completed = Experiment(
        id=experiment.id,
        hypothesis_id=experiment.hypothesis_id,
        kind=experiment.kind,
        description=experiment.description,
        status=result.status,
        evidence_ids=tuple(evidence.id for evidence in result.evidence),
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
    hypothesis: Hypothesis,
) -> tuple[ValidationJudgment | None, int | None]:
    expectation = _expectation_for(graph, hypothesis)
    if expectation is None:
        return None, None

    control_id, control_code = _run_probe(
        graph, executor, hypothesis, expectation,
        tag="control", value=expectation.marker,
    )

    payload_ids: list[tuple[str, str]] = []
    for label, value in marker_payloads(expectation.marker):
        payload_id, _ = _run_probe(
            graph, executor, hypothesis, expectation,
            tag=f"payload-{label}", value=value,
        )
        payload_ids.append((label, payload_id))

    judgment = judge_reflected_xss(
        graph,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_ids=tuple(payload_ids),
    )
    return judgment, control_code


def investigate_xss(
    graph: SecurityGraph,
    *,
    executor=None,
) -> list[XSSProbeResult]:
    """
    Probe (control + breakout payloads) → judge → confirm every OPEN `xss`
    hypothesis, then materialise findings.
    """
    hypotheses = sorted(
        graph.hypotheses_for(kind="xss", status="OPEN"),
        key=lambda item: item.id,
    )
    if not hypotheses:
        return []

    exec_ = executor or XSSProbeExecutor()

    results: list[XSSProbeResult] = []
    for hypothesis in hypotheses:
        expectation = _expectation_for(graph, hypothesis)
        severity = expectation.severity if expectation is not None else "HIGH"
        param = expectation.param if expectation is not None else ""
        location = expectation.location if expectation is not None else ""

        judgment, control_code = _probe_and_judge(graph, exec_, hypothesis)

        if judgment is None:
            results.append(
                XSSProbeResult(
                    hypothesis_id=hypothesis.id,
                    experiment_id=f"exp:xss-control:{hypothesis.id}",
                    claim=hypothesis.claim,
                    severity=severity,
                    status="INCONCLUSIVE",
                    param=param,
                    location=location,
                    control_status_code=control_code,
                    reason="XSS surface metadata unavailable",
                )
            )
            continue

        graph.add_validation_judgment(judgment)
        apply_validation_judgment(graph, judgment)

        results.append(
            XSSProbeResult(
                hypothesis_id=hypothesis.id,
                experiment_id=judgment.experiment_id,
                claim=hypothesis.claim,
                severity=severity,
                status=judgment.status,
                param=param,
                location=location,
                control_status_code=control_code,
                reason=judgment.reason,
            )
        )

    materialize_confirmed_findings(graph)
    return results


def run_xss_investigation(
    graph: SecurityGraph,
    policy: XSSPolicy,
    *,
    target_base: str,
    executor=None,
) -> list[XSSProbeResult]:
    """
    Seed a reflected-XSS matrix and run the full XSS prove-chain.

    Live probing is bounded to the engagement host by default. Returns one
    :class:`XSSProbeResult` per hypothesis (including DISPROVED and INCONCLUSIVE
    ones, so the honest differential is fully visible).
    """
    if not policy.checks:
        return []

    seed_xss_policy(graph, policy, target_base=target_base)

    if executor is None:
        host = urlsplit(
            target_base if "://" in target_base else f"http://{target_base}"
        ).netloc.lower()
        executor = XSSProbeExecutor(allowed_hosts={host} if host else None)

    return investigate_xss(graph, executor=executor)
