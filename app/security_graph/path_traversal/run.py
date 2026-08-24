"""
Drive the path-traversal / LFI prove-chain to a verdict.

Mirror of :mod:`app.security_graph.xss.run`, but each OPEN `path_traversal`
hypothesis is resolved with an **OS-canary differential** rather than a
reflection one. For each hypothesis it:

  * recovers the declared surface and the fixed benign control filename,
  * executes the live *control* probe (the benign, traversal-free filename) plus
    the fixed ladder of *payload* probes (directory-escape shapes aimed at
    cross-OS canary files), reusing the HTTP fact executor,
  * lets the PURE :func:`judge_path_traversal` decide from the differential, and
  * applies the judgment (VALIDATED -> CONFIRMED) exactly as the cycle does.

Finally it materialises confirmed hypotheses into findings via the same generic
:func:`materialize_confirmed_findings`. A finding appears only when a live
payload provably leaked an OS-file invariant absent from the benign control.
This runner holds no target-specific logic: it acts entirely on the recovered
surface metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..analysis import apply_validation_judgment, materialize_confirmed_findings
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, ValidationJudgment
from .executor import PathTraversalProbeExecutor
from .judge import (
    TraversalExpectation,
    traversal_expectation,
    judge_path_traversal,
)
from .seed import seed_path_traversal_policy
from .traversal_policy import TraversalPolicy, traversal_payloads


@dataclass(frozen=True)
class PathTraversalProbeResult:
    """What one path-traversal hypothesis resolved to, for rendering."""

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
) -> TraversalExpectation | None:
    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    return traversal_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )


def _inject(
    expectation: TraversalExpectation,
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
    expectation: TraversalExpectation,
    *,
    tag: str,
    value: str,
) -> tuple[str, int | None]:
    """Build → execute → complete one probe. Returns (experiment_id, status)."""
    identity = hypothesis.identity
    url, body, headers = _inject(expectation, value)
    experiment = Experiment(
        id=f"exp:traversal-{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="path_traversal_check",
        description=f"Path-traversal {tag} probe for {hypothesis.id}.",
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
        capability_id="path_traversal.traversal_check",
        action=f"probe_traversal_{tag}",
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
        tag="control", value=expectation.control_value,
    )

    payload_ids: list[tuple[str, str]] = []
    for label, value in traversal_payloads():
        payload_id, _ = _run_probe(
            graph, executor, hypothesis, expectation,
            tag=f"payload-{label}", value=value,
        )
        payload_ids.append((label, payload_id))

    judgment = judge_path_traversal(
        graph,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_ids=tuple(payload_ids),
    )
    return judgment, control_code
def investigate_path_traversal(
    graph: SecurityGraph,
    *,
    executor=None,
) -> list[PathTraversalProbeResult]:
    """
    Probe (control + escape payloads) → judge → confirm every OPEN
    `path_traversal` hypothesis, then materialise findings.
    """
    hypotheses = sorted(
        graph.hypotheses_for(kind="path_traversal", status="OPEN"),
        key=lambda item: item.id,
    )
    if not hypotheses:
        return []

    exec_ = executor or PathTraversalProbeExecutor()

    results: list[PathTraversalProbeResult] = []
    for hypothesis in hypotheses:
        expectation = _expectation_for(graph, hypothesis)
        severity = expectation.severity if expectation is not None else "HIGH"
        param = expectation.param if expectation is not None else ""
        location = expectation.location if expectation is not None else ""

        judgment, control_code = _probe_and_judge(graph, exec_, hypothesis)

        if judgment is None:
            results.append(
                PathTraversalProbeResult(
                    hypothesis_id=hypothesis.id,
                    experiment_id=f"exp:traversal-control:{hypothesis.id}",
                    claim=hypothesis.claim,
                    severity=severity,
                    status="INCONCLUSIVE",
                    param=param,
                    location=location,
                    control_status_code=control_code,
                    reason="path-traversal surface metadata unavailable",
                )
            )
            continue

        graph.add_validation_judgment(judgment)
        apply_validation_judgment(graph, judgment)

        results.append(
            PathTraversalProbeResult(
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
def run_path_traversal_investigation(
    graph: SecurityGraph,
    policy: TraversalPolicy,
    *,
    target_base: str,
    executor=None,
) -> list[PathTraversalProbeResult]:
    """
    Seed a path-traversal matrix and run the full prove-chain.

    Live probing is bounded to the engagement host by default. Returns one
    :class:`PathTraversalProbeResult` per hypothesis (including DISPROVED and
    INCONCLUSIVE ones, so the honest differential is fully visible).
    """
    if not policy.checks:
        return []

    seed_path_traversal_policy(graph, policy, target_base=target_base)

    if executor is None:
        host = urlsplit(
            target_base if "://" in target_base else f"http://{target_base}"
        ).netloc.lower()
        executor = PathTraversalProbeExecutor(
            allowed_hosts={host} if host else None
        )

    return investigate_path_traversal(graph, executor=executor)
