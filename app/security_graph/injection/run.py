"""
Drive the injection prove-chain to a verdict.

Mirror of :mod:`app.security_graph.privesc.run`, but each OPEN `injection`
hypothesis is resolved with a **three-way boolean differential** rather than a
control/breach differential. For each hypothesis it:

  * recovers the declared injectable surface (method, path, param, location and
    the benign baseline value) the seeder wrote into the graph,
  * executes the live *baseline* probe (the benign value) plus a ladder of
    length-matched (TRUE, FALSE) boolean probe pairs, reusing the HTTP fact
    executor,
  * lets the PURE :func:`judge_injection` decide from the differential, and
  * applies the judgment (VALIDATED -> CONFIRMED) exactly as the cycle does.

Finally it materialises confirmed hypotheses into findings via the same generic
:func:`materialize_confirmed_findings`. A finding appears only when a live
boolean payload provably toggled the backend query. This runner holds no
target-specific logic: it acts entirely on the recovered surface metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..analysis import apply_validation_judgment, materialize_confirmed_findings
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, ValidationJudgment
from .executor import InjectionProbeExecutor
from .injection_policy import InjectionPolicy, boolean_payload_pairs, quote_parity_payloads
from .judge import InjectionExpectation, injection_expectation, judge_injection
from .seed import seed_injection_policy


@dataclass(frozen=True)
class InjectionProbeResult:
    """What one injection hypothesis resolved to, for rendering."""

    hypothesis_id: str
    experiment_id: str
    claim: str
    severity: str
    status: str            # judge status: VALIDATED / DISPROVED / INCONCLUSIVE
    param: str
    location: str
    baseline_status_code: int | None
    reason: str


def _expectation_for(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> InjectionExpectation | None:
    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    return injection_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )


def _inject(
    expectation: InjectionExpectation,
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
    expectation: InjectionExpectation,
    *,
    tag: str,
    value: str,
) -> tuple[str, int | None]:
    """Build → execute → complete one probe. Returns (experiment_id, status)."""
    identity = hypothesis.identity
    url, body, headers = _inject(expectation, value)
    experiment = Experiment(
        id=f"exp:injection-{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="injection_check",
        description=f"Injection {tag} probe for {hypothesis.id}.",
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
        capability_id="injection.injection_check",
        action=f"probe_injection_{tag}",
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

    baseline_id, baseline_code = _run_probe(
        graph, executor, hypothesis, expectation,
        tag="baseline", value=expectation.baseline_value,
    )

    pairs, _ = boolean_payload_pairs(expectation.baseline_value)
    pair_ids: list[tuple[str, str]] = []
    for index, (true_value, false_value) in enumerate(pairs):
        true_id, _ = _run_probe(
            graph, executor, hypothesis, expectation,
            tag=f"true-{index}", value=true_value,
        )
        false_id, _ = _run_probe(
            graph, executor, hypothesis, expectation,
            tag=f"false-{index}", value=false_value,
        )
        pair_ids.append((true_id, false_id))

    # Error-based (quote-parity) probes: odd-quote (breaks a SQL string literal)
    # vs balanced even-quote (restores it). The judge uses these only if no
    # boolean pair toggled, so a parameter interpolated into a string literal
    # (the common case a single-point boolean payload misses) is still provable.
    parity_ids: list[tuple[str, str]] = []
    for index, (odd_value, even_value) in enumerate(
        quote_parity_payloads(expectation.baseline_value)
    ):
        odd_id, _ = _run_probe(
            graph, executor, hypothesis, expectation,
            tag=f"oddquote-{index}", value=odd_value,
        )
        even_id, _ = _run_probe(
            graph, executor, hypothesis, expectation,
            tag=f"evenquote-{index}", value=even_value,
        )
        parity_ids.append((odd_id, even_id))

    judgment = judge_injection(
        graph,
        hypothesis=hypothesis,
        baseline_experiment_id=baseline_id,
        pair_experiment_ids=tuple(pair_ids),
        parity_experiment_ids=tuple(parity_ids),
    )
    return judgment, baseline_code


def investigate_injection(
    graph: SecurityGraph,
    *,
    executor=None,
) -> list[InjectionProbeResult]:
    """
    Probe (baseline + boolean pairs) → judge → confirm every OPEN `injection`
    hypothesis, then materialise findings.
    """
    hypotheses = sorted(
        graph.hypotheses_for(kind="injection", status="OPEN"),
        key=lambda item: item.id,
    )
    if not hypotheses:
        return []

    exec_ = executor or InjectionProbeExecutor()

    results: list[InjectionProbeResult] = []
    for hypothesis in hypotheses:
        expectation = _expectation_for(graph, hypothesis)
        severity = expectation.severity if expectation is not None else "HIGH"
        param = expectation.param if expectation is not None else ""
        location = expectation.location if expectation is not None else ""

        judgment, baseline_code = _probe_and_judge(graph, exec_, hypothesis)

        if judgment is None:
            results.append(
                InjectionProbeResult(
                    hypothesis_id=hypothesis.id,
                    experiment_id=f"exp:injection-baseline:{hypothesis.id}",
                    claim=hypothesis.claim,
                    severity=severity,
                    status="INCONCLUSIVE",
                    param=param,
                    location=location,
                    baseline_status_code=baseline_code,
                    reason="injectable surface metadata unavailable",
                )
            )
            continue

        graph.add_validation_judgment(judgment)
        apply_validation_judgment(graph, judgment)

        results.append(
            InjectionProbeResult(
                hypothesis_id=hypothesis.id,
                experiment_id=judgment.experiment_id,
                claim=hypothesis.claim,
                severity=severity,
                status=judgment.status,
                param=param,
                location=location,
                baseline_status_code=baseline_code,
                reason=judgment.reason,
            )
        )

    materialize_confirmed_findings(graph)
    return results


def run_injection_investigation(
    graph: SecurityGraph,
    policy: InjectionPolicy,
    *,
    target_base: str,
    executor=None,
) -> list[InjectionProbeResult]:
    """
    Seed an injection matrix and run the full injection prove-chain.

    Live probing is bounded to the engagement host by default. Returns one
    :class:`InjectionProbeResult` per hypothesis (including DISPROVED and
    INCONCLUSIVE ones, so the honest differential is fully visible).
    """
    if not policy.checks:
        return []

    seed_injection_policy(graph, policy, target_base=target_base)

    if executor is None:
        host = urlsplit(
            target_base if "://" in target_base else f"http://{target_base}"
        ).netloc.lower()
        executor = InjectionProbeExecutor(allowed_hosts={host} if host else None)

    return investigate_injection(graph, executor=executor)
