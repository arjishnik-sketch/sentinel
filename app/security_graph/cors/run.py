"""
Drive the CORS prove-chain to a verdict.

Mirror of :mod:`app.security_graph.open_redirect.run`, but each OPEN
`cors_misconfig` hypothesis is resolved with a **two-probe origin differential**
rather than a host one. For each hypothesis it:

  * recovers the declared surface and the seeded nonce origin the seeder wrote
    into the graph,
  * executes the live *control* anchor probe (the SAME request with NO ``Origin``
    header) plus the *payload* probe (the request carrying an ``Origin`` header
    naming the unroutable nonce origin), reusing the plain HTTP fact executor so
    every response header — including ``Access-Control-Allow-Origin`` and
    ``Access-Control-Allow-Credentials`` — is captured, never interpreted,
  * lets the PURE :func:`judge_cors` decide from the origin differential, and
  * applies the judgment (VALIDATED -> CONFIRMED) exactly as the cycle does.

Finally it materialises confirmed hypotheses into findings via the same generic
:func:`materialize_confirmed_findings`. A finding appears only when a live
payload probe provably reflected our attacker origin (the unforgeable nonce, or
``*``) AND allowed credentials AND the no-Origin control anchor proved the
reflection is origin-driven. This runner holds no target-specific logic: it acts
entirely on the recovered surface metadata. The nonce origin is only ever ECHOED
back by the server in a response header — Sentinel never contacts it.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..analysis import apply_validation_judgment, materialize_confirmed_findings
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, ValidationJudgment
from .cors_policy import CorsPolicy
from .executor import CorsProbeExecutor
from .judge import (
    CorsExpectation,
    cors_expectation,
    cors_response_headers,
    judge_cors,
)
from .seed import seed_cors_policy
@dataclass(frozen=True)
class CorsProbeResult:
    """What one CORS hypothesis resolved to, for rendering."""

    hypothesis_id: str
    experiment_id: str
    claim: str
    severity: str
    status: str            # judge status: VALIDATED / DISPROVED / INCONCLUSIVE
    method: str
    path: str
    payload_acao: str
    payload_acac: str
    control_acao: str
    reason: str


def _expectation_for(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> CorsExpectation | None:
    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    return cors_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )


def _run_probe(
    graph: SecurityGraph,
    executor,
    hypothesis: Hypothesis,
    expectation: CorsExpectation,
    *,
    tag: str,
    headers: tuple[tuple[str, str], ...],
) -> str:
    """Build → execute → complete one probe. Returns the experiment id.

    Both probes hit the SAME target endpoint with the SAME method — the ONLY
    difference is whether the payload's attacker ``Origin`` header is present.
    CORS is decided entirely by the response headers the executor captures.
    """
    identity = hypothesis.identity
    experiment = Experiment(
        id=f"exp:cors-{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="cors_check",
        description=f"CORS {tag} probe for {hypothesis.id}.",
        status="PLANNED",
        request=HttpRequestSpec(
            method=expectation.method,
            url=expectation.endpoint_url,
            headers=headers,
            body=None,
            principal_id=identity.principal_id,
            resource_id=identity.resource_id,
            action=identity.action,
        ),
        capability_id="cors.cors_check",
        action=f"probe_cors_{tag}",
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
    return experiment.id
def _probe_and_judge(
    graph: SecurityGraph,
    executor,
    hypothesis: Hypothesis,
) -> tuple[ValidationJudgment | None, tuple[str, str] | None, tuple[str, str] | None]:
    expectation = _expectation_for(graph, hypothesis)
    if expectation is None:
        return None, None, None

    # Control anchor: the SAME request with NO Origin header.
    control_id = _run_probe(
        graph, executor, hypothesis, expectation,
        tag="control", headers=(),
    )
    # Payload: the request carrying the attacker (nonce) Origin header.
    payload_id = _run_probe(
        graph, executor, hypothesis, expectation,
        tag="payload", headers=(("Origin", expectation.nonce_origin),),
    )

    judgment = judge_cors(
        graph,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_id=payload_id,
    )
    payload_headers = cors_response_headers(graph, payload_id)
    control_headers = cors_response_headers(graph, control_id)
    return judgment, payload_headers, control_headers


def investigate_cors(
    graph: SecurityGraph,
    *,
    executor=None,
) -> list[CorsProbeResult]:
    """
    Probe (no-Origin control + attacker-Origin payload) → judge → confirm every
    OPEN `cors_misconfig` hypothesis, then materialise findings.
    """
    hypotheses = sorted(
        graph.hypotheses_for(kind="cors_misconfig", status="OPEN"),
        key=lambda item: item.id,
    )
    if not hypotheses:
        return []

    exec_ = executor or CorsProbeExecutor()

    results: list[CorsProbeResult] = []
    for hypothesis in hypotheses:
        expectation = _expectation_for(graph, hypothesis)
        severity = expectation.severity if expectation is not None else "MEDIUM"
        method = expectation.method if expectation is not None else ""
        path = expectation.path if expectation is not None else ""

        judgment, payload_headers, control_headers = _probe_and_judge(
            graph, exec_, hypothesis
        )

        payload_acao = payload_headers[0] if payload_headers is not None else ""
        payload_acac = payload_headers[1] if payload_headers is not None else ""
        control_acao = control_headers[0] if control_headers is not None else ""

        if judgment is None:
            results.append(
                CorsProbeResult(
                    hypothesis_id=hypothesis.id,
                    experiment_id=f"exp:cors-payload:{hypothesis.id}",
                    claim=hypothesis.claim,
                    severity=severity,
                    status="INCONCLUSIVE",
                    method=method,
                    path=path,
                    payload_acao=payload_acao,
                    payload_acac=payload_acac,
                    control_acao=control_acao,
                    reason="CORS surface metadata unavailable",
                )
            )
            continue

        graph.add_validation_judgment(judgment)
        apply_validation_judgment(graph, judgment)

        results.append(
            CorsProbeResult(
                hypothesis_id=hypothesis.id,
                experiment_id=judgment.experiment_id,
                claim=hypothesis.claim,
                severity=severity,
                status=judgment.status,
                method=method,
                path=path,
                payload_acao=payload_acao,
                payload_acac=payload_acac,
                control_acao=control_acao,
                reason=judgment.reason,
            )
        )

    materialize_confirmed_findings(graph)
    return results
def run_cors_investigation(
    graph: SecurityGraph,
    policy: CorsPolicy,
    *,
    target_base: str,
    executor=None,
) -> list[CorsProbeResult]:
    """
    Seed a CORS matrix and run the full CORS prove-chain.

    Live probing is bounded to the engagement host by default. Returns one
    :class:`CorsProbeResult` per hypothesis (including DISPROVED and INCONCLUSIVE
    ones, so the honest differential is fully visible).
    """
    if not policy.checks:
        return []

    seed_cors_policy(graph, policy, target_base=target_base)

    if executor is None:
        host = urlsplit(
            target_base if "://" in target_base else f"http://{target_base}"
        ).netloc.lower()
        executor = CorsProbeExecutor(allowed_hosts={host} if host else None)

    return investigate_cors(graph, executor=executor)



