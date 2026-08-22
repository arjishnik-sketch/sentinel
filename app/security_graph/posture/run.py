"""
Drive the security-header posture prove-chain to a verdict.

This mirrors one authorization research cycle for every OPEN
`security_misconfiguration` hypothesis, but runs as a dedicated, isolated
pass so it never perturbs the ranking/decision engine that owns the proven
authorization flow. For each hypothesis it:

  * recovers the probe request template from the seed's declaration
    experiment,
  * executes the live header probe (reusing the header-capturing HTTP
    executor),
  * lets the PURE :func:`judge_header_posture` decide, and
  * applies the judgment (VALIDATED -> CONFIRMED) exactly as the cycle does.

Finally it materialises confirmed hypotheses into findings via the same
generic :func:`materialize_confirmed_findings`. A finding appears only when a
declared posture was genuinely contradicted by the live response.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..analysis import apply_validation_judgment, materialize_confirmed_findings
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, ValidationJudgment
from .executor import SecurityHeaderExecutor
from .header_policy import HeaderPolicy
from .judge import judge_header_posture
from .seed import seed_header_policy


@dataclass(frozen=True)
class PostureProbeResult:
    """What one header hypothesis resolved to, for honest rendering."""

    hypothesis_id: str
    experiment_id: str
    claim: str
    severity: str
    status: str            # judge status: VALIDATED / DISPROVED / INCONCLUSIVE
    status_code: int | None
    reason: str


def _declaration_request(graph: SecurityGraph, hypothesis: Hypothesis):
    """Recover the probe request template the seeder attached."""
    for experiment in graph.experiments_for(
        hypothesis_id=f"decl:{hypothesis.id}"
    ):
        if (
            experiment.kind == "security_header_declaration"
            and experiment.request is not None
        ):
            return experiment.request
    return None


def _severity_for(graph: SecurityGraph, hypothesis: Hypothesis) -> str:
    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return "MEDIUM"
    from .judge import header_posture_expectation

    expectation = header_posture_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    return expectation.severity if expectation is not None else "MEDIUM"


def _probe_and_judge(
    graph: SecurityGraph,
    executor,
    hypothesis: Hypothesis,
) -> tuple[ValidationJudgment | None, int | None]:
    request = _declaration_request(graph, hypothesis)
    if request is None:
        return None, None

    experiment = Experiment(
        id=f"exp:header-probe:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="security_header_check",
        description=f"Security-header posture probe for {hypothesis.id}.",
        status="PLANNED",
        request=request,
        capability_id="security_misconfiguration.header_check",
        action="validate_security_headers",
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

    judgment = judge_header_posture(
        graph,
        hypothesis=hypothesis,
        experiment_id=experiment.id,
    )

    raw_code = dict(result.metadata).get("status_code")
    code = int(raw_code) if raw_code is not None else None
    return judgment, code


def investigate_header_posture(
    graph: SecurityGraph,
    *,
    executor=None,
) -> list[PostureProbeResult]:
    """
    Probe → judge → confirm every OPEN `security_misconfiguration`
    hypothesis already seeded into the graph, then materialise findings.
    """
    hypotheses = sorted(
        graph.hypotheses_for(kind="security_misconfiguration", status="OPEN"),
        key=lambda item: item.id,
    )
    if not hypotheses:
        return []

    exec_ = executor or SecurityHeaderExecutor()

    results: list[PostureProbeResult] = []
    for hypothesis in hypotheses:
        severity = _severity_for(graph, hypothesis)
        judgment, code = _probe_and_judge(graph, exec_, hypothesis)

        if judgment is None:
            results.append(
                PostureProbeResult(
                    hypothesis_id=hypothesis.id,
                    experiment_id=f"exp:header-probe:{hypothesis.id}",
                    claim=hypothesis.claim,
                    severity=severity,
                    status="INCONCLUSIVE",
                    status_code=code,
                    reason="probe template unavailable",
                )
            )
            continue

        graph.add_validation_judgment(judgment)
        apply_validation_judgment(graph, judgment)

        results.append(
            PostureProbeResult(
                hypothesis_id=hypothesis.id,
                experiment_id=judgment.experiment_id,
                claim=hypothesis.claim,
                severity=severity,
                status=judgment.status,
                status_code=code,
                reason=judgment.reason,
            )
        )

    materialize_confirmed_findings(graph)
    return results


def run_posture_investigation(
    graph: SecurityGraph,
    policy: HeaderPolicy,
    *,
    target_base: str,
    executor=None,
) -> list[PostureProbeResult]:
    """
    Seed a header policy and run the full posture prove-chain.

    Live probing is bounded to the engagement host by default. Returns one
    :class:`PostureProbeResult` per hypothesis (including DISPROVED ones, so
    the "compliant control ⇒ no finding" differential is visible).
    """
    if not policy.rules:
        return []

    seed_header_policy(graph, policy, target_base=target_base)

    if executor is None:
        host = urlsplit(
            target_base if "://" in target_base else f"http://{target_base}"
        ).netloc.lower()
        executor = SecurityHeaderExecutor(
            allowed_hosts={host} if host else None
        )

    return investigate_header_posture(graph, executor=executor)
