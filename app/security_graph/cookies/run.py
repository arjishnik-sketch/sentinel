"""
Drive the insecure-cookie prove-chain to a verdict.

This mirrors one authorization research cycle for every OPEN `insecure_cookie`
hypothesis, but runs as a dedicated, isolated pass so it never perturbs the
ranking/decision engine that owns the proven authorization flow. For each
hypothesis it:

  * recovers the probe request template from the seed's declaration
    experiment,
  * executes the live cookie probe (reusing the Set-Cookie-capturing HTTP
    executor),
  * lets the PURE :func:`judge_cookie_posture` decide, and
  * applies the judgment (VALIDATED -> CONFIRMED) exactly as the cycle does.

Finally it materialises confirmed hypotheses into findings via the same
generic :func:`materialize_confirmed_findings`. A finding appears only when a
declared cookie posture was genuinely contradicted by a cookie the live target
actually set.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..analysis import apply_validation_judgment, materialize_confirmed_findings
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, ValidationJudgment
from .executor import CookieProbeExecutor
from .cookie_policy import CookiePolicy
from .judge import judge_cookie_posture
from .seed import seed_cookie_policy


@dataclass(frozen=True)
class CookieProbeResult:
    """What one cookie hypothesis resolved to, for honest rendering."""

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
            experiment.kind == "cookie_declaration"
            and experiment.request is not None
        ):
            return experiment.request
    return None


def _severity_for(graph: SecurityGraph, hypothesis: Hypothesis) -> str:
    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return "MEDIUM"
    from .judge import cookie_posture_expectation

    expectation = cookie_posture_expectation(
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
        id=f"exp:cookie-probe:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="cookie_check",
        description=f"Cookie-security posture probe for {hypothesis.id}.",
        status="PLANNED",
        request=request,
        capability_id="insecure_cookie.cookie_check",
        action="validate_cookie_security",
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

    judgment = judge_cookie_posture(
        graph,
        hypothesis=hypothesis,
        experiment_id=experiment.id,
    )

    raw_code = dict(result.metadata).get("status_code")
    code = int(raw_code) if raw_code is not None else None
    return judgment, code


def investigate_cookie_posture(
    graph: SecurityGraph,
    *,
    executor=None,
) -> list[CookieProbeResult]:
    """
    Probe → judge → confirm every OPEN `insecure_cookie` hypothesis already
    seeded into the graph, then materialise findings.
    """
    hypotheses = sorted(
        graph.hypotheses_for(kind="insecure_cookie", status="OPEN"),
        key=lambda item: item.id,
    )
    if not hypotheses:
        return []

    exec_ = executor or CookieProbeExecutor()

    results: list[CookieProbeResult] = []
    for hypothesis in hypotheses:
        severity = _severity_for(graph, hypothesis)
        judgment, code = _probe_and_judge(graph, exec_, hypothesis)

        if judgment is None:
            results.append(
                CookieProbeResult(
                    hypothesis_id=hypothesis.id,
                    experiment_id=f"exp:cookie-probe:{hypothesis.id}",
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
            CookieProbeResult(
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


def run_cookie_investigation(
    graph: SecurityGraph,
    policy: CookiePolicy,
    *,
    target_base: str,
    executor=None,
) -> list[CookieProbeResult]:
    """
    Seed a cookie policy and run the full insecure-cookie prove-chain.

    Live probing is bounded to the engagement host by default. Returns one
    :class:`CookieProbeResult` per hypothesis (including DISPROVED ones, so
    the "compliant / unset cookie ⇒ no finding" differential is visible).
    """
    if not policy.rules:
        return []

    seed_cookie_policy(graph, policy, target_base=target_base)

    if executor is None:
        host = urlsplit(
            target_base if "://" in target_base else f"http://{target_base}"
        ).netloc.lower()
        executor = CookieProbeExecutor(
            allowed_hosts={host} if host else None
        )

    return investigate_cookie_posture(graph, executor=executor)
