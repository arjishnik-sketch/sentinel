"""
Drive the privilege-escalation prove-chain to a verdict.

Mirror of :mod:`app.security_graph.cookies.run`, but each OPEN
`privilege_escalation` hypothesis is resolved with a **three-probe differential**
rather than a single probe. For each hypothesis it:

  * recovers the declared boundary (attacker session headers, the control URL
    and the forbidden breach URL) the seeder wrote into the graph,
  * executes the live *control* probe (attacker → its own object), the live
    *breach* probe (attacker → the forbidden object/function), and an anonymous
    *baseline* probe (the SAME breach request with NO session), reusing the
    HTTP fact executor,
  * lets the PURE :func:`judge_privilege_escalation` decide from the
    control/breach/baseline differential, and
  * applies the judgment (VALIDATED -> CONFIRMED) exactly as the cycle does.

Finally it materialises confirmed hypotheses into findings via the same generic
:func:`materialize_confirmed_findings`. A finding appears only when a live
session provably crossed a declared privilege boundary. This runner holds no
target-specific logic: it acts entirely on the recovered boundary metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..analysis import apply_validation_judgment, materialize_confirmed_findings
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, ValidationJudgment
from .executor import PrivEscProbeExecutor
from .judge import PrivEscExpectation, judge_privilege_escalation, privesc_expectation
from .privesc_policy import PrivEscPolicy
from .seed import seed_privesc_policy


@dataclass(frozen=True)
class PrivEscProbeResult:
    """What one privilege-escalation hypothesis resolved to, for rendering."""

    hypothesis_id: str
    experiment_id: str
    claim: str
    severity: str
    status: str            # judge status: VALIDATED / DISPROVED / INCONCLUSIVE
    control_status_code: int | None
    breach_status_code: int | None
    reason: str
    baseline_status_code: int | None = None


def _expectation_for(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> PrivEscExpectation | None:
    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    return privesc_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )


def _attacker_headers(graph: SecurityGraph, hypothesis: Hypothesis):
    """Recover the attacker session headers from the declaration experiment."""
    for experiment in graph.experiments_for(hypothesis_id=f"decl:{hypothesis.id}"):
        if (
            experiment.kind == "privilege_escalation_declaration"
            and experiment.request is not None
        ):
            return experiment.request.headers
    return ()


def _run_probe(
    graph: SecurityGraph,
    executor,
    hypothesis: Hypothesis,
    *,
    tag: str,
    method: str,
    url: str,
    headers,
    identity,
) -> tuple[str, int | None]:
    """Build → execute → complete one probe. Returns (experiment_id, status)."""
    experiment = Experiment(
        id=f"exp:privesc-{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="privilege_escalation_check",
        description=f"Privilege-escalation {tag} probe for {hypothesis.id}.",
        status="PLANNED",
        request=HttpRequestSpec(
            method=method,
            url=url,
            headers=tuple(headers),
            body=None,
            principal_id=identity.principal_id,
            resource_id=identity.resource_id,
            action=identity.action,
        ),
        capability_id="privilege_escalation.privesc_check",
        action=f"probe_privilege_escalation_{tag}",
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
) -> tuple[ValidationJudgment | None, int | None, int | None, int | None]:
    expectation = _expectation_for(graph, hypothesis)
    if expectation is None:
        return None, None, None, None

    identity = hypothesis.identity
    headers = _attacker_headers(graph, hypothesis)

    control_id, control_code = _run_probe(
        graph,
        executor,
        hypothesis,
        tag="control",
        method=expectation.control_method,
        url=expectation.control_url,
        headers=headers,
        identity=identity,
    )
    breach_id, breach_code = _run_probe(
        graph,
        executor,
        hypothesis,
        tag="breach",
        method=expectation.breach_method,
        url=expectation.breach_url,
        headers=headers,
        identity=identity,
    )
    # Anonymous NEGATIVE control: the SAME breach route with NO session. If an
    # unauthenticated caller is also granted it, the route is public / the app
    # 200s everything, and the attacker's grant proves nothing — the pure judge
    # then returns INCONCLUSIVE rather than manufacturing a finding.
    baseline_id, baseline_code = _run_probe(
        graph,
        executor,
        hypothesis,
        tag="baseline",
        method=expectation.breach_method,
        url=expectation.breach_url,
        headers=(),
        identity=identity,
    )

    judgment = judge_privilege_escalation(
        graph,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        breach_experiment_id=breach_id,
        baseline_experiment_id=baseline_id,
    )
    return judgment, control_code, breach_code, baseline_code


def investigate_privilege_escalation(
    graph: SecurityGraph,
    *,
    executor=None,
) -> list[PrivEscProbeResult]:
    """
    Probe (control + breach) → judge → confirm every OPEN
    `privilege_escalation` hypothesis, then materialise findings.
    """
    hypotheses = sorted(
        graph.hypotheses_for(kind="privilege_escalation", status="OPEN"),
        key=lambda item: item.id,
    )
    if not hypotheses:
        return []

    exec_ = executor or PrivEscProbeExecutor()

    results: list[PrivEscProbeResult] = []
    for hypothesis in hypotheses:
        expectation = _expectation_for(graph, hypothesis)
        severity = expectation.severity if expectation is not None else "HIGH"

        judgment, control_code, breach_code, baseline_code = _probe_and_judge(
            graph, exec_, hypothesis
        )

        if judgment is None:
            results.append(
                PrivEscProbeResult(
                    hypothesis_id=hypothesis.id,
                    experiment_id=f"exp:privesc-breach:{hypothesis.id}",
                    claim=hypothesis.claim,
                    severity=severity,
                    status="INCONCLUSIVE",
                    control_status_code=control_code,
                    breach_status_code=breach_code,
                    reason="privilege boundary metadata unavailable",
                    baseline_status_code=baseline_code,
                )
            )
            continue

        graph.add_validation_judgment(judgment)
        apply_validation_judgment(graph, judgment)

        results.append(
            PrivEscProbeResult(
                hypothesis_id=hypothesis.id,
                experiment_id=judgment.experiment_id,
                claim=hypothesis.claim,
                severity=severity,
                status=judgment.status,
                control_status_code=control_code,
                breach_status_code=breach_code,
                reason=judgment.reason,
                baseline_status_code=baseline_code,
            )
        )

    materialize_confirmed_findings(graph)
    return results


def run_privesc_investigation(
    graph: SecurityGraph,
    policy: PrivEscPolicy,
    *,
    target_base: str,
    executor=None,
) -> list[PrivEscProbeResult]:
    """
    Seed a login matrix and run the full privilege-escalation prove-chain.

    Live probing is bounded to the engagement host by default. Returns one
    :class:`PrivEscProbeResult` per hypothesis (including DISPROVED and
    INCONCLUSIVE ones, so the honest differential is fully visible).
    """
    if not policy.checks:
        return []

    seed_privesc_policy(graph, policy, target_base=target_base)

    if executor is None:
        host = urlsplit(
            target_base if "://" in target_base else f"http://{target_base}"
        ).netloc.lower()
        executor = PrivEscProbeExecutor(allowed_hosts={host} if host else None)

    return investigate_privilege_escalation(graph, executor=executor)
