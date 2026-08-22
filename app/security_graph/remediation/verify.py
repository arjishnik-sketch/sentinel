"""
PROVE — re-probe the confirmed authorization property through the live
enforcement shield and let the *same* deterministic judge decide.

The single hard rule of this module: it calls the PURE judge
(:func:`judge_authorization_validation`) only. It never calls
``apply_validation_judgment`` or ``materialize_confirmed_findings``, and it
never touches the real graph's hypotheses or findings. All fresh probe
state is written to a throwaway scratch graph seeded with only the policy
relationships the judge reads. A CONFIRMED finding therefore can never be
downgraded, and a FIX_PROVEN verdict can never be manufactured — it is
earned only when the judge, unchanged, now returns DISPROVED under
enforcement.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..execution.http import HttpAuthorizationExecutor
from ..graph import SecurityGraph
from ..models import Experiment, HttpRequestSpec, Hypothesis
from ..orchestration.observations import ingest_execution_observations
from ..validation_core import judge_authorization_validation
from .model import RemediationPlan, RemediationVerification


def _probe_experiment(
    *,
    hypothesis_id: str,
    tag: str,
    method: str,
    url: str,
    headers: tuple[tuple[str, str], ...],
    identity,
) -> Experiment:
    request = HttpRequestSpec(
        method=method,
        url=url,
        headers=tuple(headers),
        body=None,
        principal_id=identity.principal_id,
        resource_id=identity.resource_id,
        action=identity.action,
        expected_statuses=(),
        expected_outcome="deny",
    )
    return Experiment(
        id=f"exp:remediation:{tag}:{hypothesis_id}",
        hypothesis_id=hypothesis_id,
        kind="authorization_http_check",
        description=f"Remediation {tag}-enforcement re-probe.",
        status="PLANNED",
        request=request,
        capability_id="remediation.verification",
        action="verify_remediation",
    )


def _probe_and_judge(scratch, executor, hypothesis, experiment):
    """Mirror cycle._execute_experiment, then judge with the PURE judge."""
    scratch.add_experiment(experiment)

    result = executor.execute(experiment)

    for evidence in result.evidence:
        scratch.add_evidence(evidence)

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
    scratch.add_experiment(completed)

    ingest_execution_observations(scratch, result)

    judgment = judge_authorization_validation(
        scratch,
        hypothesis=hypothesis,
        experiment_id=experiment.id,
    )

    raw_code = dict(result.metadata).get("status_code")
    code = int(raw_code) if raw_code is not None else None
    return judgment, code


def verify_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: RemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    Probe the target directly (before) and through the enforcer (after),
    judging each with the pure deterministic judge. Proven iff the after
    judgment is DISPROVED.
    """
    identity = hypothesis.identity

    target_split = urlsplit(plan.target_url)
    path_with_query = target_split.path or "/"
    if target_split.query:
        path_with_query += "?" + target_split.query
    after_url = enforcer_base.rstrip("/") + path_with_query

    # Scratch graph carries ONLY the policy edges the judge reads, so the
    # real graph's confirmed state is untouchable from here.
    scratch = SecurityGraph()
    for relationship in graph.relationships:
        scratch.add_relationship(relationship)

    method = plan.rule.method
    headers = plan.rule.principal_headers

    before_exec = before_executor or HttpAuthorizationExecutor(
        allowed_hosts={target_split.netloc.lower()},
    )
    after_exec = after_executor or HttpAuthorizationExecutor(
        allowed_hosts={urlsplit(enforcer_base).netloc.lower()},
    )

    before_exp = _probe_experiment(
        hypothesis_id=hypothesis.id,
        tag="before",
        method=method,
        url=plan.target_url,
        headers=headers,
        identity=identity,
    )
    after_exp = _probe_experiment(
        hypothesis_id=hypothesis.id,
        tag="after",
        method=method,
        url=after_url,
        headers=headers,
        identity=identity,
    )

    before_judgment, before_code = _probe_and_judge(
        scratch, before_exec, hypothesis, before_exp
    )
    after_judgment, after_code = _probe_and_judge(
        scratch, after_exec, hypothesis, after_exp
    )

    proven = after_judgment.status == "DISPROVED"

    if proven:
        reason = (
            f"under enforcement the judge returned DISPROVED "
            f"(observed {after_code}); the confirmed contradiction no "
            f"longer reproduces"
        )
    else:
        reason = (
            f"under enforcement the judge returned {after_judgment.status} "
            f"(observed {after_code}); the contradiction still reproduces"
        )

    return RemediationVerification(
        experiment_id=after_exp.id,
        after_status=after_judgment.status,
        before_status=before_judgment.status,
        proven=proven,
        observed_status_code=after_code,
        before_status_code=before_code,
        reason=reason,
    )
