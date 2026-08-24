"""
Drive the broken-authentication prove-chain to a verdict.

Mirror of :mod:`app.security_graph.privesc.run`: each OPEN ``broken_auth``
hypothesis is resolved with a **three-probe differential**. For each hypothesis
it:

  * recovers the declared boundary (the genuine-token control headers, the
    forged-token breach headers, and the protected route) the seeder wrote,
  * executes the live *control* probe (genuine token → must be accepted, proving
    the route is token-authenticated and the session valid), the live *breach*
    probe (forged token → the validation-flaw probe), and an anonymous
    *baseline* probe (NO token → must be denied), reusing the HTTP fact executor,
  * lets the PURE :func:`judge_broken_auth` decide from the differential, and
  * applies the judgment (VALIDATED -> CONFIRMED) exactly as the cycle does.

Finally it materialises confirmed hypotheses into findings via the same generic
:func:`materialize_confirmed_findings`. A finding appears only when a forged
token is provably accepted where the genuine token works and anonymous is
denied. This runner holds no target-specific logic.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import urlsplit

from ..analysis import apply_validation_judgment, materialize_confirmed_findings
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, ValidationJudgment
from .executor import BrokenAuthProbeExecutor
from .judge import (
    BrokenAuthExpectation,
    broken_auth_expectation,
    judge_broken_auth,
)
from .broken_auth_policy import BrokenAuthPolicy
from .seed import seed_broken_auth_policy

@dataclass(frozen=True)
class BrokenAuthProbeResult:
    """What one broken-authentication hypothesis resolved to, for rendering."""

    hypothesis_id: str
    experiment_id: str
    claim: str
    severity: str
    status: str            # judge status: VALIDATED / DISPROVED / INCONCLUSIVE
    forgery: str
    guard_provable: bool
    control_status_code: int | None
    breach_status_code: int | None
    reason: str
    baseline_status_code: int | None = None


def _expectation_for(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> BrokenAuthExpectation | None:
    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    return broken_auth_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )


def _decode_headers(raw: str) -> tuple[tuple[str, str], ...]:
    """Decode a JSON header list ([[name, value], ...]) into a header tuple."""
    try:
        data = json.loads(raw) if raw else []
    except (ValueError, TypeError):
        return ()
    out: list[tuple[str, str]] = []
    for pair in data:
        try:
            name, value = pair
        except (ValueError, TypeError):
            continue
        out.append((str(name), str(value)))
    return tuple(out)


def _probe_headers(graph: SecurityGraph, hypothesis: Hypothesis):
    """Recover (control_headers, breach_headers) from the boundary relationship.

    The seeder wrote both header sets into the ``requires_authentic_token``
    edge's metadata precisely so this runner can rebuild the two authenticated
    probes without re-deriving the forgery (which stays PURE in :mod:`.forge`).
    """
    identity = hypothesis.identity
    if identity is None or not identity.action:
        return (), ()
    target = f"broken_auth:{identity.action}"
    for relationship in graph.relationships:
        if (
            relationship.source == identity.resource_id
            and relationship.relation == "requires_authentic_token"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            return (
                _decode_headers(meta.get("control_headers", "")),
                _decode_headers(meta.get("breach_headers", "")),
            )
    return (), ()


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
        id=f"exp:broken-auth-{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="broken_auth_check",
        description=f"Broken-authentication {tag} probe for {hypothesis.id}.",
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
        capability_id="broken_auth.broken_auth_check",
        action=f"probe_broken_auth_{tag}",
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
    control_headers, breach_headers = _probe_headers(graph, hypothesis)

    # Control: the GENUINE captured token as the SOLE authenticator — MUST be
    # accepted, proving the route is token-authenticated and the session live.
    control_id, control_code = _run_probe(
        graph,
        executor,
        hypothesis,
        tag="control",
        method=expectation.method,
        url=expectation.breach_url,
        headers=control_headers,
        identity=identity,
    )
    # Breach: a FORGED token as the SOLE authenticator — the validation-flaw
    # probe. Acceptance here (with control accepted, baseline denied) is the flaw.
    breach_id, breach_code = _run_probe(
        graph,
        executor,
        hypothesis,
        tag="breach",
        method=expectation.method,
        url=expectation.breach_url,
        headers=breach_headers,
        identity=identity,
    )
    # Anonymous NEGATIVE control: the SAME route with NO Authorization header. If
    # an unauthenticated caller is also accepted, the route is public and the
    # forged-token grant proves nothing — the pure judge returns INCONCLUSIVE.
    baseline_id, baseline_code = _run_probe(
        graph,
        executor,
        hypothesis,
        tag="baseline",
        method=expectation.method,
        url=expectation.breach_url,
        headers=(),
        identity=identity,
    )

    judgment = judge_broken_auth(
        graph,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        breach_experiment_id=breach_id,
        baseline_experiment_id=baseline_id,
    )
    return judgment, control_code, breach_code, baseline_code


def investigate_broken_auth(
    graph: SecurityGraph,
    *,
    executor=None,
) -> list[BrokenAuthProbeResult]:
    """
    Probe (control + breach + baseline) → judge → confirm every OPEN
    ``broken_auth`` hypothesis, then materialise findings.
    """
    hypotheses = sorted(
        graph.hypotheses_for(kind="broken_auth", status="OPEN"),
        key=lambda item: item.id,
    )
    if not hypotheses:
        return []

    exec_ = executor or BrokenAuthProbeExecutor()

    results: list[BrokenAuthProbeResult] = []
    for hypothesis in hypotheses:
        expectation = _expectation_for(graph, hypothesis)
        severity = expectation.severity if expectation is not None else "HIGH"
        forgery = expectation.forgery if expectation is not None else ""
        guard_provable = (
            expectation.guard_provable if expectation is not None else False
        )

        judgment, control_code, breach_code, baseline_code = _probe_and_judge(
            graph, exec_, hypothesis
        )

        if judgment is None:
            results.append(
                BrokenAuthProbeResult(
                    hypothesis_id=hypothesis.id,
                    experiment_id=f"exp:broken-auth-breach:{hypothesis.id}",
                    claim=hypothesis.claim,
                    severity=severity,
                    status="INCONCLUSIVE",
                    forgery=forgery,
                    guard_provable=guard_provable,
                    control_status_code=control_code,
                    breach_status_code=breach_code,
                    reason="token-authentication boundary metadata unavailable",
                    baseline_status_code=baseline_code,
                )
            )
            continue

        graph.add_validation_judgment(judgment)
        apply_validation_judgment(graph, judgment)

        results.append(
            BrokenAuthProbeResult(
                hypothesis_id=hypothesis.id,
                experiment_id=judgment.experiment_id,
                claim=hypothesis.claim,
                severity=severity,
                status=judgment.status,
                forgery=forgery,
                guard_provable=guard_provable,
                control_status_code=control_code,
                breach_status_code=breach_code,
                reason=judgment.reason,
                baseline_status_code=baseline_code,
            )
        )

    materialize_confirmed_findings(graph)
    return results


def run_broken_auth_investigation(
    graph: SecurityGraph,
    policy: BrokenAuthPolicy,
    *,
    target_base: str,
    executor=None,
) -> list[BrokenAuthProbeResult]:
    """
    Seed a token-forgery matrix and run the full broken-authentication chain.

    Live probing is bounded to the engagement host by default. Returns one
    :class:`BrokenAuthProbeResult` per hypothesis (including DISPROVED and
    INCONCLUSIVE ones, so the honest differential is fully visible).
    """
    if not policy.checks:
        return []

    seed_broken_auth_policy(graph, policy, target_base=target_base)

    if executor is None:
        host = urlsplit(
            target_base if "://" in target_base else f"http://{target_base}"
        ).netloc.lower()
        executor = BrokenAuthProbeExecutor(allowed_hosts={host} if host else None)

    return investigate_broken_auth(graph, executor=executor)



