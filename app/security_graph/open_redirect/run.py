"""
Drive the open-redirect prove-chain to a verdict.

Mirror of :mod:`app.security_graph.ssti.run`, but each OPEN `open_redirect`
hypothesis is resolved with a **two-probe host differential** rather than an
arithmetic one. For each hypothesis it:

  * recovers the declared surface and the seeded probe operands (the off-origin
    ``payload_url`` on the unforgeable nonce host, and the same-origin
    ``control_url`` anchor) the seeder wrote into the graph,
  * executes the live *control* anchor probe (the parameter set to the target's
    own origin) plus the *payload* probe (the parameter set to the off-origin
    nonce URL), reusing the NO-FOLLOW HTTP fact executor so the ``Location``
    header is OBSERVED, never followed,
  * lets the PURE :func:`judge_open_redirect` decide from the host differential,
    and
  * applies the judgment (VALIDATED -> CONFIRMED) exactly as the cycle does.

Finally it materialises confirmed hypotheses into findings via the same generic
:func:`materialize_confirmed_findings`. A finding appears only when a live
off-origin payload provably redirected to the nonce host while the same-origin
control anchor proved the endpoint legitimately redirects on-origin. This runner
holds no target-specific logic: it acts entirely on the recovered surface
metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..analysis import apply_validation_judgment, materialize_confirmed_findings
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, ValidationJudgment
from .executor import OpenRedirectProbeExecutor
from .judge import (
    OpenRedirectExpectation,
    open_redirect_expectation,
    judge_open_redirect,
)
from .open_redirect_policy import OpenRedirectPolicy
from .seed import seed_open_redirect_policy


@dataclass(frozen=True)
class OpenRedirectProbeResult:
    """What one open-redirect hypothesis resolved to, for rendering."""

    hypothesis_id: str
    experiment_id: str
    claim: str
    severity: str
    status: str            # judge status: VALIDATED / DISPROVED / INCONCLUSIVE
    param: str
    location: str
    payload_status_code: int | None
    control_status_code: int | None
    reason: str


def _expectation_for(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> OpenRedirectExpectation | None:
    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    return open_redirect_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )


def _inject(
    expectation: OpenRedirectExpectation,
    value: str,
) -> tuple[str, str | None, tuple[tuple[str, str], ...]]:
    """
    Build (url, body, headers) that place `value` in the declared parameter.

    Pure and target-agnostic: the redirect-destination value goes exactly where
    the operator said the parameter lives (query string / urlencoded body / JSON
    body). The request URL is ALWAYS on the target — only the parameter value
    names the off-origin nonce host, and (thanks to no-follow) it is never fetched.
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
    expectation: OpenRedirectExpectation,
    *,
    tag: str,
    value: str,
) -> tuple[str, int | None]:
    """Build → execute → complete one probe. Returns (experiment_id, status)."""
    identity = hypothesis.identity
    url, body, headers = _inject(expectation, value)
    experiment = Experiment(
        id=f"exp:open-redirect-{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="open_redirect_check",
        description=f"open-redirect {tag} probe for {hypothesis.id}.",
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
        capability_id="open_redirect.open_redirect_check",
        action=f"probe_open_redirect_{tag}",
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
) -> tuple[ValidationJudgment | None, int | None, int | None]:
    expectation = _expectation_for(graph, hypothesis)
    if expectation is None:
        return None, None, None

    control_id, control_code = _run_probe(
        graph, executor, hypothesis, expectation,
        tag="control", value=expectation.control_url,
    )
    payload_id, payload_code = _run_probe(
        graph, executor, hypothesis, expectation,
        tag="payload", value=expectation.payload_url,
    )

    judgment = judge_open_redirect(
        graph,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_id=payload_id,
    )
    return judgment, control_code, payload_code


def investigate_open_redirect(
    graph: SecurityGraph,
    *,
    executor=None,
) -> list[OpenRedirectProbeResult]:
    """
    Probe (off-origin payload + same-origin control) → judge → confirm every OPEN
    `open_redirect` hypothesis, then materialise findings.
    """
    hypotheses = sorted(
        graph.hypotheses_for(kind="open_redirect", status="OPEN"),
        key=lambda item: item.id,
    )
    if not hypotheses:
        return []

    exec_ = executor or OpenRedirectProbeExecutor()

    results: list[OpenRedirectProbeResult] = []
    for hypothesis in hypotheses:
        expectation = _expectation_for(graph, hypothesis)
        severity = expectation.severity if expectation is not None else "MEDIUM"
        param = expectation.param if expectation is not None else ""
        location = expectation.location if expectation is not None else ""

        judgment, control_code, payload_code = _probe_and_judge(
            graph, exec_, hypothesis
        )

        if judgment is None:
            results.append(
                OpenRedirectProbeResult(
                    hypothesis_id=hypothesis.id,
                    experiment_id=f"exp:open-redirect-payload:{hypothesis.id}",
                    claim=hypothesis.claim,
                    severity=severity,
                    status="INCONCLUSIVE",
                    param=param,
                    location=location,
                    payload_status_code=payload_code,
                    control_status_code=control_code,
                    reason="open-redirect surface metadata unavailable",
                )
            )
            continue

        graph.add_validation_judgment(judgment)
        apply_validation_judgment(graph, judgment)

        results.append(
            OpenRedirectProbeResult(
                hypothesis_id=hypothesis.id,
                experiment_id=judgment.experiment_id,
                claim=hypothesis.claim,
                severity=severity,
                status=judgment.status,
                param=param,
                location=location,
                payload_status_code=payload_code,
                control_status_code=control_code,
                reason=judgment.reason,
            )
        )

    materialize_confirmed_findings(graph)
    return results


def run_open_redirect_investigation(
    graph: SecurityGraph,
    policy: OpenRedirectPolicy,
    *,
    target_base: str,
    executor=None,
) -> list[OpenRedirectProbeResult]:
    """
    Seed an open-redirect matrix and run the full open-redirect prove-chain.

    Live probing is bounded to the engagement host by default. Returns one
    :class:`OpenRedirectProbeResult` per hypothesis (including DISPROVED and
    INCONCLUSIVE ones, so the honest differential is fully visible).
    """
    if not policy.checks:
        return []

    seed_open_redirect_policy(graph, policy, target_base=target_base)

    if executor is None:
        host = urlsplit(
            target_base if "://" in target_base else f"http://{target_base}"
        ).netloc.lower()
        executor = OpenRedirectProbeExecutor(
            allowed_hosts={host} if host else None
        )

    return investigate_open_redirect(graph, executor=executor)
