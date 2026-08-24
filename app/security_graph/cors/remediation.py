"""
Remediate a confirmed CORS finding — PATCH + PROVE.

The mirror of :mod:`app.security_graph.open_redirect.remediation` for the
`cors_misconfig` class, but the shield is a **response-header rewrite** (as in
the posture class) while the PROVE is a **two-probe origin differential** (as in
open redirect). From a CONFIRMED CORS finding it:

  * reads the operator-declared surface the judge already used and the live
    control-probe provenance (no re-scoring, no invented semantics),
  * states the corrective response mutation the contradiction demands — strip the
    reflected ``Access-Control-Allow-Origin`` and the load-bearing
    ``Access-Control-Allow-Credentials`` from this route's response,
  * renders deployable provider configs (portable / nginx / Caddy / Envoy),
  * stands the *same* enforcement shield up in front of the target — forwarding
    the attacker ``Origin`` to the upstream, then stripping ACAO/ACAC from the
    forwarded response, and
  * PROVES the fix only when the PURE :func:`judge_cors` flips VALIDATED ->
    DISPROVED under real enforcement: pre-fix the credentialed reflection must
    still reproduce (before = VALIDATED), and under the shield the payload probe
    sees NO ACAO at all (after = DISPROVED) while the differential is re-run
    identically.

Nothing here manufactures a verdict. `FIX_PROVEN` is earned solely by the
deterministic judge observing the VALIDATED -> DISPROVED flip on a fresh
differential re-test. The module is target-agnostic: the response rewrite is
derived entirely from the confirmed finding's own provenance. The DURABLE fix is
to never reflect an arbitrary ``Origin`` into ACAO with credentials — pin a
strict server-side allowlist of trusted origins, and never combine a reflected
origin (or ``*``) with ``Access-Control-Allow-Credentials: true``.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import urlsplit

from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import RemediationEnforcer, ResponseHeaderRule
from ..remediation.model import RemediationVerification
from .executor import CorsProbeExecutor
from .judge import CorsExpectation, cors_expectation, judge_cors
_ACAO = "Access-Control-Allow-Origin"
_ACAC = "Access-Control-Allow-Credentials"


@dataclass(frozen=True)
class CorsControlRule:
    """
    The corrective response-header rewrite implied by one confirmed CORS misconfig.

    The shield strips BOTH the reflected ``Access-Control-Allow-Origin`` and the
    load-bearing ``Access-Control-Allow-Credentials`` from responses on
    ``method`` ``path`` — forwarding the attacker ``Origin`` to the upstream, then
    removing the reflection so a browser can no longer read a credentialed
    cross-origin response. Stripping ACAC alone already defangs the leak (a
    reflected origin without credentials is not exploitable); stripping ACAO too
    removes the reflection entirely, which is what the judge observes.
    """

    method: str
    path: str
    severity: str = "MEDIUM"


@dataclass(frozen=True)
class CorsRemediationArtifacts:
    """Deployable response-rewrite configs for the corrective control."""

    portable_json: str
    nginx: str
    caddy: str
    envoy: str


@dataclass(frozen=True)
class CorsRemediationPlan:
    """The corrective response rewrite the confirmed contradiction demands."""

    finding_id: str
    hypothesis_id: str
    rule: CorsControlRule
    upstream_base: str
    endpoint_url: str
    nonce_origin: str
    method: str
    path: str
    strategy: str = "cors_response_rewrite"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class CorsRemediationOutcome:
    """PATCH proposal + PROVE result for one confirmed CORS finding."""

    finding_id: str
    hypothesis_id: str
    result: str            # FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR
    plan: "CorsRemediationPlan | None" = None
    artifacts: "CorsRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""


def _originating_control_probe(graph: SecurityGraph, hypothesis_id: str):
    """The live COMPLETED no-Origin control probe that grounded this finding."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "cors_check"
        and experiment.action == "probe_cors_control"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]
def synthesize_cors_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> CorsRemediationPlan | None:
    """
    Derive the corrective response rewrite a confirmed CORS misconfig demands.

    Returns None for non-CORS findings, for findings whose surface metadata
    cannot be recovered, or for findings with no live control probe to anchor the
    upstream — the module never invents a target.
    """
    if finding.kind != "cors_misconfig":
        return None
    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    expectation = cors_expectation(
        graph, resource_id=identity.resource_id, aspect=identity.action
    )
    if expectation is None or not expectation.nonce_origin:
        return None
    probe = _originating_control_probe(graph, finding.hypothesis_id)
    if probe is None or probe.request is None:
        return None
    split = urlsplit(probe.request.url)
    if not split.scheme or not split.netloc:
        return None

    method = (expectation.method or probe.request.method).strip().upper() or "GET"
    path = split.path or "/"
    rule = CorsControlRule(method=method, path=path, severity=expectation.severity)
    upstream_base = f"{split.scheme}://{split.netloc}"

    rationale = (
        f"Operator matrix declares {method} {path} MUST NOT trust an arbitrary "
        "cross-origin caller.",
        "The two-probe origin differential CONFIRMED the payload probe reflected "
        f"the unforgeable attacker origin '{expectation.nonce_origin}' (or '*') in "
        "Access-Control-Allow-Origin AND set Access-Control-Allow-Credentials: "
        "true, while the no-Origin control anchor proved the reflection is "
        "origin-driven — a credentialed cross-origin read a victim's browser "
        "would honour.",
        "The shield strips Access-Control-Allow-Credentials (load-bearing) and "
        "Access-Control-Allow-Origin from this route's response, forwarding all "
        "other traffic unchanged. The DURABLE fix is to never reflect an arbitrary "
        "Origin with credentials: pin a strict server-side allowlist of trusted "
        "origins, and never pair a reflected origin (or '*') with "
        "Access-Control-Allow-Credentials: true.",
    )

    return CorsRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        endpoint_url=expectation.endpoint_url or probe.request.url,
        nonce_origin=expectation.nonce_origin,
        method=method,
        path=path,
        rationale=rationale,
    )


def _response_header_rules(rule: CorsControlRule) -> tuple[ResponseHeaderRule, ...]:
    """Lower the control to the enforcer's two pure response mutations.

    Order matters only cosmetically — the enforcer applies every matching rule.
    ACAC is removed FIRST (it is the load-bearing flag that makes the reflection
    readable), then ACAO (which removes the reflection the judge keys on).
    """
    return (
        ResponseHeaderRule(
            method=rule.method, path=rule.path, header=_ACAC, op="remove"
        ),
        ResponseHeaderRule(
            method=rule.method, path=rule.path, header=_ACAO, op="remove"
        ),
    )
def _portable_json(rule: CorsControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.cors_response_rewrite/v1",
        "decision": "strip_reflected_cors",
        "match": {"method": rule.method, "path": rule.path},
        "remove_response_headers": [_ACAC, _ACAO],
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Strip the reflected Access-Control-Allow-Origin and the load-bearing "
            "Access-Control-Allow-Credentials from this route's response (a "
            "gateway stop-gap). The ROOT-CAUSE fix is to never reflect an "
            "arbitrary Origin with credentials — pin a strict server-side "
            "allowlist of trusted origins."
        ),
    }
    return json.dumps(spec, indent=2)


def _nginx(rule: CorsControlRule, upstream_base: str) -> str:
    return "\n".join(
        [
            f"# Sentinel remediation — strip reflected CORS on "
            f"{rule.method} {rule.path}",
            f"location = {rule.path} {{",
            f"    proxy_hide_header {_ACAO};",
            f"    proxy_hide_header {_ACAC};",
            f"    proxy_pass {upstream_base};",
            "}",
            "# NOTE: gateway stop-gap only. The durable fix is a strict",
            "# server-side origin allowlist; never reflect an arbitrary Origin",
            "# together with Access-Control-Allow-Credentials: true.",
        ]
    )


def _caddy(rule: CorsControlRule, upstream_base: str) -> str:
    return "\n".join(
        [
            f"# Sentinel remediation — strip reflected CORS "
            f"{rule.method} {rule.path}",
            f"@sentinel_route path {rule.path}",
            f"header @sentinel_route -{_ACAO}",
            f"header @sentinel_route -{_ACAC}",
            f"reverse_proxy {upstream_base}",
            "# NOTE: gateway stop-gap. The durable fix is a strict server-side",
            "# origin allowlist (never reflect an arbitrary Origin with creds).",
        ]
    )


def _envoy(rule: CorsControlRule, upstream_base: str) -> str:
    return "\n".join(
        [
            "# Sentinel remediation — Envoy response-header mutation (CORS)",
            f"# upstream: {upstream_base}  match: {rule.method} {rule.path}",
            "route:",
            f'  match: {{ path: "{rule.path}" }}',
            "  response_headers_to_remove:",
            f'    - "{_ACAO}"',
            f'    - "{_ACAC}"',
        ]
    )


def render_cors_artifacts(
    rule: CorsControlRule,
    upstream_base: str,
) -> CorsRemediationArtifacts:
    """Render the corrective response rewrite as deployable provider configs."""
    return CorsRemediationArtifacts(
        portable_json=_portable_json(rule, upstream_base),
        nginx=_nginx(rule, upstream_base),
        caddy=_caddy(rule, upstream_base),
        envoy=_envoy(rule, upstream_base),
    )
def _probe(
    scratch: SecurityGraph,
    executor,
    hypothesis: Hypothesis,
    expectation: CorsExpectation,
    *,
    tag: str,
    endpoint_url: str,
    headers: tuple[tuple[str, str], ...],
) -> str:
    """Build → execute → complete one re-probe on the scratch graph."""
    identity = hypothesis.identity
    experiment = Experiment(
        id=f"exp:cors-remediation:{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="cors_check",
        description=f"CORS {tag} re-probe under remediation verification.",
        status="PLANNED",
        request=HttpRequestSpec(
            method=expectation.method,
            url=endpoint_url,
            headers=headers,
            body=None,
            principal_id=identity.principal_id,
            resource_id=identity.resource_id,
            action=identity.action,
        ),
        capability_id="cors.remediation_verification",
        action=f"verify_cors_{tag}",
    )
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
    return experiment.id


def _differential(
    scratch: SecurityGraph,
    executor,
    hypothesis: Hypothesis,
    expectation: CorsExpectation,
    *,
    phase: str,
    endpoint_url: str,
):
    """Run no-Origin control + attacker-Origin payload → PURE judge."""
    control_id = _probe(
        scratch, executor, hypothesis, expectation,
        tag=f"{phase}-control", endpoint_url=endpoint_url, headers=(),
    )
    payload_id = _probe(
        scratch, executor, hypothesis, expectation,
        tag=f"{phase}-payload", endpoint_url=endpoint_url,
        headers=(("Origin", expectation.nonce_origin),),
    )
    judgment = judge_cors(
        scratch,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_id=payload_id,
    )
    return judgment
def verify_cors_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: CorsRemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    PROVE the fix on a SCRATCH graph seeded with relationships ONLY.

    Runs the full two-probe origin differential twice with the PURE judge: BEFORE
    against the live target (the credentialed reflection must still reproduce →
    VALIDATED) and AFTER through the shield that strips ACAO/ACAC (the payload
    probe sees no reflection → DISPROVED). `proven` is earned solely by that
    VALIDATED -> DISPROVED flip. This never touches the real graph, never calls
    `apply_validation_judgment` or `materialize_confirmed_findings`, and
    manufactures nothing.
    """
    scratch = SecurityGraph()
    for relationship in graph.relationships:
        scratch.add_relationship(relationship)

    identity = hypothesis.identity
    expectation = None
    if identity is not None and identity.resource_id and identity.action:
        expectation = cors_expectation(
            scratch, resource_id=identity.resource_id, aspect=identity.action
        )
    if expectation is None or not expectation.nonce_origin:
        return RemediationVerification(
            experiment_id="",
            after_status="INCONCLUSIVE",
            before_status="INCONCLUSIVE",
            proven=False,
            reason="CORS surface metadata unavailable for verification",
        )

    target_endpoint = plan.endpoint_url
    after_endpoint = enforcer_base.rstrip("/") + urlsplit(target_endpoint).path

    target_host = urlsplit(target_endpoint).netloc.lower()
    enforcer_host = urlsplit(enforcer_base).netloc.lower()
    before_exec = before_executor or CorsProbeExecutor(
        allowed_hosts={target_host} if target_host else None
    )
    after_exec = after_executor or CorsProbeExecutor(
        allowed_hosts={enforcer_host} if enforcer_host else None
    )

    before_judgment = _differential(
        scratch, before_exec, hypothesis, expectation,
        phase="before", endpoint_url=target_endpoint,
    )
    after_judgment = _differential(
        scratch, after_exec, hypothesis, expectation,
        phase="after", endpoint_url=after_endpoint,
    )

    proven = (
        before_judgment.status == "VALIDATED"
        and after_judgment.status == "DISPROVED"
    )
    if proven:
        reason = (
            "the judge FLIPPED VALIDATED -> DISPROVED: pre-fix the payload probe "
            "reflected the attacker origin with credentials, and under the shield "
            "Access-Control-Allow-Origin/Credentials are stripped so the payload "
            "sees no reflection — a browser can no longer read a credentialed "
            "cross-origin response"
        )
    else:
        reason = (
            f"no VALIDATED -> DISPROVED flip (before={before_judgment.status}, "
            f"after={after_judgment.status}); the fix is not proven — the CORS "
            "misconfiguration must reproduce pre-fix and stop reproducing under "
            "the response-rewrite shield"
        )

    return RemediationVerification(
        experiment_id=after_judgment.experiment_id,
        after_status=after_judgment.status,
        before_status=before_judgment.status,
        proven=proven,
        reason=reason,
    )
def remediate_cors_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> CorsRemediationOutcome:
    """
    PATCH + PROVE one confirmed CORS finding.

    Synthesises the corrective response rewrite, renders deployable artifacts,
    and (when ``use_enforcer``) stands a real :class:`RemediationEnforcer` up in
    front of the target with both strip rules active, PROVING the fix only if the
    PURE :func:`judge_cors` flips VALIDATED -> DISPROVED. With
    ``use_enforcer=False`` the same verification runs against injected executors
    (offline). The live/real graph is never mutated here.
    """
    plan = synthesize_cors_remediation(graph, finding)
    if plan is None:
        return CorsRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed CORS misconfigurations with a recoverable live "
                "control probe and a declared surface are remediable here."
            ),
        )

    artifacts = render_cors_artifacts(plan.rule, plan.upstream_base)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return CorsRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail="the confirmed hypothesis or its identity is missing",
        )

    try:
        if use_enforcer:
            with RemediationEnforcer(
                (),
                plan.upstream_base,
                header_rules=_response_header_rules(plan.rule),
            ) as enforcer:
                verification = verify_cors_remediation(
                    graph,
                    hypothesis=hypothesis,
                    plan=plan,
                    enforcer_base=enforcer.base_url,
                    before_executor=before_executor,
                    after_executor=after_executor,
                )
        else:
            verification = verify_cors_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — surface the failure honestly
        return CorsRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=f"verification raised: {exc}",
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return CorsRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_cors_findings(
    graph: SecurityGraph,
) -> list[CorsRemediationOutcome]:
    """Remediate + prove every OPEN confirmed `cors_misconfig` finding."""
    findings = sorted(
        graph.findings_for(kind="cors_misconfig", status="OPEN"),
        key=lambda item: item.id,
    )
    return [remediate_cors_and_prove(graph, finding) for finding in findings]






