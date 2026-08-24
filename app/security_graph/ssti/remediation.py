"""
Remediate a confirmed SSTI finding — PATCH + PROVE.

The mirror of :mod:`app.security_graph.injection.remediation` for the
`template_injection` class. The shield is a **request-guard (virtual patch)**
with signature family ``ssti``, and the PROVE is the arithmetic-evaluation
differential. From a CONFIRMED SSTI finding it:

  * reads the operator-declared surface the judge already used and the live
    control-probe provenance (no re-scoring, no invented semantics),
  * states the one corrective request-guard the contradiction demands — refuse
    to forward this parameter on this route when it carries a template-injection
    signature (a template delimiter),
  * renders deployable provider configs (portable / nginx / ModSecurity / Caddy),
  * stands the *same* enforcement shield up in front of the target with the
    request-guard active, and
  * PROVES the fix only when the PURE :func:`judge_template_injection` flips
    VALIDATED -> DISPROVED under real enforcement: pre-fix the SSTI must still
    reproduce (before = VALIDATED), and under the shield the template payloads
    are blocked (403) so the computed product never renders while the benign
    control literal is still forwarded — the evaluation is gone.

Nothing here manufactures a verdict. `FIX_PROVEN` is earned solely by the
deterministic judge observing the VALIDATED -> DISPROVED flip on a fresh
differential re-test. The module is target-agnostic: the guard is derived
entirely from the confirmed finding's own provenance. The DURABLE fix is to stop
rendering untrusted input as a template (use a sandbox / logic-less template and
pass data as context, never as the template source).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import RemediationEnforcer, RequestGuardRule
from ..remediation.model import RemediationVerification
from .executor import SSTIProbeExecutor
from .judge import SSTIExpectation, ssti_expectation, judge_template_injection
from .ssti_policy import template_payloads


@dataclass(frozen=True)
class SSTIControlRule:
    """
    The corrective request-guard implied by one confirmed SSTI.

    The shield refuses to forward requests whose `param` (in `location`) on
    `method` `path` carries a template-injection signature (a template
    delimiter), and forwards everything else — including the benign control
    literal — to the target unchanged.
    """

    method: str
    path: str
    param: str
    location: str
    severity: str = "HIGH"


@dataclass(frozen=True)
class SSTIRemediationArtifacts:
    """Deployable virtual-patch configs for the one corrective guard."""

    portable_json: str
    nginx: str
    modsecurity: str
    caddy: str


@dataclass(frozen=True)
class SSTIRemediationPlan:
    """The single corrective request-guard the confirmed contradiction demands."""

    finding_id: str
    hypothesis_id: str
    rule: SSTIControlRule
    upstream_base: str
    endpoint_url: str
    literal_expr: str
    strategy: str = "ssti_request_guard"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class SSTIRemediationOutcome:
    """PATCH proposal + PROVE result for one confirmed SSTI finding."""

    finding_id: str
    hypothesis_id: str
    result: str            # FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR
    plan: "SSTIRemediationPlan | None" = None
    artifacts: "SSTIRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""


def _originating_control_probe(graph: SecurityGraph, hypothesis_id: str):
    """The live COMPLETED control probe that grounded this finding, or None."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "template_injection_check"
        and experiment.action == "probe_ssti_control"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]


def synthesize_ssti_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> SSTIRemediationPlan | None:
    """
    Derive the one corrective request-guard a confirmed SSTI demands.

    Returns None for non-SSTI findings, for findings whose surface metadata
    cannot be recovered, or for findings with no live control probe to anchor
    the upstream — the module never invents a target.
    """
    if finding.kind != "template_injection":
        return None
    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    expectation = ssti_expectation(
        graph, resource_id=identity.resource_id, aspect=identity.action
    )
    if expectation is None or not expectation.param:
        return None
    probe = _originating_control_probe(graph, finding.hypothesis_id)
    if probe is None or probe.request is None:
        return None
    split = urlsplit(probe.request.url)
    if not split.scheme or not split.netloc:
        return None

    rule = SSTIControlRule(
        method=expectation.method.strip().upper() or "GET",
        path=split.path or "/",
        param=expectation.param,
        location=expectation.location,
        severity=expectation.severity,
    )
    upstream_base = f"{split.scheme}://{split.netloc}"

    rationale = (
        f"Operator matrix declares the '{expectation.param}' parameter of "
        f"{rule.method} {rule.path} ({expectation.location}) MUST NOT be "
        "evaluated by a template engine.",
        "The arithmetic-evaluation differential CONFIRMED a template payload "
        "rendered the computed product while the literal expression vanished, "
        "and the control proved the app merely reflects — a real SSTI, not a "
        "reflected value.",
        "The request-guard refuses to forward this parameter when it carries a "
        "template-injection signature (a template delimiter) and forwards all "
        "other traffic — including the benign literal — unchanged. The DURABLE "
        "fix is to stop rendering untrusted input as a template: use a "
        "logic-less/sandboxed template and pass user data as context only.",
    )

    return SSTIRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        endpoint_url=expectation.endpoint_url,
        literal_expr=expectation.literal_expr,
        rationale=rationale,
    )


# Best-effort gateway signature matching the common template delimiters; the
# enforcer itself uses the richer compiled _SSTI_SIGNATURES. Both are stop-gaps —
# the durable fix is to never render untrusted input as a template.
_GATEWAY_SIGNATURE = r"(\{\{|\}\}|\$\{|#\{|<%|%>|\{%)"


def _portable_json(rule: SSTIControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.ssti_request_guard/v1",
        "decision": "deny_on_signature",
        "match": {
            "method": rule.method,
            "path": rule.path,
            "param": rule.param,
            "location": rule.location,
        },
        "signature_family": "ssti",
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Block this parameter at the gateway when it carries a template-"
            "injection signature (a stop-gap virtual patch). The ROOT-CAUSE fix "
            "is to never render untrusted input as a template — use a "
            "logic-less/sandboxed template and pass user data as context only."
        ),
    }
    return json.dumps(spec, indent=2)


def _nginx(rule: SSTIControlRule, upstream_base: str) -> str:
    matched = f"$arg_{rule.param}" if rule.location == "query" else "$request_body"
    return "\n".join(
        [
            f"# Sentinel remediation — SSTI request-guard for '{rule.param}'",
            f"# on {rule.method} {rule.path} ({rule.location}). Benign traffic is forwarded.",
            f"location = {rule.path} {{",
            f'    if ({matched} ~* "{_GATEWAY_SIGNATURE}") {{',
            "        return 403;",
            "    }",
            f"    proxy_pass {upstream_base};",
            "}",
            "# NOTE: gateway stop-gap only. The durable fix is to never render",
            "# untrusted input as a template (logic-less/sandboxed template).",
        ]
    )


def _modsecurity(rule: SSTIControlRule, upstream_base: str) -> str:
    if rule.location == "query":
        target = f"ARGS_GET:{rule.param}"
    elif rule.location == "body_form":
        target = f"ARGS_POST:{rule.param}"
    else:
        target = f"ARGS:{rule.param}"
    return "\n".join(
        [
            "# Sentinel remediation — ModSecurity virtual patch (SSTI)",
            f"# upstream: {upstream_base}   match: {rule.method} {rule.path}",
            f'SecRule REQUEST_METHOD "@streq {rule.method}" \\',
            f'    "id:1000003,phase:2,chain,deny,status:403,log,\\',
            f"     msg:'Sentinel: SSTI request-guard on {rule.param}'\"",
            f'    SecRule REQUEST_URI "@beginsWith {rule.path}" "chain"',
            f'        SecRule {target} "@rx {_GATEWAY_SIGNATURE}" "t:none,t:urlDecodeUni"',
            "# NOTE: virtual patch. The durable fix is a logic-less/sandboxed template.",
        ]
    )


def _caddy(rule: SSTIControlRule, upstream_base: str) -> str:
    lines = [
        f"# Sentinel remediation — SSTI request-guard for '{rule.param}'",
        f"# on {rule.method} {rule.path}. Best-effort matcher; prefer ModSecurity / handler fix.",
        "@ssti {",
        f"    method {rule.method}",
        f"    path {rule.path}",
    ]
    if rule.location == "query":
        lines.append(f"    query {rule.param}=*{{{{** {rule.param}=*${{** {rule.param}=*<%*")
    else:
        lines.append('    header Content-Type *')
    lines += [
        "}",
        "respond @ssti 403",
        f"reverse_proxy {upstream_base}",
        "# NOTE: gateway stop-gap. The durable fix is a logic-less/sandboxed template.",
    ]
    return "\n".join(lines)


def render_ssti_artifacts(
    rule: SSTIControlRule,
    upstream_base: str,
) -> SSTIRemediationArtifacts:
    """Render the corrective request-guard as deployable provider configs."""
    return SSTIRemediationArtifacts(
        portable_json=_portable_json(rule, upstream_base),
        nginx=_nginx(rule, upstream_base),
        modsecurity=_modsecurity(rule, upstream_base),
        caddy=_caddy(rule, upstream_base),
    )


def _inject(
    endpoint_url: str,
    param: str,
    location: str,
    value: str,
) -> tuple[str, str | None, tuple[tuple[str, str], ...]]:
    """Place `value` in the declared parameter at `endpoint_url`. Pure."""
    if location == "query":
        split = urlsplit(endpoint_url)
        params = dict(parse_qsl(split.query, keep_blank_values=True))
        params[param] = value
        new_query = urlencode(params)
        url = urlunsplit(
            (split.scheme, split.netloc, split.path, new_query, split.fragment)
        )
        return url, None, ()
    if location == "body_form":
        body = urlencode({param: value})
        return endpoint_url, body, (("Content-Type", "application/x-www-form-urlencoded"),)
    body = json.dumps({param: value})
    return endpoint_url, body, (("Content-Type", "application/json"),)


def _probe(
    scratch: SecurityGraph,
    executor,
    hypothesis: Hypothesis,
    expectation: SSTIExpectation,
    *,
    tag: str,
    endpoint_url: str,
    value: str,
) -> tuple[str, int | None]:
    """Build → execute → complete one re-probe on the scratch graph."""
    identity = hypothesis.identity
    url, body, headers = _inject(
        endpoint_url, expectation.param, expectation.location, value
    )
    experiment = Experiment(
        id=f"exp:ssti-remediation:{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="template_injection_check",
        description=f"SSTI {tag} re-probe under remediation verification.",
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
        capability_id="ssti.remediation_verification",
        action=f"verify_ssti_{tag}",
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

    raw_code = dict(result.metadata).get("status_code")
    return experiment.id, (int(raw_code) if raw_code is not None else None)


def _differential(
    scratch: SecurityGraph,
    executor,
    hypothesis: Hypothesis,
    expectation: SSTIExpectation,
    *,
    phase: str,
    endpoint_url: str,
):
    """Run control + template payloads and hand the ids to the PURE judge."""
    control_id, control_code = _probe(
        scratch, executor, hypothesis, expectation,
        tag=f"{phase}-control", endpoint_url=endpoint_url,
        value=expectation.literal_expr,
    )
    payload_ids: list[tuple[str, str]] = []
    for label, value in template_payloads(expectation.literal_expr):
        payload_id, _ = _probe(
            scratch, executor, hypothesis, expectation,
            tag=f"{phase}-payload-{label}", endpoint_url=endpoint_url,
            value=value,
        )
        payload_ids.append((label, payload_id))
    judgment = judge_template_injection(
        scratch,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_ids=tuple(payload_ids),
    )
    return judgment, control_code


def _request_guard_rule(rule: SSTIControlRule) -> RequestGuardRule:
    return RequestGuardRule(
        method=rule.method,
        path=rule.path,
        param=rule.param,
        location=rule.location,
        signature_family="ssti",
    )


def verify_ssti_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: SSTIRemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    PROVE the fix on a SCRATCH graph seeded with relationships ONLY.

    Runs the full arithmetic-evaluation differential twice with the PURE judge:
    BEFORE against the live target (must reproduce → VALIDATED) and AFTER through
    the shield with the request-guard active (template payloads blocked → the
    product never renders → DISPROVED). `proven` is earned solely by that
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
        expectation = ssti_expectation(
            scratch, resource_id=identity.resource_id, aspect=identity.action
        )
    if expectation is None or not expectation.param:
        return RemediationVerification(
            experiment_id="",
            after_status="INCONCLUSIVE",
            before_status="INCONCLUSIVE",
            proven=False,
            reason="SSTI surface metadata unavailable for verification",
        )

    target_endpoint = plan.endpoint_url
    after_endpoint = enforcer_base.rstrip("/") + urlsplit(target_endpoint).path

    target_host = urlsplit(target_endpoint).netloc.lower()
    enforcer_host = urlsplit(enforcer_base).netloc.lower()
    before_exec = before_executor or SSTIProbeExecutor(
        allowed_hosts={target_host} if target_host else None
    )
    after_exec = after_executor or SSTIProbeExecutor(
        allowed_hosts={enforcer_host} if enforcer_host else None
    )

    before_judgment, before_code = _differential(
        scratch, before_exec, hypothesis, expectation,
        phase="before", endpoint_url=target_endpoint,
    )
    after_judgment, after_code = _differential(
        scratch, after_exec, hypothesis, expectation,
        phase="after", endpoint_url=after_endpoint,
    )

    proven = (
        before_judgment.status == "VALIDATED"
        and after_judgment.status == "DISPROVED"
    )
    if proven:
        reason = (
            "the judge FLIPPED VALIDATED -> DISPROVED: pre-fix a template payload "
            "rendered the computed product, and under the request-guard the "
            "payloads are blocked (403) so the product never renders while the "
            "benign control literal is still served — the SSTI no longer reproduces"
        )
    else:
        reason = (
            f"no VALIDATED -> DISPROVED flip (before={before_judgment.status}, "
            f"after={after_judgment.status}); the fix is not proven — the SSTI "
            "must reproduce pre-fix and stop reproducing under the request-guard"
        )

    return RemediationVerification(
        experiment_id=after_judgment.experiment_id,
        after_status=after_judgment.status,
        before_status=before_judgment.status,
        proven=proven,
        observed_status_code=after_code,
        before_status_code=before_code,
        reason=reason,
    )


def remediate_ssti_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> SSTIRemediationOutcome:
    """
    PATCH + PROVE one confirmed SSTI finding.

    Synthesises the corrective request-guard, renders deployable artifacts, and
    (when ``use_enforcer``) stands a real :class:`RemediationEnforcer` up in
    front of the target with the guard active, PROVING the fix only if the PURE
    :func:`judge_template_injection` flips VALIDATED -> DISPROVED. With
    ``use_enforcer=False`` the same verification runs against injected executors
    (offline). The live/real graph is never mutated here.
    """
    plan = synthesize_ssti_remediation(graph, finding)
    if plan is None:
        return SSTIRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed SSTIs with a recoverable live control probe and "
                "a guardable declared surface are remediable here."
            ),
        )

    artifacts = render_ssti_artifacts(plan.rule, plan.upstream_base)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return SSTIRemediationOutcome(
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
                guard_rules=(_request_guard_rule(plan.rule),),
            ) as enforcer:
                verification = verify_ssti_remediation(
                    graph,
                    hypothesis=hypothesis,
                    plan=plan,
                    enforcer_base=enforcer.base_url,
                    before_executor=before_executor,
                    after_executor=after_executor,
                )
        else:
            verification = verify_ssti_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — surface the failure honestly
        return SSTIRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=f"verification raised: {exc}",
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return SSTIRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_ssti_findings(
    graph: SecurityGraph,
) -> list[SSTIRemediationOutcome]:
    """Remediate + prove every OPEN confirmed `template_injection` finding."""
    findings = sorted(
        graph.findings_for(kind="template_injection", status="OPEN"),
        key=lambda item: item.id,
    )
    return [remediate_ssti_and_prove(graph, finding) for finding in findings]
