"""
Remediate a confirmed reflected-XSS finding — PATCH + PROVE.

The mirror of :mod:`app.security_graph.ssti.remediation` for the `xss` class. The
shield is a **request-guard (virtual patch)** with signature family ``xss``, and
the PROVE is the reflection differential. From a CONFIRMED reflected-XSS finding
it:

  * reads the operator-declared surface the judge already used and the live
    control-probe provenance (no re-scoring, no invented semantics),
  * states the one corrective request-guard the contradiction demands — refuse
    to forward this parameter on this route when it carries an XSS breakout
    signature (a ``<tag`` or an ``on…=`` event handler),
  * renders deployable provider configs (portable / nginx / ModSecurity / Caddy),
  * stands the *same* enforcement shield up in front of the target with the
    request-guard active, and
  * PROVES the fix only when the PURE :func:`judge_reflected_xss` flips
    VALIDATED -> DISPROVED under real enforcement: pre-fix the XSS must still
    reproduce (before = VALIDATED), and under the shield the breakout payloads
    are blocked (403) so the raw markup never reflects while the benign control
    marker is still forwarded — the un-escaped reflection is gone.

Nothing here manufactures a verdict. `FIX_PROVEN` is earned solely by the
deterministic judge observing the VALIDATED -> DISPROVED flip on a fresh
differential re-test. The module is target-agnostic: the guard is derived
entirely from the confirmed finding's own provenance. The DURABLE fix is
context-aware output encoding (HTML-escape untrusted input at the sink) plus a
restrictive Content-Security-Policy — the request-guard is only a stop-gap.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import RemediationEnforcer, RequestGuardRule
from ..remediation.model import RemediationVerification
from .executor import XSSProbeExecutor
from .judge import XSSExpectation, xss_expectation, judge_reflected_xss
from .xss_policy import marker_payloads


@dataclass(frozen=True)
class XSSControlRule:
    """
    The corrective request-guard implied by one confirmed reflected XSS.

    The shield refuses to forward requests whose `param` (in `location`) on
    `method` `path` carries an XSS breakout signature (a ``<tag`` or ``on…=``
    handler), and forwards everything else — including the benign control marker
    — to the target unchanged.
    """

    method: str
    path: str
    param: str
    location: str
    severity: str = "HIGH"


@dataclass(frozen=True)
class XSSRemediationArtifacts:
    """Deployable virtual-patch configs for the one corrective guard."""

    portable_json: str
    nginx: str
    modsecurity: str
    caddy: str


@dataclass(frozen=True)
class XSSRemediationPlan:
    """The single corrective request-guard the confirmed contradiction demands."""

    finding_id: str
    hypothesis_id: str
    rule: XSSControlRule
    upstream_base: str
    endpoint_url: str
    marker: str
    strategy: str = "xss_request_guard"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class XSSRemediationOutcome:
    """PATCH proposal + PROVE result for one confirmed reflected-XSS finding."""

    finding_id: str
    hypothesis_id: str
    result: str            # FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR
    plan: "XSSRemediationPlan | None" = None
    artifacts: "XSSRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""


def _originating_control_probe(graph: SecurityGraph, hypothesis_id: str):
    """The live COMPLETED control probe that grounded this finding, or None."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "xss_check"
        and experiment.action == "probe_xss_control"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]


def synthesize_xss_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> XSSRemediationPlan | None:
    """
    Derive the one corrective request-guard a confirmed reflected XSS demands.

    Returns None for non-XSS findings, for findings whose surface metadata cannot
    be recovered, or for findings with no live control probe to anchor the
    upstream — the module never invents a target.
    """
    if finding.kind != "xss":
        return None
    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    expectation = xss_expectation(
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

    rule = XSSControlRule(
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
        "reflected as active markup.",
        "The reflection differential CONFIRMED a payload's raw markup was "
        "reflected VERBATIM (un-escaped, carrying our marker) while the control "
        "proved the app reflects the bare marker — a real reflected XSS, not an "
        "escaped value.",
        "The request-guard refuses to forward this parameter when it carries an "
        "XSS breakout signature and forwards all other traffic — including the "
        "benign marker — unchanged. The DURABLE fix is context-aware output "
        "encoding at the sink (HTML-escape untrusted input) plus a restrictive "
        "Content-Security-Policy.",
    )

    return XSSRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        endpoint_url=expectation.endpoint_url,
        marker=expectation.marker,
        rationale=rationale,
    )


# Best-effort gateway signature matching the common XSS breakout shapes; the
# enforcer itself uses the richer compiled _XSS_SIGNATURES. Both are stop-gaps —
# the durable fix is context-aware output encoding + CSP.
_GATEWAY_SIGNATURE = r"(<\s*/?\s*script|<\s*(svg|img|iframe|body|input)|\bon[a-z]+\s*=|javascript:)"


def _portable_json(rule: XSSControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.xss_request_guard/v1",
        "decision": "deny_on_signature",
        "match": {
            "method": rule.method,
            "path": rule.path,
            "param": rule.param,
            "location": rule.location,
        },
        "signature_family": "xss",
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Block this parameter at the gateway when it carries an XSS breakout "
            "signature (a stop-gap virtual patch). The ROOT-CAUSE fix is "
            "context-aware output encoding at the sink (HTML-escape untrusted "
            "input) plus a restrictive Content-Security-Policy."
        ),
    }
    return json.dumps(spec, indent=2)


def _nginx(rule: XSSControlRule, upstream_base: str) -> str:
    matched = f"$arg_{rule.param}" if rule.location == "query" else "$request_body"
    return "\n".join(
        [
            f"# Sentinel remediation — reflected-XSS request-guard for '{rule.param}'",
            f"# on {rule.method} {rule.path} ({rule.location}). Benign traffic is forwarded.",
            f"location = {rule.path} {{",
            f'    if ({matched} ~* "{_GATEWAY_SIGNATURE}") {{',
            "        return 403;",
            "    }",
            f"    proxy_pass {upstream_base};",
            "}",
            "# NOTE: gateway stop-gap only. The durable fix is context-aware output",
            "# encoding at the sink + a restrictive Content-Security-Policy.",
        ]
    )


def _modsecurity(rule: XSSControlRule, upstream_base: str) -> str:
    if rule.location == "query":
        target = f"ARGS_GET:{rule.param}"
    elif rule.location == "body_form":
        target = f"ARGS_POST:{rule.param}"
    else:
        target = f"ARGS:{rule.param}"
    return "\n".join(
        [
            "# Sentinel remediation — ModSecurity virtual patch (reflected XSS)",
            f"# upstream: {upstream_base}   match: {rule.method} {rule.path}",
            f'SecRule REQUEST_METHOD "@streq {rule.method}" \\',
            f'    "id:1000005,phase:2,chain,deny,status:403,log,\\',
            f"     msg:'Sentinel: reflected-XSS request-guard on {rule.param}'\"",
            f'    SecRule REQUEST_URI "@beginsWith {rule.path}" "chain"',
            f'        SecRule {target} "@rx {_GATEWAY_SIGNATURE}" "t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase"',
            "# NOTE: virtual patch. The durable fix is output encoding + CSP.",
        ]
    )


def _caddy(rule: XSSControlRule, upstream_base: str) -> str:
    lines = [
        f"# Sentinel remediation — reflected-XSS request-guard for '{rule.param}'",
        f"# on {rule.method} {rule.path}. Best-effort matcher; prefer ModSecurity / sink fix.",
        "@xss {",
        f"    method {rule.method}",
        f"    path {rule.path}",
    ]
    if rule.location == "query":
        lines.append(f"    query {rule.param}=*<* {rule.param}=*on*=* {rule.param}=*javascript:*")
    else:
        lines.append('    header Content-Type *')
    lines += [
        "}",
        "respond @xss 403",
        f"reverse_proxy {upstream_base}",
        "# NOTE: gateway stop-gap. The durable fix is output encoding + CSP.",
    ]
    return "\n".join(lines)


def render_xss_artifacts(
    rule: XSSControlRule,
    upstream_base: str,
) -> XSSRemediationArtifacts:
    """Render the corrective request-guard as deployable provider configs."""
    return XSSRemediationArtifacts(
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
    expectation: XSSExpectation,
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
        id=f"exp:xss-remediation:{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="xss_check",
        description=f"XSS {tag} re-probe under remediation verification.",
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
        capability_id="xss.remediation_verification",
        action=f"verify_xss_{tag}",
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
    expectation: XSSExpectation,
    *,
    phase: str,
    endpoint_url: str,
):
    """Run control + breakout payloads and hand the ids to the PURE judge."""
    control_id, control_code = _probe(
        scratch, executor, hypothesis, expectation,
        tag=f"{phase}-control", endpoint_url=endpoint_url,
        value=expectation.marker,
    )
    payload_ids: list[tuple[str, str]] = []
    for label, value in marker_payloads(expectation.marker):
        payload_id, _ = _probe(
            scratch, executor, hypothesis, expectation,
            tag=f"{phase}-payload-{label}", endpoint_url=endpoint_url,
            value=value,
        )
        payload_ids.append((label, payload_id))
    judgment = judge_reflected_xss(
        scratch,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_ids=tuple(payload_ids),
    )
    return judgment, control_code


def _request_guard_rule(rule: XSSControlRule) -> RequestGuardRule:
    return RequestGuardRule(
        method=rule.method,
        path=rule.path,
        param=rule.param,
        location=rule.location,
        signature_family="xss",
    )


def verify_xss_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: XSSRemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    PROVE the fix on a SCRATCH graph seeded with relationships ONLY.

    Runs the full reflection differential twice with the PURE judge: BEFORE
    against the live target (must reproduce → VALIDATED) and AFTER through the
    shield with the request-guard active (breakout payloads blocked → the raw
    markup never reflects → DISPROVED). `proven` is earned solely by that
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
        expectation = xss_expectation(
            scratch, resource_id=identity.resource_id, aspect=identity.action
        )
    if expectation is None or not expectation.param:
        return RemediationVerification(
            experiment_id="",
            after_status="INCONCLUSIVE",
            before_status="INCONCLUSIVE",
            proven=False,
            reason="XSS surface metadata unavailable for verification",
        )

    target_endpoint = plan.endpoint_url
    after_endpoint = enforcer_base.rstrip("/") + urlsplit(target_endpoint).path

    target_host = urlsplit(target_endpoint).netloc.lower()
    enforcer_host = urlsplit(enforcer_base).netloc.lower()
    before_exec = before_executor or XSSProbeExecutor(
        allowed_hosts={target_host} if target_host else None
    )
    after_exec = after_executor or XSSProbeExecutor(
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
            "the judge FLIPPED VALIDATED -> DISPROVED: pre-fix a payload's raw "
            "markup reflected verbatim, and under the request-guard the breakout "
            "payloads are blocked (403) so the markup never reflects while the "
            "benign control marker is still served — the reflected XSS no longer "
            "reproduces"
        )
    else:
        reason = (
            f"no VALIDATED -> DISPROVED flip (before={before_judgment.status}, "
            f"after={after_judgment.status}); the fix is not proven — the XSS "
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


def remediate_xss_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> XSSRemediationOutcome:
    """
    PATCH + PROVE one confirmed reflected-XSS finding.

    Synthesises the corrective request-guard, renders deployable artifacts, and
    (when ``use_enforcer``) stands a real :class:`RemediationEnforcer` up in
    front of the target with the guard active, PROVING the fix only if the PURE
    :func:`judge_reflected_xss` flips VALIDATED -> DISPROVED. With
    ``use_enforcer=False`` the same verification runs against injected executors
    (offline). The live/real graph is never mutated here.
    """
    plan = synthesize_xss_remediation(graph, finding)
    if plan is None:
        return XSSRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed reflected XSS with a recoverable live control "
                "probe and a guardable declared surface are remediable here."
            ),
        )

    artifacts = render_xss_artifacts(plan.rule, plan.upstream_base)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return XSSRemediationOutcome(
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
                verification = verify_xss_remediation(
                    graph,
                    hypothesis=hypothesis,
                    plan=plan,
                    enforcer_base=enforcer.base_url,
                    before_executor=before_executor,
                    after_executor=after_executor,
                )
        else:
            verification = verify_xss_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — surface the failure honestly
        return XSSRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=f"verification raised: {exc}",
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return XSSRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_xss_findings(
    graph: SecurityGraph,
) -> list[XSSRemediationOutcome]:
    """Remediate + prove every OPEN confirmed `xss` finding."""
    findings = sorted(
        graph.findings_for(kind="xss", status="OPEN"),
        key=lambda item: item.id,
    )
    return [remediate_xss_and_prove(graph, finding) for finding in findings]
