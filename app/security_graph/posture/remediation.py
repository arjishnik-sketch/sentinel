"""
Remediate a confirmed security-header posture finding — PATCH + PROVE.

The mirror of :mod:`app.security_graph.remediation` for the
`security_misconfiguration` class. From a CONFIRMED posture finding it:

  * reads the operator-declared expectation the judge already used and the
    live probe provenance (no re-scoring, no invented semantics),
  * states the one corrective header mutation the contradiction demands
    (inject / rewrite / strip),
  * renders deployable provider configs (nginx / Caddy / Envoy / portable),
  * stands the *same* enforcement shield up — now rewriting the forwarded
    response headers — and re-probes through it, and
  * PROVES the fix only when the PURE :func:`judge_header_posture` flips
    VALIDATED → DISPROVED under real enforcement.

Nothing here manufactures a verdict. `FIX_PROVEN` is earned solely by the
deterministic judge observing corrected headers on a fresh live probe.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import urlsplit

from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import RemediationEnforcer, ResponseHeaderRule
from ..remediation.model import RemediationVerification
from .executor import SecurityHeaderExecutor
from .judge import header_posture_expectation, judge_header_posture


# Conservative starting values injected for a `must_present` header. The
# PROOF is presence (that is all the judge checks for must_present); the
# concrete value is an advisory hardening default the operator should tune.
_SUGGESTED_VALUES = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=(), camera=(), microphone=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}

@dataclass(frozen=True)
class HeaderControlRule:
    """
    The corrective response-header control implied by one confirmed posture
    finding. `op` is the enforcement primitive the shield applies:

      set              -> emit `header: value` (must_present / must_equal)
      remove           -> drop the header      (must_absent)
      remove_if_equals -> drop iff it equals `value` (must_not_equal, e.g.
                          a wildcard CORS origin)

    `declared_value` preserves the operator's declared value (if any) for the
    rendered artifacts; `value` is what enforcement actually uses.
    """

    header: str
    requirement: str
    method: str
    path: str
    op: str
    value: str = ""
    declared_value: str = ""
    severity: str = "MEDIUM"


@dataclass(frozen=True)
class HeaderRemediationArtifacts:
    """Deployable header-posture enforcement configs rendered from a rule."""

    portable_json: str
    nginx: str
    caddy: str
    envoy: str


@dataclass(frozen=True)
class HeaderRemediationPlan:
    """The corrective control implied by one confirmed posture finding."""

    finding_id: str
    hypothesis_id: str
    rule: HeaderControlRule
    upstream_base: str
    target_url: str
    strategy: str = "header_posture_enforcement"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class HeaderRemediationOutcome:
    """
    Full PATCH + PROVE result for one confirmed posture finding.

    `result` is one of FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR.
    """

    finding_id: str
    hypothesis_id: str
    result: str
    plan: "HeaderRemediationPlan | None" = None
    artifacts: "HeaderRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""


def _originating_probe(
    graph: SecurityGraph,
    hypothesis_id: str,
) -> Experiment | None:
    """Recover the completed live header probe that backs this finding."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "security_header_check"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]


def _control_for(expectation) -> tuple[str, str, str]:
    """Map a violated expectation to (op, enforcement_value, declared_value)."""
    requirement = expectation.requirement
    declared = expectation.value or ""
    if requirement == "must_present":
        injected = _SUGGESTED_VALUES.get(
            expectation.header.lower(), "enabled"
        )
        return "set", injected, ""
    if requirement == "must_equal":
        return "set", declared, declared
    if requirement == "must_absent":
        return "remove", "", ""
    if requirement == "must_not_equal":
        return "remove_if_equals", declared, declared
    # Unknown requirement — not shieldable.
    return "", "", ""


def synthesize_header_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> HeaderRemediationPlan | None:
    """Derive the corrective header control for one confirmed finding."""

    if finding.kind != "security_misconfiguration":
        return None

    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None

    expectation = header_posture_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.requirement:
        return None

    op, value, declared = _control_for(expectation)
    if not op:
        return None

    probe = _originating_probe(graph, finding.hypothesis_id)
    if probe is None or probe.request is None:
        return None

    request = probe.request
    split = urlsplit(request.url)
    if not split.scheme or not split.netloc:
        return None

    rule = HeaderControlRule(
        header=expectation.header,
        requirement=expectation.requirement,
        method=request.method.strip().upper(),
        path=split.path or "/",
        op=op,
        value=value,
        declared_value=declared,
        severity=expectation.severity,
    )

    upstream_base = f"{split.scheme}://{split.netloc}"

    verb = {
        "set": f"set {rule.header}",
        "remove": f"strip {rule.header}",
        "remove_if_equals": f"strip the insecure {rule.header} value",
    }[op]
    rationale = (
        f"Operator posture declares {rule.method} {rule.path} "
        f"{expectation.requirement} {rule.header}.",
        "The live probe observed a header that CONTRADICTS it — a confirmed "
        "security misconfiguration.",
        f"The enforcement shield rewrites the response to {verb} and "
        "forwards all other traffic to the target unchanged.",
    )

    return HeaderRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        target_url=request.url,
        rationale=rationale,
    )


def _portable_json(rule: HeaderControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.header_control_rule/v1",
        "op": rule.op,
        "match": {"method": rule.method, "path": rule.path},
        "header": rule.header,
        "requirement": rule.requirement,
        "value": rule.value,
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Rewrite the forwarded response for this method+path so the "
            "declared posture holds; forward all other traffic unchanged. "
            "For a 'must_present' header the injected value is a hardening "
            "default to tune."
        ),
    }
    return json.dumps(spec, indent=2)


def _nginx(rule: HeaderControlRule, upstream_base: str) -> str:
    lines = [
        f"# Sentinel remediation — {rule.op} {rule.header} on "
        f"{rule.method} {rule.path}",
        f"location = {rule.path} {{",
    ]
    if rule.op == "set":
        lines.append(f'    add_header {rule.header} "{rule.value}" always;')
    elif rule.op == "remove":
        lines.append(f"    proxy_hide_header {rule.header};")
    else:  # remove_if_equals
        lines += [
            f"    # Hide the upstream {rule.header} (it carries the insecure",
            f"    # value '{rule.value}'); set an explicit safe value if the",
            "    # header is actually required.",
            f"    proxy_hide_header {rule.header};",
        ]
    lines += [
        f"    proxy_pass {upstream_base};",
        "}",
    ]
    return "\n".join(lines)


def _caddy(rule: HeaderControlRule, upstream_base: str) -> str:
    lines = [
        f"# Sentinel remediation — {rule.op} {rule.header} "
        f"{rule.method} {rule.path}",
        f"@sentinel_route path {rule.path}",
    ]
    if rule.op == "set":
        lines.append(f'header @sentinel_route {rule.header} "{rule.value}"')
    else:  # remove / remove_if_equals both drop the header
        if rule.op == "remove_if_equals":
            lines.append(
                f"# upstream value '{rule.value}' is insecure — remove it"
            )
        lines.append(f"header @sentinel_route -{rule.header}")
    lines.append(f"reverse_proxy {upstream_base}")
    return "\n".join(lines)


def _envoy(rule: HeaderControlRule, upstream_base: str) -> str:
    lines = [
        "# Sentinel remediation — Envoy response-header mutation",
        f"# upstream: {upstream_base}  match: {rule.method} {rule.path}",
        "route:",
        f'  match: {{ path: "{rule.path}" }}',
    ]
    if rule.op == "set":
        lines += [
            "  response_headers_to_add:",
            f'    - header: {{ key: "{rule.header}", '
            f'value: "{rule.value}" }}',
            "      append_action: OVERWRITE_IF_EXISTS_OR_ADD",
        ]
    else:
        if rule.op == "remove_if_equals":
            lines.append(f"  # remove insecure value '{rule.value}'")
        lines += [
            "  response_headers_to_remove:",
            f'    - "{rule.header}"',
        ]
    return "\n".join(lines)


def render_header_artifacts(
    rule: HeaderControlRule,
    upstream_base: str,
) -> HeaderRemediationArtifacts:
    """Render all deployable header-posture enforcement configs."""
    return HeaderRemediationArtifacts(
        portable_json=_portable_json(rule, upstream_base),
        nginx=_nginx(rule, upstream_base),
        caddy=_caddy(rule, upstream_base),
        envoy=_envoy(rule, upstream_base),
    )


def _probe_experiment(
    *,
    hypothesis_id: str,
    tag: str,
    method: str,
    url: str,
    identity,
) -> Experiment:
    request = HttpRequestSpec(
        method=method,
        url=url,
        headers=(),
        body=None,
        principal_id=identity.principal_id,
        resource_id=identity.resource_id,
        action=identity.action,
    )
    return Experiment(
        id=f"exp:header-remediation:{tag}:{hypothesis_id}",
        hypothesis_id=hypothesis_id,
        kind="security_header_check",
        description=f"Header-posture {tag}-enforcement re-probe.",
        status="PLANNED",
        request=request,
        capability_id="security_misconfiguration.remediation_verification",
        action="verify_header_remediation",
    )


def _probe_and_judge(scratch, executor, hypothesis, experiment):
    """Mirror the posture runner, then judge with the PURE judge."""
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

    judgment = judge_header_posture(
        scratch,
        hypothesis=hypothesis,
        experiment_id=experiment.id,
    )

    raw_code = dict(result.metadata).get("status_code")
    code = int(raw_code) if raw_code is not None else None
    return judgment, code


def verify_header_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: HeaderRemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    Probe the target directly (before) and through the header-rewriting
    shield (after), judging each with the PURE posture judge. Proven iff the
    after judgment is DISPROVED.
    """
    identity = hypothesis.identity

    target_split = urlsplit(plan.target_url)
    path_with_query = target_split.path or "/"
    if target_split.query:
        path_with_query += "?" + target_split.query
    after_url = enforcer_base.rstrip("/") + path_with_query

    # Scratch graph carries ONLY the posture edges the judge reads, so the
    # real graph's confirmed state is untouchable from here.
    scratch = SecurityGraph()
    for relationship in graph.relationships:
        scratch.add_relationship(relationship)

    method = plan.rule.method

    before_exec = before_executor or SecurityHeaderExecutor(
        allowed_hosts={target_split.netloc.lower()},
    )
    after_exec = after_executor or SecurityHeaderExecutor(
        allowed_hosts={urlsplit(enforcer_base).netloc.lower()},
    )

    before_exp = _probe_experiment(
        hypothesis_id=hypothesis.id,
        tag="before",
        method=method,
        url=plan.target_url,
        identity=identity,
    )
    after_exp = _probe_experiment(
        hypothesis_id=hypothesis.id,
        tag="after",
        method=method,
        url=after_url,
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
            "under enforcement the judge returned DISPROVED; the declared "
            "posture now holds and the misconfiguration no longer reproduces"
        )
    else:
        reason = (
            f"under enforcement the judge returned {after_judgment.status}; "
            "the misconfiguration still reproduces"
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


def _response_header_rule(rule: HeaderControlRule) -> ResponseHeaderRule:
    """Lower a HeaderControlRule to the enforcer's pure mutation directive."""
    return ResponseHeaderRule(
        method=rule.method,
        path=rule.path,
        header=rule.header,
        op=rule.op,
        value=rule.value,
    )


def remediate_header_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> HeaderRemediationOutcome:
    """Synthesize → enforce → prove a corrective header control."""

    plan = synthesize_header_remediation(graph, finding)
    if plan is None:
        return HeaderRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed posture violations with a recoverable live "
                "probe and a shieldable requirement are remediable here."
            ),
        )

    artifacts = render_header_artifacts(plan.rule, plan.upstream_base)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return HeaderRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail="confirmed hypothesis or its identity is missing",
        )

    try:
        if use_enforcer:
            with RemediationEnforcer(
                (),
                plan.upstream_base,
                header_rules=(_response_header_rule(plan.rule),),
            ) as enforcer:
                verification = verify_header_remediation(
                    graph,
                    hypothesis=hypothesis,
                    plan=plan,
                    enforcer_base=enforcer.base_url,
                    before_executor=before_executor,
                    after_executor=after_executor,
                )
        else:
            # Injected-executor path (tests): the after executor supplies the
            # corrected response directly, so no proxy is stood up.
            verification = verify_header_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — report cleanly, never raise
        return HeaderRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=str(exc),
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return HeaderRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_header_findings(
    graph: SecurityGraph,
) -> list[HeaderRemediationOutcome]:
    """Remediate every OPEN confirmed posture finding, deterministically."""
    findings = graph.findings_for(
        kind="security_misconfiguration",
        status="OPEN",
    )
    findings = sorted(findings, key=lambda item: item.id)
    return [
        remediate_header_and_prove(graph, finding) for finding in findings
    ]

