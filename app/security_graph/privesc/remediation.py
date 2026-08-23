"""
Remediate a confirmed privilege-escalation finding — PATCH + PROVE.

The mirror of :mod:`app.security_graph.cookies.remediation` for the
`privilege_escalation` class, but the PROVE is a **three-probe differential**
(attacker control + attacker breach + anonymous baseline). From a CONFIRMED
escalation finding it:

  * reads the operator-declared boundary the judge already used and the live
    breach-probe provenance (no re-scoring, no invented semantics),
  * states the one corrective access-control rule the contradiction demands —
    deny exactly this attacker session on exactly the breach route,
  * renders deployable provider configs (nginx / Caddy / Envoy / portable),
  * stands the *same* enforcement shield up in front of the target, and
  * PROVES the fix only when the PURE :func:`judge_privilege_escalation` flips
    VALIDATED → DISPROVED under real enforcement: pre-fix the escalation must
    still reproduce (before = VALIDATED), and under the shield the attacker's
    control probe still succeeds (its own object is forwarded, so the session
    stays provably alive) while the breach probe is now denied (403). The
    control leg keeps the proof honest — the fix blocks the escalation without
    breaking the attacker's legitimate access — and requiring the pre-fix
    VALIDATED half stops a shield taking credit for a boundary that never
    reproduced.

Nothing here manufactures a verdict. `FIX_PROVEN` is earned solely by the
deterministic judge observing the VALIDATED → DISPROVED flip on a fresh
three-probe re-test. The module is target-agnostic: the rule is derived
entirely from the confirmed finding's own provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import urlsplit

from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import RemediationEnforcer
from ..remediation.model import AccessControlRule, RemediationVerification
from .executor import PrivEscProbeExecutor
from .judge import PrivEscExpectation, judge_privilege_escalation, privesc_expectation


@dataclass(frozen=True)
class PrivEscControlRule:
    """
    The corrective access-control rule implied by one confirmed escalation.

    The shield denies exactly `attacker_headers` on `method` `path`, and
    forwards everything else — including the attacker's own control route — to
    the target unchanged.
    """

    attacker_name: str
    type: str
    method: str
    path: str
    attacker_headers: tuple[tuple[str, str], ...]
    severity: str = "HIGH"


@dataclass(frozen=True)
class PrivEscRemediationArtifacts:
    """Deployable object-level access-control configs rendered from a rule."""

    portable_json: str
    nginx: str
    caddy: str
    envoy: str


@dataclass(frozen=True)
class PrivEscRemediationPlan:
    """The corrective control implied by one confirmed escalation finding."""

    finding_id: str
    hypothesis_id: str
    rule: PrivEscControlRule
    upstream_base: str
    breach_url: str
    control_url: str
    control_method: str
    strategy: str = "privilege_escalation_enforcement"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class PrivEscRemediationOutcome:
    """
    Full PATCH + PROVE result for one confirmed escalation finding.

    `result` is one of FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR.
    """

    finding_id: str
    hypothesis_id: str
    result: str
    plan: "PrivEscRemediationPlan | None" = None
    artifacts: "PrivEscRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""


def _originating_breach_probe(
    graph: SecurityGraph,
    hypothesis_id: str,
) -> Experiment | None:
    """Recover the completed live breach probe that backs this finding."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "privilege_escalation_check"
        and experiment.action == "probe_privilege_escalation_breach"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]


def synthesize_privesc_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> PrivEscRemediationPlan | None:
    """Derive the corrective access-control rule for one confirmed finding."""

    if finding.kind != "privilege_escalation":
        return None

    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None

    expectation = privesc_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.type:
        return None

    probe = _originating_breach_probe(graph, finding.hypothesis_id)
    if probe is None or probe.request is None:
        return None

    request = probe.request
    split = urlsplit(request.url)
    if not split.scheme or not split.netloc:
        return None

    principal = graph.principals.get(identity.principal_id)
    attacker_name = principal.name if principal is not None else expectation.attacker

    rule = PrivEscControlRule(
        attacker_name=attacker_name,
        type=expectation.type,
        method=request.method.strip().upper(),
        path=split.path or "/",
        attacker_headers=tuple(request.headers),
        severity=expectation.severity,
    )

    upstream_base = f"{split.scheme}://{split.netloc}"

    boundary = (
        f"read {expectation.victim}'s object"
        if expectation.type == "horizontal"
        else "reach the elevated function"
    )
    rationale = (
        f"Operator matrix declares '{attacker_name}' MUST NOT {boundary} at "
        f"{rule.method} {rule.path} ({expectation.type}).",
        "The three-probe differential confirmed a live session was GRANTED it "
        "while an anonymous caller was denied — a real privilege-boundary "
        "crossing (IDOR/BOLA or vertical escalation).",
        "The enforcement shield denies exactly this principal's session on this "
        "object/function and forwards all other traffic — including the "
        "attacker's own legitimate access — to the target unchanged.",
    )

    return PrivEscRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        breach_url=request.url,
        control_url=expectation.control_url,
        control_method=expectation.control_method,
        rationale=rationale,
    )


# RENDER_MARKER


def _header_names(rule: PrivEscControlRule) -> str:
    names = [name for name, _ in rule.attacker_headers] or ["Authorization"]
    return ", ".join(names)


def _portable_json(rule: PrivEscControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.privesc_control_rule/v1",
        "decision": "deny",
        "match": {
            "method": rule.method,
            "path": rule.path,
            "principal_headers": [list(pair) for pair in rule.attacker_headers],
        },
        "escalation_type": rule.type,
        "principal": rule.attacker_name,
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Deny this principal's session on this object/function at the "
            "gateway (a stop-gap shield). The ROOT-CAUSE fix is an "
            "object-level authorization check in the handler: verify the "
            "authenticated principal owns (or is entitled to) the requested "
            "object before returning it."
        ),
    }
    return json.dumps(spec, indent=2)


def _nginx(rule: PrivEscControlRule, upstream_base: str) -> str:
    name, value = (
        rule.attacker_headers[0]
        if rule.attacker_headers
        else ("Authorization", "")
    )
    var = "$http_" + name.lower().replace("-", "_")
    return "\n".join(
        [
            f"# Sentinel remediation — deny privilege escalation "
            f"({rule.type}) for '{rule.attacker_name}'",
            f"# on {rule.method} {rule.path}. Forwards all other traffic.",
            f"location = {rule.path} {{",
            f'    if ({var} = "{value}") {{',
            "        return 403;",
            "    }",
            f"    proxy_pass {upstream_base};",
            "}",
            "# NOTE: gateway stop-gap. The durable fix is an object-ownership",
            "# check in the handler (does this principal own this object?).",
        ]
    )


def _caddy(rule: PrivEscControlRule, upstream_base: str) -> str:
    name, value = (
        rule.attacker_headers[0]
        if rule.attacker_headers
        else ("Authorization", "")
    )
    return "\n".join(
        [
            f"# Sentinel remediation — deny {rule.type} escalation for "
            f"'{rule.attacker_name}' on {rule.method} {rule.path}",
            f"@breach {{",
            f"    method {rule.method}",
            f"    path {rule.path}",
            f'    header {name} "{value}"',
            "}",
            "respond @breach 403",
            f"reverse_proxy {upstream_base}",
        ]
    )


def _envoy(rule: PrivEscControlRule, upstream_base: str) -> str:
    return "\n".join(
        [
            "# Sentinel remediation — Envoy RBAC deny (privilege escalation)",
            f"# upstream: {upstream_base}  match: {rule.method} {rule.path}",
            f"# deny principal '{rule.attacker_name}' identified by: "
            f"{_header_names(rule)}",
            "http_filters:",
            "  - name: envoy.filters.http.rbac",
            "    typed_config:",
            '      "@type": type.googleapis.com/'
            "envoy.extensions.filters.http.rbac.v3.RBAC",
            "      rules:",
            "        action: DENY",
            "        policies:",
            '          "deny-privesc":',
            "            permissions:",
            f"              - header: {{ name: \":path\", exact_match: \"{rule.path}\" }}",
            "            principals:",
            "              - any: true  # scope to the attacker session headers",
        ]
    )


def render_privesc_artifacts(
    rule: PrivEscControlRule,
    upstream_base: str,
) -> PrivEscRemediationArtifacts:
    """Render all deployable access-control enforcement configs."""
    return PrivEscRemediationArtifacts(
        portable_json=_portable_json(rule, upstream_base),
        nginx=_nginx(rule, upstream_base),
        caddy=_caddy(rule, upstream_base),
        envoy=_envoy(rule, upstream_base),
    )


# VERIFY_MARKER


def _path_with_query(url: str) -> str:
    split = urlsplit(url)
    path = split.path or "/"
    if split.query:
        path += "?" + split.query
    return path


def _probe(
    scratch: SecurityGraph,
    executor,
    hypothesis: Hypothesis,
    *,
    tag: str,
    method: str,
    url: str,
    headers,
) -> tuple[str, int | None]:
    """Build → execute → complete one verification probe on the scratch graph."""
    identity = hypothesis.identity
    experiment = Experiment(
        id=f"exp:privesc-remediation:{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="privilege_escalation_check",
        description=f"Privilege-escalation {tag} re-probe.",
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
        capability_id="privilege_escalation.remediation_verification",
        action=f"verify_privilege_escalation_{tag}",
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
    code = int(raw_code) if raw_code is not None else None
    return experiment.id, code


def verify_privesc_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: PrivEscRemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    Re-run the three-probe differential (attacker control + attacker breach +
    anonymous baseline) directly against the target (before) and through the
    enforcement shield (after), judging each with the PURE privesc judge.

    Proven iff the judge FLIPS VALIDATED → DISPROVED: the escalation must
    reproduce live pre-fix (before = VALIDATED) AND stop reproducing under
    enforcement (after = DISPROVED), with the attacker's own control probe still
    succeeding through the shield. Gating on the after judgment alone would let
    a shield take credit for closing something that never reproduced pre-fix.
    """
    headers = plan.rule.attacker_headers

    after_breach_url = enforcer_base.rstrip("/") + _path_with_query(plan.breach_url)
    after_control_url = enforcer_base.rstrip("/") + _path_with_query(plan.control_url)

    # Scratch graph carries ONLY the boundary edges the judge reads, so the
    # real graph's confirmed state is untouchable from here.
    scratch = SecurityGraph()
    for relationship in graph.relationships:
        scratch.add_relationship(relationship)

    target_host = urlsplit(plan.breach_url).netloc.lower()
    control_host = urlsplit(plan.control_url).netloc.lower()
    before_exec = before_executor or PrivEscProbeExecutor(
        allowed_hosts={target_host, control_host},
    )
    after_exec = after_executor or PrivEscProbeExecutor(
        allowed_hosts={urlsplit(enforcer_base).netloc.lower()},
    )

    before_control_id, before_control_code = _probe(
        scratch, before_exec, hypothesis,
        tag="before-control",
        method=plan.control_method,
        url=plan.control_url,
        headers=headers,
    )
    before_breach_id, before_breach_code = _probe(
        scratch, before_exec, hypothesis,
        tag="before-breach",
        method=plan.rule.method,
        url=plan.breach_url,
        headers=headers,
    )
    before_baseline_id, _before_baseline_code = _probe(
        scratch, before_exec, hypothesis,
        tag="before-baseline",
        method=plan.rule.method,
        url=plan.breach_url,
        headers=(),  # anonymous negative control on the breach route
    )
    after_control_id, after_control_code = _probe(
        scratch, after_exec, hypothesis,
        tag="after-control",
        method=plan.control_method,
        url=after_control_url,
        headers=headers,
    )
    after_breach_id, after_breach_code = _probe(
        scratch, after_exec, hypothesis,
        tag="after-breach",
        method=plan.rule.method,
        url=after_breach_url,
        headers=headers,
    )
    after_baseline_id, _after_baseline_code = _probe(
        scratch, after_exec, hypothesis,
        tag="after-baseline",
        method=plan.rule.method,
        url=after_breach_url,
        headers=(),  # anonymous negative control through the shield
    )

    before_judgment = judge_privilege_escalation(
        scratch,
        hypothesis=hypothesis,
        control_experiment_id=before_control_id,
        breach_experiment_id=before_breach_id,
        baseline_experiment_id=before_baseline_id,
    )
    after_judgment = judge_privilege_escalation(
        scratch,
        hypothesis=hypothesis,
        control_experiment_id=after_control_id,
        breach_experiment_id=after_breach_id,
        baseline_experiment_id=after_baseline_id,
    )

    # FIX_PROVEN requires the SAME pure judge to FLIP: the escalation must
    # reproduce live pre-fix (VALIDATED) and stop reproducing under enforcement
    # (DISPROVED). A shield credited with closing something that no longer
    # reproduced on the pre-fix re-probe would be a manufactured proof.
    proven = (
        before_judgment.status == "VALIDATED"
        and after_judgment.status == "DISPROVED"
    )

    if proven:
        reason = (
            "the judge FLIPPED VALIDATED → DISPROVED: pre-fix the escalation "
            "reproduced live, and under enforcement the attacker's control "
            "probe still succeeds while the breach is denied — the privilege "
            "boundary now holds and the escalation no longer reproduces"
        )
    else:
        reason = (
            f"no VALIDATED → DISPROVED flip (before={before_judgment.status}, "
            f"after={after_judgment.status}); the fix is not proven — the "
            "escalation must reproduce pre-fix and stop reproducing under "
            "enforcement (with the attacker's own control access preserved)"
        )

    return RemediationVerification(
        experiment_id=after_breach_id,
        after_status=after_judgment.status,
        before_status=before_judgment.status,
        proven=proven,
        observed_status_code=after_breach_code,
        before_status_code=before_breach_code,
        reason=reason,
    )


def _access_control_rule(rule: PrivEscControlRule) -> AccessControlRule:
    """Lower a PrivEscControlRule to the enforcer's pure deny directive."""
    return AccessControlRule(
        principal_name=rule.attacker_name,
        principal_kind="user",
        method=rule.method,
        path=rule.path,
        action="deny_privilege_escalation",
        decision="deny",
        principal_headers=tuple(rule.attacker_headers),
    )


# REMEDIATE_MARKER


def remediate_privesc_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> PrivEscRemediationOutcome:
    """Synthesize → enforce → prove a corrective access-control rule."""

    plan = synthesize_privesc_remediation(graph, finding)
    if plan is None:
        return PrivEscRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed escalations with a recoverable live breach "
                "probe and a shieldable boundary are remediable here."
            ),
        )

    artifacts = render_privesc_artifacts(plan.rule, plan.upstream_base)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return PrivEscRemediationOutcome(
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
                (_access_control_rule(plan.rule),),
                plan.upstream_base,
            ) as enforcer:
                verification = verify_privesc_remediation(
                    graph,
                    hypothesis=hypothesis,
                    plan=plan,
                    enforcer_base=enforcer.base_url,
                    before_executor=before_executor,
                    after_executor=after_executor,
                )
        else:
            # Injected-executor path (tests): the after executor supplies the
            # enforced responses directly, so no proxy is stood up.
            verification = verify_privesc_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — report cleanly, never raise
        return PrivEscRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=str(exc),
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return PrivEscRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_privesc_findings(
    graph: SecurityGraph,
) -> list[PrivEscRemediationOutcome]:
    """Remediate every OPEN confirmed escalation finding, deterministically."""
    findings = graph.findings_for(
        kind="privilege_escalation",
        status="OPEN",
    )
    findings = sorted(findings, key=lambda item: item.id)
    return [
        remediate_privesc_and_prove(graph, finding) for finding in findings
    ]


