"""
Remediate a confirmed injection finding — PATCH + PROVE.

The mirror of :mod:`app.security_graph.privesc.remediation` for the `injection`
class, but the shield is a **request-guard (virtual patch)** rather than an
access-control deny, and the PROVE is the three-way boolean differential. From a
CONFIRMED injection finding it:

  * reads the operator-declared injectable surface the judge already used and the
    live baseline-probe provenance (no re-scoring, no invented semantics),
  * states the one corrective request-guard the contradiction demands — refuse
    to forward this parameter on this route when it carries a SQL-injection
    signature,
  * renders deployable provider configs (portable / nginx / ModSecurity / Caddy),
  * stands the *same* enforcement shield up in front of the target with the
    request-guard active, and
  * PROVES the fix only when the PURE :func:`judge_injection` flips
    VALIDATED -> DISPROVED under real enforcement: pre-fix the injection must
    still reproduce (before = VALIDATED), and under the shield the boolean
    payloads are blocked (403) so TRUE and FALSE collapse to an identical
    response while the benign baseline is still forwarded — the differential is
    gone.

Nothing here manufactures a verdict. `FIX_PROVEN` is earned solely by the
deterministic judge observing the VALIDATED -> DISPROVED flip on a fresh
differential re-test. The module is target-agnostic: the guard is derived
entirely from the confirmed finding's own provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import RemediationEnforcer, RequestGuardRule
from ..remediation.model import RemediationVerification
from .executor import InjectionProbeExecutor
from .injection_policy import (
    boolean_payload_pairs,
    quote_parity_payloads,
    time_delay_payloads,
)
from .judge import InjectionExpectation, injection_expectation, judge_injection

# Time-based blind re-probes: the delay arm's request timeout is bumped well
# above the injected sleep so a real backend delay completes and is measured in
# the BEFORE phase, while under the shield the same payload is blocked (403) and
# returns fast — the excess collapses and the time arm goes silent, part of the
# VALIDATED -> DISPROVED flip.
_TIME_PROBE_TIMEOUT = 20.0

@dataclass(frozen=True)
class InjectionControlRule:
    """
    The corrective request-guard implied by one confirmed injection.

    The shield refuses to forward requests whose `param` (in `location`) on
    `method` `path` carries a SQL-injection signature, and forwards everything
    else — including the benign baseline value — to the target unchanged.
    """

    method: str
    path: str
    param: str
    location: str
    severity: str = "HIGH"


@dataclass(frozen=True)
class InjectionRemediationArtifacts:
    """Deployable virtual-patch configs for the one corrective guard."""

    portable_json: str
    nginx: str
    modsecurity: str
    caddy: str


@dataclass(frozen=True)
class InjectionRemediationPlan:
    """The single corrective request-guard the confirmed contradiction demands."""

    finding_id: str
    hypothesis_id: str
    rule: InjectionControlRule
    upstream_base: str
    endpoint_url: str
    baseline_value: str
    strategy: str = "injection_request_guard"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class InjectionRemediationOutcome:
    """PATCH proposal + PROVE result for one confirmed injection finding."""

    finding_id: str
    hypothesis_id: str
    result: str            # FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR
    plan: "InjectionRemediationPlan | None" = None
    artifacts: "InjectionRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""

def _originating_baseline_probe(graph: SecurityGraph, hypothesis_id: str):
    """The live COMPLETED baseline probe that grounded this finding, or None."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "injection_check"
        and experiment.action == "probe_injection_baseline"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]


def synthesize_injection_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> InjectionRemediationPlan | None:
    """
    Derive the one corrective request-guard a confirmed injection demands.

    Returns None for non-injection findings, for findings whose injectable
    surface metadata cannot be recovered, or for findings with no live baseline
    probe to anchor the upstream — the module never invents a target.
    """
    if finding.kind != "injection":
        return None
    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    expectation = injection_expectation(
        graph, resource_id=identity.resource_id, aspect=identity.action
    )
    if expectation is None or not expectation.param:
        return None
    probe = _originating_baseline_probe(graph, finding.hypothesis_id)
    if probe is None or probe.request is None:
        return None
    split = urlsplit(probe.request.url)
    if not split.scheme or not split.netloc:
        return None

    rule = InjectionControlRule(
        method=expectation.method.strip().upper() or "GET",
        path=split.path or "/",
        param=expectation.param,
        location=expectation.location,
        severity=expectation.severity,
    )
    upstream_base = f"{split.scheme}://{split.netloc}"

    rationale = (
        f"Operator matrix declares the '{expectation.param}' parameter of "
        f"{rule.method} {rule.path} ({expectation.location}) MUST NOT alter the "
        "backend query.",
        "The three-way boolean differential CONFIRMED a length-matched payload "
        "toggled the response while one arm reproduced the legitimate baseline — "
        "a real SQL injection, not a reflected value.",
        "The request-guard refuses to forward this parameter when it carries a "
        "SQL-injection signature and forwards all other traffic — including the "
        "benign value — unchanged. The DURABLE fix is a parameterised (prepared) "
        "query in the handler so the parameter can never change the query shape.",
    )

    return InjectionRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        endpoint_url=expectation.endpoint_url,
        baseline_value=expectation.baseline_value,
        rationale=rationale,
    )

def _portable_json(rule: InjectionControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.injection_request_guard/v1",
        "decision": "deny_on_signature",
        "match": {
            "method": rule.method,
            "path": rule.path,
            "param": rule.param,
            "location": rule.location,
        },
        "signature_family": "sql_injection_boolean_union_comment",
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Block this parameter at the gateway when it carries a SQL-injection "
            "signature (a stop-gap virtual patch). The ROOT-CAUSE fix is a "
            "parameterised/prepared query in the handler so the parameter can "
            "never change the query's structure."
        ),
    }
    return json.dumps(spec, indent=2)


# Best-effort gateway signature; the enforcer itself uses the richer compiled
# _SQLI_SIGNATURES. Both are stop-gaps — the durable fix is a prepared statement.
_GATEWAY_SIGNATURE = r"(\x27|\x22|;|--|/\*|\bunion\b|\b(or|and)\b\s+[\x27\x22]?\d|\d\s*=\s*\d)"


def _nginx(rule: InjectionControlRule, upstream_base: str) -> str:
    matched = f"$arg_{rule.param}" if rule.location == "query" else "$request_body"
    return "\n".join(
        [
            f"# Sentinel remediation — SQL-injection request-guard for '{rule.param}'",
            f"# on {rule.method} {rule.path} ({rule.location}). Benign traffic is forwarded.",
            f"location = {rule.path} {{",
            f'    if ({matched} ~* "{_GATEWAY_SIGNATURE}") {{',
            "        return 403;",
            "    }",
            f"    proxy_pass {upstream_base};",
            "}",
            "# NOTE: gateway stop-gap only. The durable fix is a parameterised",
            "# (prepared-statement) query in the handler.",
        ]
    )


def _modsecurity(rule: InjectionControlRule, upstream_base: str) -> str:
    if rule.location == "query":
        target = f"ARGS_GET:{rule.param}"
    elif rule.location == "body_form":
        target = f"ARGS_POST:{rule.param}"
    else:
        target = f"ARGS:{rule.param}"
    return "\n".join(
        [
            "# Sentinel remediation — ModSecurity virtual patch (SQL injection)",
            f"# upstream: {upstream_base}   match: {rule.method} {rule.path}",
            f'SecRule REQUEST_METHOD "@streq {rule.method}" \\',
            f'    "id:1000001,phase:2,chain,deny,status:403,log,\\',
            f"     msg:'Sentinel: SQLi request-guard on {rule.param}'\"",
            f'    SecRule REQUEST_URI "@beginsWith {rule.path}" "chain"',
            f'        SecRule {target} "@detectSQLi" "t:none,t:urlDecodeUni"',
            "# NOTE: virtual patch. The durable fix is a parameterised query.",
        ]
    )


def _caddy(rule: InjectionControlRule, upstream_base: str) -> str:
    lines = [
        f"# Sentinel remediation — SQL-injection request-guard for '{rule.param}'",
        f"# on {rule.method} {rule.path}. Best-effort matcher; prefer ModSecurity / handler fix.",
        "@sqli {",
        f"    method {rule.method}",
        f"    path {rule.path}",
    ]
    if rule.location == "query":
        lines.append(f"    query {rule.param}=*'* {rule.param}=*--* {rule.param}=*=*")
    else:
        lines.append('    header Content-Type *')
    lines += [
        "}",
        "respond @sqli 403",
        f"reverse_proxy {upstream_base}",
        "# NOTE: gateway stop-gap. The durable fix is a parameterised query.",
    ]
    return "\n".join(lines)


def render_injection_artifacts(
    rule: InjectionControlRule,
    upstream_base: str,
) -> InjectionRemediationArtifacts:
    """Render the corrective request-guard as deployable provider configs."""
    return InjectionRemediationArtifacts(
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
    expectation: InjectionExpectation,
    *,
    tag: str,
    endpoint_url: str,
    value: str,
    timeout: float = 10.0,
) -> tuple[str, int | None]:
    """Build → execute → complete one re-probe on the scratch graph."""
    identity = hypothesis.identity
    url, body, headers = _inject(
        endpoint_url, expectation.param, expectation.location, value
    )
    experiment = Experiment(
        id=f"exp:injection-remediation:{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="injection_check",
        description=f"Injection {tag} re-probe under remediation verification.",
        status="PLANNED",
        request=HttpRequestSpec(
            method=expectation.method,
            url=url,
            headers=headers,
            body=body,
            timeout=timeout,
            principal_id=identity.principal_id,
            resource_id=identity.resource_id,
            action=identity.action,
        ),
        capability_id="injection.remediation_verification",
        action=f"verify_injection_{tag}",
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
    expectation: InjectionExpectation,
    *,
    phase: str,
    endpoint_url: str,
):
    """Run baseline + boolean pairs and hand the ids to the PURE judge."""
    baseline_id, baseline_code = _probe(
        scratch, executor, hypothesis, expectation,
        tag=f"{phase}-baseline", endpoint_url=endpoint_url,
        value=expectation.baseline_value,
    )
    pairs, _ = boolean_payload_pairs(expectation.baseline_value)
    pair_ids: list[tuple[str, str]] = []
    for index, (true_value, false_value) in enumerate(pairs):
        true_id, _ = _probe(
            scratch, executor, hypothesis, expectation,
            tag=f"{phase}-true-{index}", endpoint_url=endpoint_url,
            value=true_value,
        )
        false_id, _ = _probe(
            scratch, executor, hypothesis, expectation,
            tag=f"{phase}-false-{index}", endpoint_url=endpoint_url,
            value=false_value,
        )
        pair_ids.append((true_id, false_id))
    # Error-based (quote-parity) arm, re-run identically under the shield so a
    # string-literal injection CONFIRMED via quote parity also flips to DISPROVED
    # once the request-guard blocks the quote payloads (odd and even both 403 ->
    # the parity is gone) while the benign baseline is still forwarded.
    parity_ids: list[tuple[str, str]] = []
    for index, (odd_value, even_value) in enumerate(
        quote_parity_payloads(expectation.baseline_value)
    ):
        odd_id, _ = _probe(
            scratch, executor, hypothesis, expectation,
            tag=f"{phase}-oddquote-{index}", endpoint_url=endpoint_url,
            value=odd_value,
        )
        even_id, _ = _probe(
            scratch, executor, hypothesis, expectation,
            tag=f"{phase}-evenquote-{index}", endpoint_url=endpoint_url,
            value=even_value,
        )
        parity_ids.append((odd_id, even_id))
    # Time-based BLIND arm, re-run identically in both phases. Pre-fix a delay
    # payload makes the backend sleep (delay arm slow vs its zero-delay control);
    # under the shield the same payload is blocked (403) and returns fast, so the
    # excess collapses and the time arm goes silent — the differential is gone.
    time_ids: list[tuple[str, str]] = []
    for index, (delay_value, control_value) in enumerate(
        time_delay_payloads(expectation.baseline_value)
    ):
        delay_id, _ = _probe(
            scratch, executor, hypothesis, expectation,
            tag=f"{phase}-timedelay-{index}", endpoint_url=endpoint_url,
            value=delay_value, timeout=_TIME_PROBE_TIMEOUT,
        )
        control_id, _ = _probe(
            scratch, executor, hypothesis, expectation,
            tag=f"{phase}-timecontrol-{index}", endpoint_url=endpoint_url,
            value=control_value, timeout=_TIME_PROBE_TIMEOUT,
        )
        time_ids.append((delay_id, control_id))
    judgment = judge_injection(
        scratch,
        hypothesis=hypothesis,
        baseline_experiment_id=baseline_id,
        pair_experiment_ids=tuple(pair_ids),
        parity_experiment_ids=tuple(parity_ids),
        time_experiment_ids=tuple(time_ids),
    )
    return judgment, baseline_code

def _request_guard_rule(rule: InjectionControlRule) -> RequestGuardRule:
    return RequestGuardRule(
        method=rule.method,
        path=rule.path,
        param=rule.param,
        location=rule.location,
    )


def verify_injection_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: InjectionRemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    PROVE the fix on a SCRATCH graph seeded with relationships ONLY.

    Runs the full boolean differential twice with the PURE judge: BEFORE against
    the live target (must reproduce → VALIDATED) and AFTER through the shield
    with the request-guard active (payloads blocked → TRUE and FALSE collapse →
    DISPROVED). `proven` is earned solely by that VALIDATED -> DISPROVED flip.
    This never touches the real graph, never calls `apply_validation_judgment`
    or `materialize_confirmed_findings`, and manufactures nothing.
    """
    scratch = SecurityGraph()
    for relationship in graph.relationships:
        scratch.add_relationship(relationship)

    identity = hypothesis.identity
    expectation = None
    if identity is not None and identity.resource_id and identity.action:
        expectation = injection_expectation(
            scratch, resource_id=identity.resource_id, aspect=identity.action
        )
    if expectation is None or not expectation.param:
        return RemediationVerification(
            experiment_id="",
            after_status="INCONCLUSIVE",
            before_status="INCONCLUSIVE",
            proven=False,
            reason="injectable surface metadata unavailable for verification",
        )

    target_endpoint = plan.endpoint_url
    after_endpoint = enforcer_base.rstrip("/") + urlsplit(target_endpoint).path

    target_host = urlsplit(target_endpoint).netloc.lower()
    enforcer_host = urlsplit(enforcer_base).netloc.lower()
    before_exec = before_executor or InjectionProbeExecutor(
        allowed_hosts={target_host} if target_host else None
    )
    after_exec = after_executor or InjectionProbeExecutor(
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
            "the judge FLIPPED VALIDATED -> DISPROVED: pre-fix a length-matched "
            "boolean payload toggled the response, and under the request-guard "
            "the payloads are blocked (403) so TRUE and FALSE collapse to an "
            "identical response while the benign baseline is still served — the "
            "injection no longer reproduces"
        )
    else:
        reason = (
            f"no VALIDATED -> DISPROVED flip (before={before_judgment.status}, "
            f"after={after_judgment.status}); the fix is not proven — the "
            "injection must reproduce pre-fix and stop reproducing under the "
            "request-guard"
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
def remediate_injection_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> InjectionRemediationOutcome:
    """
    PATCH + PROVE one confirmed injection finding.

    Synthesises the corrective request-guard, renders deployable artifacts, and
    (when ``use_enforcer``) stands a real :class:`RemediationEnforcer` up in
    front of the target with the guard active, PROVING the fix only if the PURE
    :func:`judge_injection` flips VALIDATED -> DISPROVED. With
    ``use_enforcer=False`` the same verification runs against injected executors
    (offline). The live/real graph is never mutated here.
    """
    plan = synthesize_injection_remediation(graph, finding)
    if plan is None:
        return InjectionRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed injections with a recoverable live baseline "
                "probe and a guardable declared surface are remediable here."
            ),
        )

    artifacts = render_injection_artifacts(plan.rule, plan.upstream_base)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return InjectionRemediationOutcome(
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
                verification = verify_injection_remediation(
                    graph,
                    hypothesis=hypothesis,
                    plan=plan,
                    enforcer_base=enforcer.base_url,
                    before_executor=before_executor,
                    after_executor=after_executor,
                )
        else:
            verification = verify_injection_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — surface the failure honestly
        return InjectionRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=f"verification raised: {exc}",
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return InjectionRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_injection_findings(
    graph: SecurityGraph,
) -> list[InjectionRemediationOutcome]:
    """Remediate + prove every OPEN confirmed `injection` finding."""
    findings = sorted(
        graph.findings_for(kind="injection", status="OPEN"),
        key=lambda item: item.id,
    )
    return [remediate_injection_and_prove(graph, finding) for finding in findings]






