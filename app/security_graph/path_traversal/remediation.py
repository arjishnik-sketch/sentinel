"""
Remediate a confirmed path-traversal / LFI finding — PATCH + PROVE.

The mirror of :mod:`app.security_graph.xss.remediation` for the `path_traversal`
class. The shield is a **request-guard (virtual patch)** with signature family
``traversal``, and the PROVE is the OS-canary differential. From a CONFIRMED
path-traversal finding it:

  * reads the operator-declared surface the judge already used and the live
    control-probe provenance (no re-scoring, no invented semantics),
  * states the one corrective request-guard the contradiction demands — refuse
    to forward this parameter on this route when it carries a directory-escape
    signature (a ``../`` / ``..\\`` escape, an encoded ``%2e%2e``, a NUL byte, or
    a known OS-file name such as ``etc/passwd`` / ``win.ini``),
  * renders deployable provider configs (portable / nginx / ModSecurity / Caddy),
  * stands the *same* enforcement shield up in front of the target with the
    request-guard active, and
  * PROVES the fix only when the PURE :func:`judge_path_traversal` flips
    VALIDATED -> DISPROVED under real enforcement: pre-fix the traversal must
    still reproduce (before = VALIDATED), and under the shield the escape
    payloads are blocked (403) so no OS-file invariant ever reaches the response
    while the benign control filename is still forwarded — the leak is gone.

Nothing here manufactures a verdict. `FIX_PROVEN` is earned solely by the
deterministic judge observing the VALIDATED -> DISPROVED flip on a fresh
differential re-test. The module is target-agnostic: the guard is derived
entirely from the confirmed finding's own provenance. The DURABLE fix is to
canonicalise the resolved path and confirm it stays within an allowlisted base
directory (reject anything whose real path escapes the root) — never hand user
input to a file API directly; the request-guard is only a stop-gap.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import RemediationEnforcer, RequestGuardRule
from ..remediation.model import RemediationVerification
from .executor import PathTraversalProbeExecutor
from .judge import (
    TraversalExpectation,
    traversal_expectation,
    judge_path_traversal,
)
from .traversal_policy import traversal_payloads

@dataclass(frozen=True)
class PathTraversalControlRule:
    """
    The corrective request-guard implied by one confirmed path traversal.

    The shield refuses to forward requests whose `param` (in `location`) on
    `method` `path` carries a directory-escape signature (a ``../`` / ``..\\``
    sequence, an encoded ``%2e%2e``, a NUL byte, or a known OS-file name), and
    forwards everything else — including the benign control filename — to the
    target unchanged.
    """

    method: str
    path: str
    param: str
    location: str
    severity: str = "HIGH"


@dataclass(frozen=True)
class PathTraversalRemediationArtifacts:
    """Deployable virtual-patch configs for the one corrective guard."""

    portable_json: str
    nginx: str
    modsecurity: str
    caddy: str


@dataclass(frozen=True)
class PathTraversalRemediationPlan:
    """The single corrective request-guard the confirmed contradiction demands."""

    finding_id: str
    hypothesis_id: str
    rule: PathTraversalControlRule
    upstream_base: str
    endpoint_url: str
    control: str
    strategy: str = "path_traversal_request_guard"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class PathTraversalRemediationOutcome:
    """PATCH proposal + PROVE result for one confirmed path-traversal finding."""

    finding_id: str
    hypothesis_id: str
    result: str            # FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR
    plan: "PathTraversalRemediationPlan | None" = None
    artifacts: "PathTraversalRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""


def _originating_control_probe(graph: SecurityGraph, hypothesis_id: str):
    """The live COMPLETED control probe that grounded this finding, or None."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "path_traversal_check"
        and experiment.action == "probe_traversal_control"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]
def synthesize_path_traversal_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> PathTraversalRemediationPlan | None:
    """
    Derive the one corrective request-guard a confirmed path traversal demands.

    Returns None for non-traversal findings, for findings whose surface metadata
    cannot be recovered, or for findings with no live control probe to anchor the
    upstream — the module never invents a target.
    """
    if finding.kind != "path_traversal":
        return None
    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    expectation = traversal_expectation(
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

    rule = PathTraversalControlRule(
        method=expectation.method.strip().upper() or "GET",
        path=split.path or "/",
        param=expectation.param,
        location=expectation.location,
        severity=expectation.severity,
    )
    upstream_base = f"{split.scheme}://{split.netloc}"

    rationale = (
        f"Operator matrix declares the '{expectation.param}' parameter of "
        f"{rule.method} {rule.path} ({expectation.location}) MUST NOT read a file "
        "outside its intended directory.",
        "The OS-canary differential CONFIRMED a directory-escape payload leaked an "
        "OS-file invariant (root:x:0:0: / a win.ini section) into the response "
        "while the benign, traversal-free control carried no such invariant — a "
        "real path traversal / LFI, not an app that merely mentions 'root'.",
        "The request-guard refuses to forward this parameter when it carries a "
        "directory-escape signature and forwards all other traffic — including the "
        "benign control filename — unchanged. The DURABLE fix is to canonicalise "
        "the resolved path (os.path.realpath) and reject anything that escapes an "
        "allowlisted base directory; never pass user input to a file API directly.",
    )

    return PathTraversalRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        endpoint_url=expectation.endpoint_url,
        control=expectation.control_value,
        rationale=rationale,
    )
# Best-effort gateway signature matching the common traversal / LFI shapes; the
# enforcer itself uses the richer compiled _TRAVERSAL_SIGNATURES. Both are
# stop-gaps — the durable fix is path canonicalisation confined to a safe root.
_GATEWAY_SIGNATURE = r"(\.\./|\.\.\\|%2e%2e|%252e|(?:etc/passwd|boot\.ini|win\.ini))"


def _portable_json(rule: PathTraversalControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.path_traversal_request_guard/v1",
        "decision": "deny_on_signature",
        "match": {
            "method": rule.method,
            "path": rule.path,
            "param": rule.param,
            "location": rule.location,
        },
        "signature_family": "traversal",
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Block this parameter at the gateway when it carries a directory-escape "
            "signature (a stop-gap virtual patch). The ROOT-CAUSE fix is to "
            "canonicalise the resolved path (os.path.realpath) and reject anything "
            "that escapes an allowlisted base directory; never pass user input to a "
            "file API directly."
        ),
    }
    return json.dumps(spec, indent=2)


def _nginx(rule: PathTraversalControlRule, upstream_base: str) -> str:
    matched = f"$arg_{rule.param}" if rule.location == "query" else "$request_body"
    return "\n".join(
        [
            f"# Sentinel remediation — path-traversal request-guard for '{rule.param}'",
            f"# on {rule.method} {rule.path} ({rule.location}). Benign traffic is forwarded.",
            f"location = {rule.path} {{",
            f'    if ({matched} ~* "{_GATEWAY_SIGNATURE}") {{',
            "        return 403;",
            "    }",
            f"    proxy_pass {upstream_base};",
            "}",
            "# NOTE: gateway stop-gap only. The durable fix is path canonicalisation",
            "# confined to an allowlisted base directory (reject realpath escapes).",
        ]
    )


def _modsecurity(rule: PathTraversalControlRule, upstream_base: str) -> str:
    if rule.location == "query":
        target = f"ARGS_GET:{rule.param}"
    elif rule.location == "body_form":
        target = f"ARGS_POST:{rule.param}"
    else:
        target = f"ARGS:{rule.param}"
    return "\n".join(
        [
            "# Sentinel remediation — ModSecurity virtual patch (path traversal / LFI)",
            f"# upstream: {upstream_base}   match: {rule.method} {rule.path}",
            f'SecRule REQUEST_METHOD "@streq {rule.method}" \\',
            f'    "id:1000006,phase:2,chain,deny,status:403,log,\\',
            f"     msg:'Sentinel: path-traversal request-guard on {rule.param}'\"",
            f'    SecRule REQUEST_URI "@beginsWith {rule.path}" "chain"',
            f'        SecRule {target} "@rx {_GATEWAY_SIGNATURE}" "t:none,t:urlDecodeUni,t:normalizePathWin,t:lowercase"',
            "# NOTE: virtual patch. The durable fix is canonicalise + confine to root.",
        ]
    )


def _caddy(rule: PathTraversalControlRule, upstream_base: str) -> str:
    lines = [
        f"# Sentinel remediation — path-traversal request-guard for '{rule.param}'",
        f"# on {rule.method} {rule.path}. Best-effort matcher; prefer ModSecurity / sink fix.",
        "@traversal {",
        f"    method {rule.method}",
        f"    path {rule.path}",
    ]
    if rule.location == "query":
        lines.append(
            f"    query {rule.param}=*..*  {rule.param}=*etc/passwd*  {rule.param}=*win.ini*"
        )
    else:
        lines.append('    header Content-Type *')
    lines += [
        "}",
        "respond @traversal 403",
        f"reverse_proxy {upstream_base}",
        "# NOTE: gateway stop-gap. The durable fix is canonicalise + confine to root.",
    ]
    return "\n".join(lines)


def render_path_traversal_artifacts(
    rule: PathTraversalControlRule,
    upstream_base: str,
) -> PathTraversalRemediationArtifacts:
    """Render the corrective request-guard as deployable provider configs."""
    return PathTraversalRemediationArtifacts(
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
    expectation: TraversalExpectation,
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
        id=f"exp:traversal-remediation:{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="path_traversal_check",
        description=f"Path-traversal {tag} re-probe under remediation verification.",
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
        capability_id="path_traversal.remediation_verification",
        action=f"verify_traversal_{tag}",
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
    expectation: TraversalExpectation,
    *,
    phase: str,
    endpoint_url: str,
):
    """Run control + escape payloads and hand the ids to the PURE judge."""
    control_id, control_code = _probe(
        scratch, executor, hypothesis, expectation,
        tag=f"{phase}-control", endpoint_url=endpoint_url,
        value=expectation.control_value,
    )
    payload_ids: list[tuple[str, str]] = []
    for label, value in traversal_payloads():
        payload_id, _ = _probe(
            scratch, executor, hypothesis, expectation,
            tag=f"{phase}-payload-{label}", endpoint_url=endpoint_url,
            value=value,
        )
        payload_ids.append((label, payload_id))
    judgment = judge_path_traversal(
        scratch,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_ids=tuple(payload_ids),
    )
    return judgment, control_code


def _request_guard_rule(rule: PathTraversalControlRule) -> RequestGuardRule:
    return RequestGuardRule(
        method=rule.method,
        path=rule.path,
        param=rule.param,
        location=rule.location,
        signature_family="traversal",
    )
def verify_path_traversal_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: PathTraversalRemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    PROVE the fix on a SCRATCH graph seeded with relationships ONLY.

    Runs the full OS-canary differential twice with the PURE judge: BEFORE
    against the live target (must reproduce → VALIDATED) and AFTER through the
    shield with the request-guard active (escape payloads blocked → no OS-file
    invariant ever reaches the response → DISPROVED). `proven` is earned solely
    by that VALIDATED -> DISPROVED flip. This never touches the real graph, never
    calls `apply_validation_judgment` or `materialize_confirmed_findings`, and
    manufactures nothing.
    """
    scratch = SecurityGraph()
    for relationship in graph.relationships:
        scratch.add_relationship(relationship)

    identity = hypothesis.identity
    expectation = None
    if identity is not None and identity.resource_id and identity.action:
        expectation = traversal_expectation(
            scratch, resource_id=identity.resource_id, aspect=identity.action
        )
    if expectation is None or not expectation.param:
        return RemediationVerification(
            experiment_id="",
            after_status="INCONCLUSIVE",
            before_status="INCONCLUSIVE",
            proven=False,
            reason="path-traversal surface metadata unavailable for verification",
        )

    target_endpoint = plan.endpoint_url
    after_endpoint = enforcer_base.rstrip("/") + urlsplit(target_endpoint).path

    target_host = urlsplit(target_endpoint).netloc.lower()
    enforcer_host = urlsplit(enforcer_base).netloc.lower()
    before_exec = before_executor or PathTraversalProbeExecutor(
        allowed_hosts={target_host} if target_host else None
    )
    after_exec = after_executor or PathTraversalProbeExecutor(
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
            "the judge FLIPPED VALIDATED -> DISPROVED: pre-fix an escape payload "
            "leaked an OS-file invariant, and under the request-guard the escape "
            "payloads are blocked (403) so no invariant ever reaches the response "
            "while the benign control filename is still served — the path traversal "
            "no longer reproduces"
        )
    else:
        reason = (
            f"no VALIDATED -> DISPROVED flip (before={before_judgment.status}, "
            f"after={after_judgment.status}); the fix is not proven — the traversal "
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
def remediate_path_traversal_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> PathTraversalRemediationOutcome:
    """
    PATCH + PROVE one confirmed path-traversal finding.

    Synthesises the corrective request-guard, renders deployable artifacts, and
    (when ``use_enforcer``) stands a real :class:`RemediationEnforcer` up in
    front of the target with the guard active, PROVING the fix only if the PURE
    :func:`judge_path_traversal` flips VALIDATED -> DISPROVED. With
    ``use_enforcer=False`` the same verification runs against injected executors
    (offline). The live/real graph is never mutated here.
    """
    plan = synthesize_path_traversal_remediation(graph, finding)
    if plan is None:
        return PathTraversalRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed path traversal with a recoverable live control "
                "probe and a guardable declared surface are remediable here."
            ),
        )

    artifacts = render_path_traversal_artifacts(plan.rule, plan.upstream_base)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return PathTraversalRemediationOutcome(
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
                verification = verify_path_traversal_remediation(
                    graph,
                    hypothesis=hypothesis,
                    plan=plan,
                    enforcer_base=enforcer.base_url,
                    before_executor=before_executor,
                    after_executor=after_executor,
                )
        else:
            verification = verify_path_traversal_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — surface the failure honestly
        return PathTraversalRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=f"verification raised: {exc}",
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return PathTraversalRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_path_traversal_findings(
    graph: SecurityGraph,
) -> list[PathTraversalRemediationOutcome]:
    """Remediate + prove every OPEN confirmed `path_traversal` finding."""
    findings = sorted(
        graph.findings_for(kind="path_traversal", status="OPEN"),
        key=lambda item: item.id,
    )
    return [
        remediate_path_traversal_and_prove(graph, finding) for finding in findings
    ]
