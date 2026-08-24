"""
Remediate a confirmed open-redirect finding — PATCH + PROVE.

The mirror of :mod:`app.security_graph.ssti.remediation` for the `open_redirect`
class. The shield is a **request-guard (virtual patch)** with signature family
``url_allowlist``, and the PROVE is the two-probe host differential. From a
CONFIRMED open-redirect finding it:

  * reads the operator-declared surface the judge already used and the live
    control-probe provenance (no re-scoring, no invented semantics),
  * states the one corrective request-guard the contradiction demands — refuse
    to forward this parameter on this route when it carries an off-origin URL
    whose host is not on the engagement allowlist (the target's own host),
  * renders deployable provider configs (portable / nginx / ModSecurity / Caddy),
  * stands the *same* enforcement shield up in front of the target with the
    request-guard active, and
  * PROVES the fix only when the PURE :func:`judge_open_redirect` flips
    VALIDATED -> DISPROVED under real enforcement: pre-fix the open redirect must
    still reproduce (before = VALIDATED), and under the shield the off-origin
    payload is blocked (403) so the ``Location`` never carries the nonce host
    while the benign same-origin control is still forwarded — the redirect is no
    longer attacker-controlled.

Nothing here manufactures a verdict. `FIX_PROVEN` is earned solely by the
deterministic judge observing the VALIDATED -> DISPROVED flip on a fresh
differential re-test. The module is target-agnostic: the guard (and its host
allowlist) is derived entirely from the confirmed finding's own provenance. The
DURABLE fix is to never build a redirect target from raw user input — validate
against a strict server-side allowlist, or only ever redirect to relative paths.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import RemediationEnforcer, RequestGuardRule
from ..remediation.model import RemediationVerification
from .executor import OpenRedirectProbeExecutor
from .judge import (
    OpenRedirectExpectation,
    open_redirect_expectation,
    judge_open_redirect,
)

@dataclass(frozen=True)
class OpenRedirectControlRule:
    """
    The corrective request-guard implied by one confirmed open redirect.

    The shield refuses to forward requests whose `param` (in `location`) on
    `method` `path` carries an off-origin URL whose host is not `allow_host`
    (the engagement target's own host), and forwards everything else — including
    the benign same-origin control — to the target unchanged.
    """

    method: str
    path: str
    param: str
    location: str
    allow_host: str
    severity: str = "MEDIUM"


@dataclass(frozen=True)
class OpenRedirectRemediationArtifacts:
    """Deployable virtual-patch configs for the one corrective guard."""

    portable_json: str
    nginx: str
    modsecurity: str
    caddy: str


@dataclass(frozen=True)
class OpenRedirectRemediationPlan:
    """The single corrective request-guard the confirmed contradiction demands."""

    finding_id: str
    hypothesis_id: str
    rule: OpenRedirectControlRule
    upstream_base: str
    endpoint_url: str
    nonce_host: str
    payload_url: str
    control_url: str
    strategy: str = "open_redirect_request_guard"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class OpenRedirectRemediationOutcome:
    """PATCH proposal + PROVE result for one confirmed open-redirect finding."""

    finding_id: str
    hypothesis_id: str
    result: str            # FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR
    plan: "OpenRedirectRemediationPlan | None" = None
    artifacts: "OpenRedirectRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""


def _originating_control_probe(graph: SecurityGraph, hypothesis_id: str):
    """The live COMPLETED same-origin control probe that grounded this finding."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "open_redirect_check"
        and experiment.action == "probe_open_redirect_control"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]


def synthesize_open_redirect_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> OpenRedirectRemediationPlan | None:
    """
    Derive the one corrective request-guard a confirmed open redirect demands.

    Returns None for non-open-redirect findings, for findings whose surface
    metadata cannot be recovered, or for findings with no live control probe to
    anchor the upstream — the module never invents a target.
    """
    if finding.kind != "open_redirect":
        return None
    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    expectation = open_redirect_expectation(
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

    allow_host = expectation.target_host or (split.hostname or "").lower()
    rule = OpenRedirectControlRule(
        method=expectation.method.strip().upper() or "GET",
        path=split.path or "/",
        param=expectation.param,
        location=expectation.location,
        allow_host=allow_host,
        severity=expectation.severity,
    )
    upstream_base = f"{split.scheme}://{split.netloc}"

    rationale = (
        f"Operator matrix declares the '{expectation.param}' parameter of "
        f"{rule.method} {rule.path} ({expectation.location}) MUST NOT redirect "
        "off-origin.",
        "The two-probe host differential CONFIRMED the off-origin payload "
        f"redirected to the unforgeable nonce host '{expectation.nonce_host}' "
        "while the same-origin control anchor proved the endpoint legitimately "
        "redirects on-origin — a real open redirect, not a fixed destination.",
        "The request-guard refuses to forward this parameter when it carries an "
        f"off-origin URL whose host is not '{allow_host}', and forwards all other "
        "traffic — including the benign same-origin control — unchanged. The "
        "DURABLE fix is to never build a redirect target from raw user input: "
        "validate against a strict server-side allowlist, or only redirect to "
        "relative paths.",
    )

    return OpenRedirectRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        endpoint_url=expectation.endpoint_url,
        nonce_host=expectation.nonce_host,
        payload_url=expectation.payload_url,
        control_url=expectation.control_url,
        rationale=rationale,
    )

import re as _re


def _off_origin_signature(allow_host: str) -> str:
    """
    A best-effort gateway regex matching an OFF-ORIGIN absolute redirect value.

    Matches an absolute (``scheme://host`` or protocol-relative ``//host``) URL
    whose host is NOT ``allow_host`` — the shape the durable fix must reject. A
    relative path (no host) never matches, so the benign same-origin control is
    forwarded. This is a stop-gap; the enforcer itself uses the exact
    :func:`_matches_url_allowlist` host check, not this regex.
    """
    host = _re.escape(allow_host or "")
    # (?:https?:)?//  → absolute or protocol-relative; (?!<host>[:/]) → not our host.
    return rf"^\s*(?:https?:)?//(?!{host}[:/])" if host else r"^\s*(?:https?:)?//"


def _portable_json(rule: OpenRedirectControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.open_redirect_request_guard/v1",
        "decision": "deny_off_origin_redirect",
        "match": {
            "method": rule.method,
            "path": rule.path,
            "param": rule.param,
            "location": rule.location,
        },
        "signature_family": "url_allowlist",
        "allow_hosts": [rule.allow_host],
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Block this parameter at the gateway when it carries an off-origin "
            "URL whose host is not on the allowlist (a stop-gap virtual patch). "
            "The ROOT-CAUSE fix is to never build a redirect target from raw user "
            "input — validate against a strict server-side allowlist, or only "
            "redirect to relative paths."
        ),
    }
    return json.dumps(spec, indent=2)


def _nginx(rule: OpenRedirectControlRule, upstream_base: str) -> str:
    matched = f"$arg_{rule.param}" if rule.location == "query" else "$request_body"
    signature = _off_origin_signature(rule.allow_host)
    return "\n".join(
        [
            f"# Sentinel remediation — open-redirect request-guard for '{rule.param}'",
            f"# on {rule.method} {rule.path} ({rule.location}). Same-origin traffic is forwarded.",
            f"location = {rule.path} {{",
            f'    if ({matched} ~* "{signature}") {{',
            "        return 403;",
            "    }",
            f"    proxy_pass {upstream_base};",
            "}",
            "# NOTE: gateway stop-gap only. The durable fix is to never build a",
            "# redirect target from raw user input (server-side allowlist / relative paths).",
        ]
    )


def _modsecurity(rule: OpenRedirectControlRule, upstream_base: str) -> str:
    if rule.location == "query":
        target = f"ARGS_GET:{rule.param}"
    elif rule.location == "body_form":
        target = f"ARGS_POST:{rule.param}"
    else:
        target = f"ARGS:{rule.param}"
    signature = _off_origin_signature(rule.allow_host)
    return "\n".join(
        [
            "# Sentinel remediation — ModSecurity virtual patch (open redirect)",
            f"# upstream: {upstream_base}   match: {rule.method} {rule.path}",
            f'SecRule REQUEST_METHOD "@streq {rule.method}" \\',
            f'    "id:1000009,phase:2,chain,deny,status:403,log,\\',
            f"     msg:'Sentinel: open-redirect request-guard on {rule.param}'\"",
            f'    SecRule REQUEST_URI "@beginsWith {rule.path}" "chain"',
            f'        SecRule {target} "@rx {signature}" "t:none,t:urlDecodeUni,t:lowercase"',
            "# NOTE: virtual patch. The durable fix is a server-side redirect allowlist.",
        ]
    )


def _caddy(rule: OpenRedirectControlRule, upstream_base: str) -> str:
    lines = [
        f"# Sentinel remediation — open-redirect request-guard for '{rule.param}'",
        f"# on {rule.method} {rule.path}. Best-effort matcher; prefer ModSecurity / handler fix.",
        "@open_redirect {",
        f"    method {rule.method}",
        f"    path {rule.path}",
    ]
    if rule.location == "query":
        lines.append(f"    query {rule.param}=http://* {rule.param}=https://* {rule.param}=//*")
    else:
        lines.append('    header Content-Type *')
    lines += [
        "}",
        "respond @open_redirect 403",
        f"reverse_proxy {upstream_base}",
        "# NOTE: gateway stop-gap. Caddy cannot express the host allowlist exactly;",
        "# the durable fix is a server-side redirect allowlist / relative paths.",
    ]
    return "\n".join(lines)


def render_open_redirect_artifacts(
    rule: OpenRedirectControlRule,
    upstream_base: str,
) -> OpenRedirectRemediationArtifacts:
    """Render the corrective request-guard as deployable provider configs."""
    return OpenRedirectRemediationArtifacts(
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
    expectation: OpenRedirectExpectation,
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
        id=f"exp:open-redirect-remediation:{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="open_redirect_check",
        description=f"open-redirect {tag} re-probe under remediation verification.",
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
        capability_id="open_redirect.remediation_verification",
        action=f"verify_open_redirect_{tag}",
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
    expectation: OpenRedirectExpectation,
    *,
    phase: str,
    endpoint_url: str,
):
    """Run same-origin control + off-origin payload and hand ids to the PURE judge."""
    control_id, _control_code = _probe(
        scratch, executor, hypothesis, expectation,
        tag=f"{phase}-control", endpoint_url=endpoint_url,
        value=expectation.control_url,
    )
    payload_id, payload_code = _probe(
        scratch, executor, hypothesis, expectation,
        tag=f"{phase}-payload", endpoint_url=endpoint_url,
        value=expectation.payload_url,
    )
    judgment = judge_open_redirect(
        scratch,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_id=payload_id,
    )
    return judgment, payload_code


def _request_guard_rule(rule: OpenRedirectControlRule) -> RequestGuardRule:
    return RequestGuardRule(
        method=rule.method,
        path=rule.path,
        param=rule.param,
        location=rule.location,
        signature_family="url_allowlist",
        allow=(rule.allow_host,),
    )

def verify_open_redirect_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: OpenRedirectRemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    PROVE the fix on a SCRATCH graph seeded with relationships ONLY.

    Runs the full two-probe host differential twice with the PURE judge: BEFORE
    against the live target (must reproduce → VALIDATED) and AFTER through the
    shield with the request-guard active (the off-origin payload blocked → the
    Location never carries the nonce host → DISPROVED). `proven` is earned solely
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
        expectation = open_redirect_expectation(
            scratch, resource_id=identity.resource_id, aspect=identity.action
        )
    if expectation is None or not expectation.param:
        return RemediationVerification(
            experiment_id="",
            after_status="INCONCLUSIVE",
            before_status="INCONCLUSIVE",
            proven=False,
            reason="open-redirect surface metadata unavailable for verification",
        )

    target_endpoint = plan.endpoint_url
    after_endpoint = enforcer_base.rstrip("/") + urlsplit(target_endpoint).path

    target_host = urlsplit(target_endpoint).netloc.lower()
    enforcer_host = urlsplit(enforcer_base).netloc.lower()
    before_exec = before_executor or OpenRedirectProbeExecutor(
        allowed_hosts={target_host} if target_host else None
    )
    after_exec = after_executor or OpenRedirectProbeExecutor(
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
            "the judge FLIPPED VALIDATED -> DISPROVED: pre-fix the off-origin "
            "payload redirected to the nonce host, and under the request-guard "
            "the off-origin value is blocked (403) so the Location never carries "
            "the nonce host while the benign same-origin control is still served "
            "— the redirect is no longer attacker-controlled"
        )
    else:
        reason = (
            f"no VALIDATED -> DISPROVED flip (before={before_judgment.status}, "
            f"after={after_judgment.status}); the fix is not proven — the open "
            "redirect must reproduce pre-fix and stop reproducing under the "
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


def remediate_open_redirect_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> OpenRedirectRemediationOutcome:
    """
    PATCH + PROVE one confirmed open-redirect finding.

    Synthesises the corrective request-guard, renders deployable artifacts, and
    (when ``use_enforcer``) stands a real :class:`RemediationEnforcer` up in
    front of the target with the guard active, PROVING the fix only if the PURE
    :func:`judge_open_redirect` flips VALIDATED -> DISPROVED. With
    ``use_enforcer=False`` the same verification runs against injected executors
    (offline). The live/real graph is never mutated here.
    """
    plan = synthesize_open_redirect_remediation(graph, finding)
    if plan is None:
        return OpenRedirectRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed open redirects with a recoverable live control "
                "probe and a guardable declared surface are remediable here."
            ),
        )

    artifacts = render_open_redirect_artifacts(plan.rule, plan.upstream_base)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return OpenRedirectRemediationOutcome(
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
                verification = verify_open_redirect_remediation(
                    graph,
                    hypothesis=hypothesis,
                    plan=plan,
                    enforcer_base=enforcer.base_url,
                    before_executor=before_executor,
                    after_executor=after_executor,
                )
        else:
            verification = verify_open_redirect_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — surface the failure honestly
        return OpenRedirectRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=f"verification raised: {exc}",
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return OpenRedirectRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_open_redirect_findings(
    graph: SecurityGraph,
) -> list[OpenRedirectRemediationOutcome]:
    """Remediate + prove every OPEN confirmed `open_redirect` finding."""
    findings = sorted(
        graph.findings_for(kind="open_redirect", status="OPEN"),
        key=lambda item: item.id,
    )
    return [
        remediate_open_redirect_and_prove(graph, finding) for finding in findings
    ]




