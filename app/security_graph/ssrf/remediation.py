"""
Remediate a confirmed SSRF finding — PATCH + PROVE.

The mirror of :mod:`app.security_graph.open_redirect.remediation` for the `ssrf`
class. The shield is the SAME **request-guard (virtual patch)** with signature
family ``url_allowlist`` — SSRF reuses it verbatim, so remediation is wiring, not
new enforcement logic — and the PROVE is the two-probe out-of-band callback
differential. From a CONFIRMED SSRF finding it:

  * reads the operator-declared fetch surface the judge already used and the live
    payload-probe provenance (no re-scoring, no invented semantics),
  * states the one corrective request-guard the contradiction demands — refuse
    to forward this parameter on this route when it carries a URL whose host:port
    is not the engagement target's own (an egress allowlist of exactly one
    destination: the target itself),
  * renders deployable provider configs (portable / nginx / ModSecurity / Caddy),
  * stands the *same* enforcement shield up in front of the target with the guard
    active, and
  * PROVES the fix only when the PURE :func:`judge_ssrf` flips VALIDATED ->
    DISPROVED under real enforcement: pre-fix the SSRF must still reproduce
    (before = VALIDATED, the collaborator is hit on a FRESH nonce) and under the
    shield the collaborator URL is refused (403) so no callback lands (after =
    DISPROVED) while a benign same-origin control is still forwarded.

Fresh distinct nonces are minted for EVERY probe round (before and after), so a
long-lived collaborator cannot leak a stale before-hit into the after round.
Nothing here manufactures a verdict; `FIX_PROVEN` is earned solely by the
deterministic judge observing the VALIDATED -> DISPROVED flip. The DURABLE fix is
to allowlist egress destinations and block loopback / link-local / metadata
ranges at the fetch layer (documented in the artifact).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import random
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..graph import SecurityGraph
from ..models import Evidence, Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import RemediationEnforcer, RequestGuardRule
from ..remediation.model import RemediationVerification
from .collaborator import SentinelCollaborator
from .executor import SsrfProbeExecutor
from .judge import SsrfExpectation, ssrf_expectation, judge_ssrf
from .run import _distinct_nonces, _same_origin_control


@dataclass(frozen=True)
class SsrfControlRule:
    """
    The corrective request-guard implied by one confirmed SSRF.

    The shield refuses to forward requests whose `param` (in `location`) on
    `method` `path` carries a URL whose ``host:port`` is not `allow_netloc` (the
    engagement target's own destination), and forwards everything else — including
    the benign same-origin control — to the target unchanged. `allow_netloc` is
    the target's exact ``host:port`` (not a bare host) so a same-host loopback
    collaborator on a DIFFERENT port is still refused.
    """

    method: str
    path: str
    param: str
    location: str
    allow_netloc: str
    severity: str = "HIGH"


@dataclass(frozen=True)
class SsrfRemediationArtifacts:
    """Deployable virtual-patch configs for the one corrective guard."""

    portable_json: str
    nginx: str
    modsecurity: str
    caddy: str


@dataclass(frozen=True)
class SsrfRemediationPlan:
    """The single corrective request-guard the confirmed contradiction demands."""

    finding_id: str
    hypothesis_id: str
    rule: SsrfControlRule
    upstream_base: str
    endpoint_url: str
    target_netloc: str
    strategy: str = "ssrf_egress_allowlist_guard"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class SsrfRemediationOutcome:
    """PATCH proposal + PROVE result for one confirmed SSRF finding."""

    finding_id: str
    hypothesis_id: str
    result: str            # FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR
    plan: "SsrfRemediationPlan | None" = None
    artifacts: "SsrfRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""


def _originating_payload_probe(graph: SecurityGraph, hypothesis_id: str):
    """The live COMPLETED payload probe that grounded this finding."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "ssrf_check"
        and experiment.action == "probe_ssrf_payload"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]


def synthesize_ssrf_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> SsrfRemediationPlan | None:
    """
    Derive the one corrective request-guard a confirmed SSRF demands.

    Returns None for non-SSRF findings, for findings whose surface metadata
    cannot be recovered, or for findings with no live payload probe to anchor the
    upstream — the module never invents a target.
    """
    if finding.kind != "ssrf":
        return None
    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    expectation = ssrf_expectation(
        graph, resource_id=identity.resource_id, aspect=identity.action
    )
    if expectation is None or not expectation.param:
        return None
    probe = _originating_payload_probe(graph, finding.hypothesis_id)
    if probe is None or probe.request is None:
        return None
    split = urlsplit(probe.request.url)
    if not split.scheme or not split.netloc:
        return None

    target_netloc = (split.netloc or "").lower()
    rule = SsrfControlRule(
        method=expectation.method.strip().upper() or "GET",
        path=split.path or "/",
        param=expectation.param,
        location=expectation.location,
        allow_netloc=target_netloc,
        severity=expectation.severity,
    )
    upstream_base = f"{split.scheme}://{split.netloc}"

    rationale = (
        f"Operator matrix declares the '{expectation.param}' parameter of "
        f"{rule.method} {rule.path} ({expectation.location}) MUST NOT be coerced "
        "into a server-side fetch of an attacker-chosen URL.",
        "The out-of-band callback differential CONFIRMED that the payload URL was "
        "fetched server-side — Sentinel's loopback collaborator recorded a request "
        "on the unforgeable payload nonce while a never-injected control nonce "
        "stayed un-hit — a real SSRF, not a coincidental status.",
        "The request-guard refuses to forward this parameter when it carries a URL "
        f"whose host:port is not '{target_netloc}' (an egress allowlist of exactly "
        "the target itself), and forwards all other traffic — including the benign "
        "same-origin control — unchanged. The DURABLE fix is to allowlist egress "
        "destinations and block loopback / link-local / cloud-metadata ranges at "
        "the fetch layer.",
    )

    return SsrfRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        endpoint_url=expectation.endpoint_url,
        target_netloc=target_netloc,
        rationale=rationale,
    )


def _portable_json(rule: SsrfControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.ssrf_egress_allowlist_guard/v1",
        "decision": "deny_off_allowlist_fetch",
        "match": {
            "method": rule.method,
            "path": rule.path,
            "param": rule.param,
            "location": rule.location,
        },
        "signature_family": "url_allowlist",
        "allow_hosts": [rule.allow_netloc],
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Block this parameter at the gateway when it carries a URL whose "
            "host:port is not on the egress allowlist (a stop-gap virtual patch). "
            "The ROOT-CAUSE fix is to allowlist egress destinations at the fetch "
            "layer and block loopback / link-local / cloud-metadata ranges "
            "(127.0.0.0/8, 169.254.0.0/16, 10/8, 172.16/12, 192.168/16)."
        ),
    }
    return json.dumps(spec, indent=2)


def _absolute_url_signature() -> str:
    """A best-effort gateway regex matching an absolute or protocol-relative URL.

    The gateway configs are a coarse stop-gap: they refuse this parameter when it
    carries ANY absolute/protocol-relative URL, since the target legitimately
    needs no attacker-supplied absolute fetch target. The enforcer itself applies
    the EXACT :func:`_matches_url_allowlist` host:port check, not this regex.
    """
    return r"^\s*(?:[a-z][a-z0-9+.\-]*:)?//"


def _nginx(rule: SsrfControlRule, upstream_base: str) -> str:
    matched = f"$arg_{rule.param}" if rule.location == "query" else "$request_body"
    signature = _absolute_url_signature()
    return "\n".join(
        [
            f"# Sentinel remediation — SSRF egress-allowlist guard for '{rule.param}'",
            f"# on {rule.method} {rule.path} ({rule.location}). Same-origin traffic is forwarded.",
            f"location = {rule.path} {{",
            f'    if ({matched} ~* "{signature}") {{',
            "        return 403;",
            "    }",
            f"    proxy_pass {upstream_base};",
            "}",
            "# NOTE: gateway stop-gap only. The durable fix is to allowlist egress",
            "# destinations and block loopback/link-local/metadata ranges at the fetch layer.",
        ]
    )


def _modsecurity(rule: SsrfControlRule, upstream_base: str) -> str:
    if rule.location == "query":
        target = f"ARGS_GET:{rule.param}"
    elif rule.location == "body_form":
        target = f"ARGS_POST:{rule.param}"
    else:
        target = f"ARGS:{rule.param}"
    signature = _absolute_url_signature()
    return "\n".join(
        [
            "# Sentinel remediation — ModSecurity virtual patch (SSRF)",
            f"# upstream: {upstream_base}   match: {rule.method} {rule.path}",
            f'SecRule REQUEST_METHOD "@streq {rule.method}" \\',
            "    \"id:1000011,phase:2,chain,deny,status:403,log,\\",
            f"     msg:'Sentinel: SSRF egress-allowlist guard on {rule.param}'\"",
            f'    SecRule REQUEST_URI "@beginsWith {rule.path}" "chain"',
            f'        SecRule {target} "@rx {signature}" "t:none,t:urlDecodeUni,t:lowercase"',
            "# NOTE: virtual patch. The durable fix is a server-side egress allowlist.",
        ]
    )


def _caddy(rule: SsrfControlRule, upstream_base: str) -> str:
    lines = [
        f"# Sentinel remediation — SSRF egress-allowlist guard for '{rule.param}'",
        f"# on {rule.method} {rule.path}. Best-effort matcher; prefer ModSecurity / handler fix.",
        "@ssrf {",
        f"    method {rule.method}",
        f"    path {rule.path}",
    ]
    if rule.location == "query":
        lines.append(f"    query {rule.param}=http://* {rule.param}=https://* {rule.param}=//*")
    else:
        lines.append('    header Content-Type *')
    lines += [
        "}",
        "respond @ssrf 403",
        f"reverse_proxy {upstream_base}",
        "# NOTE: gateway stop-gap. Caddy cannot express the host:port allowlist exactly;",
        "# the durable fix is a server-side egress allowlist at the fetch layer.",
    ]
    return "\n".join(lines)


def render_ssrf_artifacts(
    rule: SsrfControlRule,
    upstream_base: str,
) -> SsrfRemediationArtifacts:
    """Render the corrective request-guard as deployable provider configs."""
    return SsrfRemediationArtifacts(
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


def _request_guard_rule(rule: SsrfControlRule) -> RequestGuardRule:
    return RequestGuardRule(
        method=rule.method,
        path=rule.path,
        param=rule.param,
        location=rule.location,
        signature_family="url_allowlist",
        allow=(rule.allow_netloc,),
    )


def _probe(
    scratch: SecurityGraph,
    executor,
    collaborator,
    hypothesis: Hypothesis,
    expectation: SsrfExpectation,
    *,
    tag: str,
    role: str,
    endpoint_url: str,
    value: str,
    payload_nonce: str,
    control_nonce: str,
) -> tuple[str, int | None]:
    """Build → execute → capture-callback → complete one re-probe on scratch."""
    identity = hypothesis.identity
    url, body, headers = _inject(
        endpoint_url, expectation.param, expectation.location, value
    )
    experiment = Experiment(
        id=f"exp:ssrf-remediation:{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="ssrf_check",
        description=f"ssrf {tag} re-probe under remediation verification.",
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
        capability_id="ssrf.remediation_verification",
        action=f"verify_ssrf_{role}",
    )
    scratch.add_experiment(experiment)

    result = executor.execute(experiment)
    evidence_ids = []
    for evidence in result.evidence:
        scratch.add_evidence(evidence)
        evidence_ids.append(evidence.id)

    # -- out-of-band callback snapshot (the SSRF signal) -------------------
    if role == "payload":
        payload_hit = bool(collaborator.wait_for_hit(payload_nonce))
    else:
        payload_hit = bool(collaborator.was_hit(payload_nonce))
    control_hit = bool(collaborator.was_hit(control_nonce))

    callback_id = f"evidence:ssrf-callback-{tag}:{hypothesis.id}"
    scratch.add_evidence(
        Evidence(
            id=callback_id,
            source="sentinel_collaborator",
            data={
                "mode": "ssrf_callback",
                "role": role,
                "collaborator_base": collaborator.base_url,
                "payload_nonce": payload_nonce,
                "control_nonce": control_nonce,
                "payload_nonce_hit": payload_hit,
                "control_nonce_hit": control_hit,
            },
            confidence=1.0,
        )
    )
    evidence_ids.append(callback_id)

    completed = Experiment(
        id=experiment.id,
        hypothesis_id=experiment.hypothesis_id,
        kind=experiment.kind,
        description=experiment.description,
        status=result.status,
        evidence_ids=tuple(evidence_ids),
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
    collaborator,
    hypothesis: Hypothesis,
    expectation: SsrfExpectation,
    *,
    phase: str,
    endpoint_url: str,
    control_value: str,
    rng: random.Random | None = None,
):
    """Run same-origin control + collaborator payload; hand ids to the PURE judge.

    FRESH distinct nonces are minted for THIS phase so a stateful collaborator
    cannot leak a before-phase hit into the after phase. The control anchor (the
    target's own origin) runs first to establish that the fresh payload nonce is
    un-hit before injection (temporal attribution).
    """
    payload_nonce, control_nonce = _distinct_nonces(rng)
    control_id, _control_code = _probe(
        scratch, executor, collaborator, hypothesis, expectation,
        tag=f"{phase}-control", role="control", endpoint_url=endpoint_url,
        value=control_value, payload_nonce=payload_nonce, control_nonce=control_nonce,
    )
    payload_id, payload_code = _probe(
        scratch, executor, collaborator, hypothesis, expectation,
        tag=f"{phase}-payload", role="payload", endpoint_url=endpoint_url,
        value=collaborator.callback_url(payload_nonce),
        payload_nonce=payload_nonce, control_nonce=control_nonce,
    )
    judgment = judge_ssrf(
        scratch,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        payload_experiment_id=payload_id,
    )
    return judgment, payload_code


def verify_ssrf_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: SsrfRemediationPlan,
    enforcer_base: str,
    collaborator,
    before_executor=None,
    after_executor=None,
    rng: random.Random | None = None,
) -> RemediationVerification:
    """
    PROVE the fix on a SCRATCH graph seeded with relationships ONLY.

    Runs the full two-probe out-of-band callback differential twice with the PURE
    judge: BEFORE against the live target (the collaborator is hit on a FRESH
    payload nonce → VALIDATED) and AFTER through the shield with the egress-
    allowlist request-guard active (the collaborator URL is off-allowlist → the
    guard denies it 403 → no callback lands → DISPROVED) while the benign same-
    origin control is still forwarded. `proven` is earned solely by that
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
        expectation = ssrf_expectation(
            scratch, resource_id=identity.resource_id, aspect=identity.action
        )
    if expectation is None or not expectation.param:
        return RemediationVerification(
            experiment_id="",
            after_status="INCONCLUSIVE",
            before_status="INCONCLUSIVE",
            proven=False,
            reason="ssrf surface metadata unavailable for verification",
        )

    target_endpoint = plan.endpoint_url
    after_endpoint = enforcer_base.rstrip("/") + urlsplit(target_endpoint).path

    target_host = urlsplit(target_endpoint).netloc.lower()
    enforcer_host = urlsplit(enforcer_base).netloc.lower()
    before_exec = before_executor or SsrfProbeExecutor(
        allowed_hosts={target_host} if target_host else None
    )
    after_exec = after_executor or SsrfProbeExecutor(
        allowed_hosts={enforcer_host} if enforcer_host else None
    )

    # The benign control is ALWAYS the TARGET's own origin (on the egress
    # allowlist), so the guard forwards it in BOTH phases and it never reaches
    # our collaborator — only the payload names the loopback listener.
    control_value = _same_origin_control(target_endpoint)

    before_judgment, before_code = _differential(
        scratch, before_exec, collaborator, hypothesis, expectation,
        phase="before", endpoint_url=target_endpoint,
        control_value=control_value, rng=rng,
    )
    after_judgment, after_code = _differential(
        scratch, after_exec, collaborator, hypothesis, expectation,
        phase="after", endpoint_url=after_endpoint,
        control_value=control_value, rng=rng,
    )

    proven = (
        before_judgment.status == "VALIDATED"
        and after_judgment.status == "DISPROVED"
    )
    if proven:
        reason = (
            "the judge FLIPPED VALIDATED -> DISPROVED: pre-fix the payload URL was "
            "fetched server-side (the collaborator recorded the fresh payload "
            "nonce), and under the egress-allowlist request-guard the collaborator "
            "URL is denied (403) so no callback lands while the benign same-origin "
            "control is still forwarded — the fetch is no longer attacker-controlled"
        )
    else:
        reason = (
            f"no VALIDATED -> DISPROVED flip (before={before_judgment.status}, "
            f"after={after_judgment.status}); the fix is not proven — the SSRF must "
            "reproduce pre-fix and stop reproducing under the request-guard"
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


def _verify_with_enforcer(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
    plan: SsrfRemediationPlan,
    collaborator,
    *,
    before_executor,
    after_executor,
    use_enforcer: bool,
    rng: random.Random | None,
) -> RemediationVerification:
    """Stand the shield up (or not) and run the differential once."""
    if use_enforcer:
        with RemediationEnforcer(
            (),
            plan.upstream_base,
            guard_rules=(_request_guard_rule(plan.rule),),
        ) as enforcer:
            return verify_ssrf_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=enforcer.base_url,
                collaborator=collaborator,
                before_executor=before_executor,
                after_executor=after_executor,
                rng=rng,
            )
    return verify_ssrf_remediation(
        graph,
        hypothesis=hypothesis,
        plan=plan,
        enforcer_base=plan.upstream_base,
        collaborator=collaborator,
        before_executor=before_executor,
        after_executor=after_executor,
        rng=rng,
    )


def remediate_ssrf_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    collaborator=None,
    use_enforcer: bool = True,
    rng: random.Random | None = None,
) -> SsrfRemediationOutcome:
    """
    PATCH + PROVE one confirmed SSRF finding.

    Synthesises the corrective egress-allowlist request-guard, renders deployable
    artifacts, and (when ``use_enforcer``) stands a real :class:`RemediationEnforcer`
    up in front of the target with the guard active, PROVING the fix only if the
    PURE :func:`judge_ssrf` flips VALIDATED -> DISPROVED. With ``use_enforcer=False``
    the same verification runs against injected executors (offline). When no
    ``collaborator`` is supplied a real loopback :class:`SentinelCollaborator` is
    stood up for the duration. The live/real graph is never mutated here.
    """
    plan = synthesize_ssrf_remediation(graph, finding)
    if plan is None:
        return SsrfRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed SSRFs with a recoverable live payload probe and a "
                "guardable declared surface are remediable here."
            ),
        )

    artifacts = render_ssrf_artifacts(plan.rule, plan.upstream_base)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return SsrfRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail="the confirmed hypothesis or its identity is missing",
        )

    try:
        if collaborator is not None:
            verification = _verify_with_enforcer(
                graph, hypothesis, plan, collaborator,
                before_executor=before_executor,
                after_executor=after_executor,
                use_enforcer=use_enforcer,
                rng=rng,
            )
        else:
            with SentinelCollaborator() as collab:
                verification = _verify_with_enforcer(
                    graph, hypothesis, plan, collab,
                    before_executor=before_executor,
                    after_executor=after_executor,
                    use_enforcer=use_enforcer,
                    rng=rng,
                )
    except Exception as exc:  # noqa: BLE001 — surface the failure honestly
        return SsrfRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=f"verification raised: {exc}",
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return SsrfRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_ssrf_findings(
    graph: SecurityGraph,
) -> list[SsrfRemediationOutcome]:
    """Remediate + prove every OPEN confirmed `ssrf` finding."""
    findings = sorted(
        graph.findings_for(kind="ssrf", status="OPEN"),
        key=lambda item: item.id,
    )
    return [remediate_ssrf_and_prove(graph, finding) for finding in findings]

