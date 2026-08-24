"""
Remediate a confirmed broken-authentication finding — PATCH + PROVE (honestly).

The mirror of :mod:`app.security_graph.ssrf.remediation` for the ``broken_auth``
class, with one honesty split the class demands. The shield is the SAME
**request-guard (virtual patch)** with signature family ``jwt`` — it inspects the
``Authorization`` request header and refuses to forward a forged/unsigned token
(``alg=none`` / an unsigned two-part token) BEFORE it reaches the upstream, so a
fresh three-probe differential through the shield collapses and the pure judge
can observe the fix. From a CONFIRMED broken-auth finding it:

  * reads the operator-declared token-authentication boundary the judge already
    used and the live control/breach probe provenance (no re-scoring),
  * states the one corrective request-guard the contradiction demands — refuse a
    forged token on this route while forwarding a genuinely-signed one, and
  * PROVES the fix ONLY for a **guard-provable forgery** (``alg_none`` /
    ``unsigned``), where the PURE :func:`judge_broken_auth` flips VALIDATED ->
    DISPROVED under real enforcement: pre-fix the forged token is still accepted
    (before = VALIDATED) and under the jwt shape-guard it is refused (403) while
    the genuine control token is still forwarded (after = DISPROVED).

**Honesty split.** ``hs256_confusion`` and ``weak_secret`` produce a validly
*signed* forgery indistinguishable from a genuine token at the gateway — no
shape-guard can refuse it. For those the outcome is ``ADVISORY_ONLY``: Sentinel
never stands a shield it knows cannot earn the flip and never labels the honest
case a failure. The DURABLE fix (documented in the artifact) is handler-side:
pin the accepted algorithms and verify the signature against the real key.

Nothing here manufactures a verdict; ``FIX_PROVEN`` is earned solely by the
deterministic judge observing the VALIDATED -> DISPROVED flip on a fresh
three-probe re-test.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import urlsplit

from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import RemediationEnforcer, RequestGuardRule
from ..remediation.model import RemediationVerification
from .executor import BrokenAuthProbeExecutor
from .judge import BrokenAuthExpectation, broken_auth_expectation, judge_broken_auth

@dataclass(frozen=True)
class BrokenAuthControlRule:
    """
    The corrective request-guard implied by one confirmed broken-authentication.

    The shield inspects the ``Authorization`` header on `method` `path` and
    refuses to forward a token whose SHAPE is a forgery (``alg=none`` / an
    unsigned two-part token), while forwarding a genuinely-signed token — and all
    other traffic — to the target unchanged. Only ``guard_provable`` forgeries
    (``alg_none`` / ``unsigned``) can be blocked by shape.
    """

    method: str
    path: str
    param: str
    location: str
    forgery: str
    guard_provable: bool
    severity: str = "HIGH"


@dataclass(frozen=True)
class BrokenAuthRemediationArtifacts:
    """Deployable virtual-patch configs for the one corrective guard."""

    portable_json: str
    nginx: str
    modsecurity: str
    caddy: str


@dataclass(frozen=True)
class BrokenAuthRemediationPlan:
    """The single corrective request-guard the confirmed contradiction demands."""

    finding_id: str
    hypothesis_id: str
    rule: BrokenAuthControlRule
    upstream_base: str
    breach_url: str
    control_headers: tuple[tuple[str, str], ...]
    breach_headers: tuple[tuple[str, str], ...]
    strategy: str = "broken_auth_jwt_shape_guard"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class BrokenAuthRemediationOutcome:
    """PATCH proposal + PROVE result for one confirmed broken-auth finding."""

    finding_id: str
    hypothesis_id: str
    result: str            # FIX_PROVEN / FIX_FAILED / ADVISORY_ONLY / NOT_APPLICABLE / ERROR
    plan: "BrokenAuthRemediationPlan | None" = None
    artifacts: "BrokenAuthRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""


def _completed_probe(graph: SecurityGraph, hypothesis_id: str, action: str):
    """The live COMPLETED broken-auth probe for one action, or None."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "broken_auth_check"
        and experiment.action == action
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]


def synthesize_broken_auth_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> BrokenAuthRemediationPlan | None:
    """
    Derive the one corrective request-guard a confirmed broken-auth demands.

    Returns None for non-broken-auth findings, for findings whose boundary
    metadata cannot be recovered, or for findings with no live control/breach
    probe to anchor the upstream and the two authenticated header sets — the
    module never invents a target or a token.
    """
    if finding.kind != "broken_auth":
        return None
    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None
    expectation = broken_auth_expectation(
        graph, resource_id=identity.resource_id, aspect=identity.action
    )
    if expectation is None or not expectation.forgery:
        return None

    breach_probe = _completed_probe(
        graph, finding.hypothesis_id, "probe_broken_auth_breach"
    )
    control_probe = _completed_probe(
        graph, finding.hypothesis_id, "probe_broken_auth_control"
    )
    if breach_probe is None or breach_probe.request is None:
        return None
    if control_probe is None or control_probe.request is None:
        return None

    split = urlsplit(breach_probe.request.url)
    if not split.scheme or not split.netloc:
        return None

    rule = BrokenAuthControlRule(
        method=expectation.method.strip().upper() or "GET",
        path=split.path or "/",
        param="Authorization",
        location="header",
        forgery=expectation.forgery,
        guard_provable=expectation.guard_provable,
        severity=expectation.severity,
    )
    upstream_base = f"{split.scheme}://{split.netloc}"

    if expectation.guard_provable:
        fix_line = (
            "The request-guard refuses to forward this route's Authorization "
            f"header when it carries a forged token ({expectation.forgery}: "
            "alg=none / an unsigned two-part token) and forwards a genuinely-"
            "signed token unchanged — a shape the gateway can block. The DURABLE "
            "fix is still handler-side: pin the accepted algorithms and verify the "
            "signature against the real key."
        )
    else:
        fix_line = (
            f"This forgery ({expectation.forgery}) is validly SIGNED and is "
            "indistinguishable from a genuine token at the gateway — no shape-"
            "guard can refuse it, so remediation here is ADVISORY. The DURABLE "
            "fix is handler-side: pin the accepted algorithms (reject alg "
            "confusion) and verify the signature against the real key / a strong "
            "secret."
        )

    rationale = (
        f"Operator matrix declares {rule.method} {rule.path} MUST reject a forged "
        f"token ({expectation.forgery}) — the token must be authentically verified.",
        "The three-probe differential CONFIRMED that a token Sentinel MINTED was "
        "accepted where the genuine token works and an unauthenticated caller was "
        "denied — the server does not authentically verify the token signature.",
        fix_line,
    )

    return BrokenAuthRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        breach_url=breach_probe.request.url,
        control_headers=tuple(control_probe.request.headers),
        breach_headers=tuple(breach_probe.request.headers),
        rationale=rationale,
    )


# RENDER_MARKER


_DURABLE_NOTE = (
    "The ROOT-CAUSE fix is handler-side: pin the accepted JWT algorithms (never "
    "trust the token's own 'alg' header — reject 'none' and RS256->HS256 "
    "confusion) and cryptographically verify the signature against the real "
    "public key / a strong secret before honouring any claim."
)


def _portable_json(rule: BrokenAuthControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.broken_auth_jwt_shape_guard/v1",
        "decision": "deny_forged_token",
        "match": {
            "method": rule.method,
            "path": rule.path,
            "param": rule.param,
            "location": rule.location,
        },
        "signature_family": "jwt",
        "forgery": rule.forgery,
        "guard_provable": rule.guard_provable,
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Block this route's Authorization header at the gateway when it "
            "carries a forged token shape (alg=none / an unsigned two-part token) "
            "— a stop-gap virtual patch that ONLY catches unsigned forgeries. "
            + _DURABLE_NOTE
        ),
    }
    return json.dumps(spec, indent=2)


def _nginx(rule: BrokenAuthControlRule, upstream_base: str) -> str:
    return "\n".join(
        [
            f"# Sentinel remediation — broken-auth jwt shape-guard for '{rule.param}'",
            f"# on {rule.method} {rule.path}. Genuinely-signed tokens are forwarded.",
            "# Refuse alg=none / unsigned two-part tokens. Requires the njs/lua",
            "# module to parse the JWT header; a bare regex cannot decode base64url.",
            f"location = {rule.path} {{",
            "    # auth_jwt off for 'none'; verify signature otherwise (nginx-plus / lua).",
            '    if ($http_authorization ~* "^Bearer\\s+[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.?$") {',
            "        return 403;  # two-part (unsigned) or empty-signature token",
            "    }",
            f"    proxy_pass {upstream_base};",
            "}",
            f"# NOTE: gateway stop-gap only. {_DURABLE_NOTE}",
        ]
    )


def _modsecurity(rule: BrokenAuthControlRule, upstream_base: str) -> str:
    return "\n".join(
        [
            "# Sentinel remediation — ModSecurity virtual patch (broken auth / JWT)",
            f"# upstream: {upstream_base}   match: {rule.method} {rule.path}",
            f'SecRule REQUEST_METHOD "@streq {rule.method}" \\',
            "    \"id:1000012,phase:1,chain,deny,status:403,log,\\",
            f"     msg:'Sentinel: forged JWT ({rule.forgery}) on {rule.path}'\"",
            f'    SecRule REQUEST_URI "@beginsWith {rule.path}" "chain"',
            "        SecRule REQUEST_HEADERS:Authorization \\",
            '            "@rx ^Bearer\\s+[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.?$" "t:none"',
            f"# NOTE: catches unsigned/alg=none shapes only. {_DURABLE_NOTE}",
        ]
    )


def _caddy(rule: BrokenAuthControlRule, upstream_base: str) -> str:
    return "\n".join(
        [
            f"# Sentinel remediation — broken-auth jwt shape-guard on {rule.method} {rule.path}",
            "# Best-effort matcher; prefer a real JWT-verifying handler.",
            "@forged {",
            f"    method {rule.method}",
            f"    path {rule.path}",
            "    header_regexp Authorization \"^Bearer\\s+[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.?$\"",
            "}",
            "respond @forged 403",
            f"reverse_proxy {upstream_base}",
            f"# NOTE: gateway stop-gap. {_DURABLE_NOTE}",
        ]
    )


def render_broken_auth_artifacts(
    rule: BrokenAuthControlRule,
    upstream_base: str,
) -> BrokenAuthRemediationArtifacts:
    """Render the corrective request-guard as deployable provider configs."""
    return BrokenAuthRemediationArtifacts(
        portable_json=_portable_json(rule, upstream_base),
        nginx=_nginx(rule, upstream_base),
        modsecurity=_modsecurity(rule, upstream_base),
        caddy=_caddy(rule, upstream_base),
    )


# VERIFY_MARKER


def _path_with_query(url: str) -> str:
    split = urlsplit(url)
    path = split.path or "/"
    if split.query:
        path += "?" + split.query
    return path


def _request_guard_rule(rule: BrokenAuthControlRule) -> RequestGuardRule:
    return RequestGuardRule(
        method=rule.method,
        path=rule.path,
        param=rule.param,
        location=rule.location,
        signature_family="jwt",
    )


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
        id=f"exp:broken-auth-remediation:{tag}:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="broken_auth_check",
        description=f"broken-auth {tag} re-probe under remediation verification.",
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
        capability_id="broken_auth.remediation_verification",
        action=f"verify_broken_auth_{tag}",
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


def _differential(
    scratch: SecurityGraph,
    executor,
    hypothesis: Hypothesis,
    *,
    phase: str,
    method: str,
    url: str,
    control_headers,
    breach_headers,
):
    """Run control (genuine) + breach (forged) + anonymous baseline; PURE judge.

    Mirrors the live three-probe differential exactly, so the same judge that
    CONFIRMED the finding re-decides here. The genuine control token is a valid
    3-part JWS — the jwt shape-guard forwards it — so the control leg proves the
    fix does not break legitimate access.
    """
    control_id, control_code = _probe(
        scratch, executor, hypothesis,
        tag=f"{phase}-control", method=method, url=url, headers=control_headers,
    )
    breach_id, breach_code = _probe(
        scratch, executor, hypothesis,
        tag=f"{phase}-breach", method=method, url=url, headers=breach_headers,
    )
    baseline_id, _baseline_code = _probe(
        scratch, executor, hypothesis,
        tag=f"{phase}-baseline", method=method, url=url, headers=(),
    )
    judgment = judge_broken_auth(
        scratch,
        hypothesis=hypothesis,
        control_experiment_id=control_id,
        breach_experiment_id=breach_id,
        baseline_experiment_id=baseline_id,
    )
    return judgment, control_code, breach_code


def verify_broken_auth_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: BrokenAuthRemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    PROVE the fix on a SCRATCH graph seeded with relationships ONLY.

    Re-runs the three-probe differential (genuine control + forged breach +
    anonymous baseline) directly against the target (before) and through the jwt
    shape-guard shield (after). Proven iff the PURE judge FLIPS VALIDATED ->
    DISPROVED: the forgery must reproduce live pre-fix (before = VALIDATED) and
    stop reproducing under the guard (after = DISPROVED) while the genuine
    control token is still forwarded. This never touches the real graph and
    manufactures nothing.
    """
    scratch = SecurityGraph()
    for relationship in graph.relationships:
        scratch.add_relationship(relationship)

    identity = hypothesis.identity
    expectation = None
    if identity is not None and identity.resource_id and identity.action:
        expectation = broken_auth_expectation(
            scratch, resource_id=identity.resource_id, aspect=identity.action
        )
    if expectation is None or not expectation.forgery:
        return RemediationVerification(
            experiment_id="",
            after_status="INCONCLUSIVE",
            before_status="INCONCLUSIVE",
            proven=False,
            reason="broken-auth boundary metadata unavailable for verification",
        )

    after_url = enforcer_base.rstrip("/") + _path_with_query(plan.breach_url)

    target_host = urlsplit(plan.breach_url).netloc.lower()
    enforcer_host = urlsplit(enforcer_base).netloc.lower()
    before_exec = before_executor or BrokenAuthProbeExecutor(
        allowed_hosts={target_host} if target_host else None
    )
    after_exec = after_executor or BrokenAuthProbeExecutor(
        allowed_hosts={enforcer_host} if enforcer_host else None
    )

    before_judgment, before_control, before_breach = _differential(
        scratch, before_exec, hypothesis,
        phase="before", method=expectation.method, url=plan.breach_url,
        control_headers=plan.control_headers, breach_headers=plan.breach_headers,
    )
    after_judgment, _after_control, after_breach = _differential(
        scratch, after_exec, hypothesis,
        phase="after", method=expectation.method, url=after_url,
        control_headers=plan.control_headers, breach_headers=plan.breach_headers,
    )

    proven = (
        before_judgment.status == "VALIDATED"
        and after_judgment.status == "DISPROVED"
    )
    if proven:
        reason = (
            "the judge FLIPPED VALIDATED -> DISPROVED: pre-fix the forged token "
            f"({expectation.forgery}) was still accepted, and under the jwt "
            "shape-guard it is refused (403) while the genuine control token is "
            "still forwarded — the server no longer accepts a token Sentinel minted"
        )
    else:
        reason = (
            f"no VALIDATED -> DISPROVED flip (before={before_judgment.status}, "
            f"after={after_judgment.status}); the fix is not proven — the forgery "
            "must reproduce pre-fix and stop reproducing under the request-guard"
        )

    return RemediationVerification(
        experiment_id=after_judgment.experiment_id,
        after_status=after_judgment.status,
        before_status=before_judgment.status,
        proven=proven,
        observed_status_code=after_breach,
        before_status_code=before_breach,
        reason=reason,
    )


# REMEDIATE_MARKER


def remediate_broken_auth_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> BrokenAuthRemediationOutcome:
    """
    PATCH + PROVE one confirmed broken-auth finding — honestly.

    Synthesises the corrective jwt shape-guard and renders deployable artifacts.
    For a **guard-provable forgery** (``alg_none`` / ``unsigned``) it stands a
    real :class:`RemediationEnforcer` up with the guard active and PROVES the fix
    only if the PURE :func:`judge_broken_auth` flips VALIDATED -> DISPROVED. For a
    validly-signed forgery (``hs256_confusion`` / ``weak_secret``) it returns
    ``ADVISORY_ONLY`` — no shape-guard can block it, so Sentinel never stands a
    shield it knows cannot earn the flip. The live/real graph is never mutated.
    """
    plan = synthesize_broken_auth_remediation(graph, finding)
    if plan is None:
        return BrokenAuthRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed broken-auth findings with recoverable live "
                "control/breach probes and a declared boundary are remediable here."
            ),
        )

    artifacts = render_broken_auth_artifacts(plan.rule, plan.upstream_base)

    # HONESTY SPLIT: a validly-signed forgery is invisible to a shape-guard, so
    # remediation is advisory (durable fix = handler-side). Never label it a
    # failure and never stand a shield that cannot earn the flip.
    if not plan.rule.guard_provable:
        return BrokenAuthRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ADVISORY_ONLY",
            plan=plan,
            artifacts=artifacts,
            detail=(
                f"The {plan.rule.forgery} forgery is validly signed and cannot be "
                "distinguished from a genuine token at the gateway. The durable "
                "fix is handler-side: pin the accepted algorithms and verify the "
                "signature against the real key."
            ),
        )

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return BrokenAuthRemediationOutcome(
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
                verification = verify_broken_auth_remediation(
                    graph,
                    hypothesis=hypothesis,
                    plan=plan,
                    enforcer_base=enforcer.base_url,
                    before_executor=before_executor,
                    after_executor=after_executor,
                )
        else:
            verification = verify_broken_auth_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — surface the failure honestly
        return BrokenAuthRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=f"verification raised: {exc}",
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return BrokenAuthRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_broken_auth_findings(
    graph: SecurityGraph,
) -> list[BrokenAuthRemediationOutcome]:
    """Remediate + prove every OPEN confirmed `broken_auth` finding."""
    findings = sorted(
        graph.findings_for(kind="broken_auth", status="OPEN"),
        key=lambda item: item.id,
    )
    return [remediate_broken_auth_and_prove(graph, finding) for finding in findings]






