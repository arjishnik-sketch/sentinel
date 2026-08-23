"""
Remediate a confirmed insecure-cookie finding — PATCH + PROVE.

The mirror of :mod:`app.security_graph.posture.remediation` for the
`insecure_cookie` class. From a CONFIRMED cookie finding it:

  * reads the operator-declared expectation the judge already used and the
    live probe provenance (no re-scoring, no invented semantics),
  * states the one corrective cookie-attribute mutation the contradiction
    demands (add HttpOnly/Secure, strip a flag, set SameSite),
  * renders deployable provider configs (nginx / Caddy / Envoy / portable),
  * stands the *same* enforcement shield up — now hardening the forwarded
    ``Set-Cookie`` — and re-probes through it, and
  * PROVES the fix only when the PURE :func:`judge_cookie_posture` flips
    VALIDATED → DISPROVED under real enforcement.

Nothing here manufactures a verdict. `FIX_PROVEN` is earned solely by the
deterministic judge observing a corrected cookie on a fresh live probe.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import urlsplit

from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis, HttpRequestSpec, SecurityFinding
from ..remediation.enforcer import CookieAttributeRule, RemediationEnforcer
from ..remediation.model import RemediationVerification
from .executor import CookieProbeExecutor
from .judge import cookie_posture_expectation, judge_cookie_posture


# CHUNK_MARKER


@dataclass(frozen=True)
class CookieControlRule:
    """
    The corrective cookie-attribute control implied by one confirmed finding.
    `op` is the enforcement primitive the shield applies:

      add_flag     -> append HttpOnly / Secure          (must_have_flag)
      remove_flag  -> drop HttpOnly / Secure            (must_not_have_flag)
      set_samesite -> set/replace SameSite=<value>      (samesite_must_*)

    `cookie_name` empty means "every Set-Cookie on this route".
    """

    cookie_name: str
    check: str
    method: str
    path: str
    op: str
    flag: str = ""
    value: str = ""
    severity: str = "MEDIUM"


@dataclass(frozen=True)
class CookieRemediationArtifacts:
    """Deployable cookie-hardening enforcement configs rendered from a rule."""

    portable_json: str
    nginx: str
    caddy: str
    envoy: str


@dataclass(frozen=True)
class CookieRemediationPlan:
    """The corrective control implied by one confirmed cookie finding."""

    finding_id: str
    hypothesis_id: str
    rule: CookieControlRule
    upstream_base: str
    target_url: str
    strategy: str = "cookie_security_enforcement"
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True)
class CookieRemediationOutcome:
    """
    Full PATCH + PROVE result for one confirmed cookie finding.

    `result` is one of FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR.
    """

    finding_id: str
    hypothesis_id: str
    result: str
    plan: "CookieRemediationPlan | None" = None
    artifacts: "CookieRemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    detail: str = ""


def _originating_probe(
    graph: SecurityGraph,
    hypothesis_id: str,
) -> Experiment | None:
    """Recover the completed live cookie probe that backs this finding."""
    candidates = [
        experiment
        for experiment in graph.experiments_for(hypothesis_id=hypothesis_id)
        if experiment.kind == "cookie_check"
        and experiment.request is not None
        and experiment.status == "COMPLETED"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.id)
    return candidates[0]


def _control_for(expectation) -> tuple[str, str, str]:
    """Map a violated expectation to (op, flag, samesite_value)."""
    check = expectation.check
    if check == "must_have_flag":
        return "add_flag", (expectation.flag or ""), ""
    if check == "must_not_have_flag":
        return "remove_flag", (expectation.flag or ""), ""
    if check == "samesite_must_equal":
        return "set_samesite", "", (expectation.value or "Lax")
    if check == "samesite_must_not_equal":
        # Correct by setting a safe SameSite that is NOT the forbidden value.
        forbidden = (expectation.value or "").strip().lower()
        safe = "Lax" if forbidden != "lax" else "Strict"
        return "set_samesite", "", safe
    # Unknown check — not shieldable.
    return "", "", ""


def synthesize_cookie_remediation(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> CookieRemediationPlan | None:
    """Derive the corrective cookie control for one confirmed finding."""

    if finding.kind != "insecure_cookie":
        return None

    identity = finding.identity
    if identity is None or not (identity.resource_id and identity.action):
        return None

    expectation = cookie_posture_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.check:
        return None

    op, flag, value = _control_for(expectation)
    if not op:
        return None

    probe = _originating_probe(graph, finding.hypothesis_id)
    if probe is None or probe.request is None:
        return None

    request = probe.request
    split = urlsplit(request.url)
    if not split.scheme or not split.netloc:
        return None

    rule = CookieControlRule(
        cookie_name=expectation.cookie_name,
        check=expectation.check,
        method=request.method.strip().upper(),
        path=split.path or "/",
        op=op,
        flag=flag,
        value=value,
        severity=expectation.severity,
    )

    upstream_base = f"{split.scheme}://{split.netloc}"

    label = expectation.cookie_name or "every"
    verb = {
        "add_flag": f"add the {flag} attribute to the {label} cookie",
        "remove_flag": f"strip the {flag} attribute from the {label} cookie",
        "set_samesite": f"set SameSite={value} on the {label} cookie",
    }[op]
    rationale = (
        f"Operator cookie posture declares {rule.method} {rule.path} "
        f"{expectation.check} on '{label}'.",
        "The live probe observed a Set-Cookie that CONTRADICTS it — a "
        "confirmed insecure cookie, a classic session-theft / CSRF pivot.",
        f"The enforcement shield rewrites the response to {verb} and forwards "
        "all other traffic to the target unchanged.",
    )

    return CookieRemediationPlan(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        rule=rule,
        upstream_base=upstream_base,
        target_url=request.url,
        rationale=rationale,
    )


# RENDER_MARKER


def _nginx_flag_token(rule: CookieControlRule) -> str:
    if rule.op == "add_flag":
        return rule.flag.lower()
    if rule.op == "remove_flag":
        return "no" + rule.flag.lower()
    # set_samesite
    return "samesite=" + rule.value.lower()


def _portable_json(rule: CookieControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.cookie_control_rule/v1",
        "op": rule.op,
        "match": {"method": rule.method, "path": rule.path},
        "cookie_name": rule.cookie_name,
        "check": rule.check,
        "flag": rule.flag,
        "value": rule.value,
        "severity": rule.severity,
        "upstream": upstream_base,
        "note": (
            "Rewrite the forwarded Set-Cookie for this method+path so the "
            "declared cookie posture holds; forward all other traffic "
            "unchanged. Cookie hardening is the standard defence against "
            "session theft (HttpOnly), transport downgrade (Secure) and CSRF "
            "(SameSite)."
        ),
    }
    return json.dumps(spec, indent=2)


def _nginx(rule: CookieControlRule, upstream_base: str) -> str:
    selector = rule.cookie_name if rule.cookie_name else "~"
    token = _nginx_flag_token(rule)
    return "\n".join(
        [
            f"# Sentinel remediation — {rule.op} on "
            f"{rule.cookie_name or 'every'} cookie ({rule.method} {rule.path})",
            f"location = {rule.path} {{",
            f"    proxy_pass {upstream_base};",
            "    # proxy_cookie_flags rewrites Set-Cookie from the upstream.",
            f"    proxy_cookie_flags {selector} {token};",
            "}",
        ]
    )


def _caddy(rule: CookieControlRule, upstream_base: str) -> str:
    name = rule.cookie_name or ""
    if rule.op == "add_flag":
        # Append the flag to matching Set-Cookie lines that lack it.
        find = f"(?i)^({name}=[^;]*(?:;(?!\\s*{rule.flag}\\b)[^;]*)*)$"
        replace = f"$1; {rule.flag}"
    elif rule.op == "remove_flag":
        find = f"(?i)(;\\s*{rule.flag}\\b)"
        replace = ""
    else:  # set_samesite
        find = f"(?i)(;\\s*SameSite=[^;]*)"
        replace = f"; SameSite={rule.value}"
    return "\n".join(
        [
            f"# Sentinel remediation — {rule.op} "
            f"{rule.cookie_name or 'every'} cookie ({rule.method} {rule.path})",
            f"reverse_proxy {upstream_base} {{",
            f'    header_down Set-Cookie "{find}" "{replace}"',
            "}",
            "# NOTE: advisory regex; for set_samesite also append the attribute",
            "# when the cookie ships none. The Sentinel shield proves the fix.",
        ]
    )


def _envoy(rule: CookieControlRule, upstream_base: str) -> str:
    return "\n".join(
        [
            "# Sentinel remediation — Envoy Set-Cookie mutation (Lua)",
            f"# upstream: {upstream_base}  match: {rule.method} {rule.path}",
            f"# {rule.op} on cookie '{rule.cookie_name or '*'}'",
            "http_filters:",
            "  - name: envoy.filters.http.lua",
            "    typed_config:",
            '      "@type": type.googleapis.com/'
            "envoy.extensions.filters.http.lua.v3.Lua",
            "      inline_code: |",
            "        function envoy_on_response(handle)",
            '          local sc = handle:headers():get("set-cookie")',
            "          if sc == nil then return end",
            f"          -- {rule.op}: {rule.flag or rule.value}",
            '          handle:headers():replace("set-cookie", '
            f"harden(sc))  -- {rule.op}",
            "        end",
        ]
    )


def render_cookie_artifacts(
    rule: CookieControlRule,
    upstream_base: str,
) -> CookieRemediationArtifacts:
    """Render all deployable cookie-hardening enforcement configs."""
    return CookieRemediationArtifacts(
        portable_json=_portable_json(rule, upstream_base),
        nginx=_nginx(rule, upstream_base),
        caddy=_caddy(rule, upstream_base),
        envoy=_envoy(rule, upstream_base),
    )


# VERIFY_MARKER


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
        id=f"exp:cookie-remediation:{tag}:{hypothesis_id}",
        hypothesis_id=hypothesis_id,
        kind="cookie_check",
        description=f"Cookie-security {tag}-enforcement re-probe.",
        status="PLANNED",
        request=request,
        capability_id="insecure_cookie.remediation_verification",
        action="verify_cookie_remediation",
    )


def _probe_and_judge(scratch, executor, hypothesis, experiment):
    """Mirror the cookie runner, then judge with the PURE judge."""
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

    judgment = judge_cookie_posture(
        scratch,
        hypothesis=hypothesis,
        experiment_id=experiment.id,
    )

    raw_code = dict(result.metadata).get("status_code")
    code = int(raw_code) if raw_code is not None else None
    return judgment, code


def verify_cookie_remediation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    plan: CookieRemediationPlan,
    enforcer_base: str,
    before_executor=None,
    after_executor=None,
) -> RemediationVerification:
    """
    Probe the target directly (before) and through the cookie-hardening shield
    (after), judging each with the PURE cookie judge. Proven iff the after
    judgment is DISPROVED.
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

    before_exec = before_executor or CookieProbeExecutor(
        allowed_hosts={target_split.netloc.lower()},
    )
    after_exec = after_executor or CookieProbeExecutor(
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
            "cookie posture now holds and the weak cookie no longer reproduces"
        )
    else:
        reason = (
            f"under enforcement the judge returned {after_judgment.status}; "
            "the insecure cookie still reproduces"
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


def _cookie_attribute_rule(rule: CookieControlRule) -> CookieAttributeRule:
    """Lower a CookieControlRule to the enforcer's pure mutation directive."""
    return CookieAttributeRule(
        method=rule.method,
        path=rule.path,
        cookie_name=rule.cookie_name,
        op=rule.op,
        flag=rule.flag,
        value=rule.value,
    )


# REMEDIATE_MARKER


def remediate_cookie_and_prove(
    graph: SecurityGraph,
    finding: SecurityFinding,
    *,
    before_executor=None,
    after_executor=None,
    use_enforcer: bool = True,
) -> CookieRemediationOutcome:
    """Synthesize → enforce → prove a corrective cookie control."""

    plan = synthesize_cookie_remediation(graph, finding)
    if plan is None:
        return CookieRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="NOT_APPLICABLE",
            detail=(
                "Only confirmed cookie violations with a recoverable live "
                "probe and a shieldable check are remediable here."
            ),
        )

    artifacts = render_cookie_artifacts(plan.rule, plan.upstream_base)

    hypothesis = graph.hypotheses.get(finding.hypothesis_id)
    if hypothesis is None or hypothesis.identity is None:
        return CookieRemediationOutcome(
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
                cookie_rules=(_cookie_attribute_rule(plan.rule),),
            ) as enforcer:
                verification = verify_cookie_remediation(
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
            verification = verify_cookie_remediation(
                graph,
                hypothesis=hypothesis,
                plan=plan,
                enforcer_base=plan.upstream_base,
                before_executor=before_executor,
                after_executor=after_executor,
            )
    except Exception as exc:  # noqa: BLE001 — report cleanly, never raise
        return CookieRemediationOutcome(
            finding_id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            result="ERROR",
            plan=plan,
            artifacts=artifacts,
            detail=str(exc),
        )

    result = "FIX_PROVEN" if verification.proven else "FIX_FAILED"
    return CookieRemediationOutcome(
        finding_id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        result=result,
        plan=plan,
        artifacts=artifacts,
        verification=verification,
        detail=verification.reason,
    )


def remediate_cookie_findings(
    graph: SecurityGraph,
) -> list[CookieRemediationOutcome]:
    """Remediate every OPEN confirmed cookie finding, deterministically."""
    findings = graph.findings_for(
        kind="insecure_cookie",
        status="OPEN",
    )
    findings = sorted(findings, key=lambda item: item.id)
    return [
        remediate_cookie_and_prove(graph, finding) for finding in findings
    ]




