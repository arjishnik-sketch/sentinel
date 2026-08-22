"""
Render an :class:`AccessControlRule` into deployable, provider-agnostic
enforcement artifacts.

These are the operator's take-away configs — the same corrective control
Sentinel proves live via :class:`RemediationEnforcer`, expressed for the
gateways teams actually run. Everything is derived from the rule; there is
no target-specific text. The artifacts are informational: the authoritative
live PROVE is the enforcer re-probe, not these files.
"""

from __future__ import annotations

import json

from .model import AccessControlRule, RemediationArtifacts


def _is_anonymous(rule: AccessControlRule) -> bool:
    return rule.principal_kind == "anonymous" or not rule.principal_headers


def _portable_json(rule: AccessControlRule, upstream_base: str) -> str:
    spec = {
        "$schema": "sentinel.remediation.access_control_rule/v1",
        "decision": rule.decision,
        "principal": {
            "name": rule.principal_name,
            "kind": rule.principal_kind,
            "identifying_headers": [
                {"name": name, "value": value}
                for name, value in rule.principal_headers
            ],
        },
        "match": {"method": rule.method, "path": rule.path},
        "action": rule.action,
        "upstream": upstream_base,
        "note": (
            "Deny the matched principal on this method+path; forward all "
            "other traffic unchanged. Anonymous == request presenting none "
            "of {authorization, cookie, x-access-token, x-api-key}."
        ),
    }
    return json.dumps(spec, indent=2)


def _nginx(rule: AccessControlRule, upstream_base: str) -> str:
    lines = [
        f"# Sentinel remediation — deny {rule.principal_name} "
        f"({rule.principal_kind}) {rule.method} {rule.path}",
        f"location = {rule.path} {{",
    ]
    if _is_anonymous(rule):
        lines += [
            "    # Anonymous == no credential header present.",
            f"    if ($request_method = {rule.method}) {{ set $sentinel_m 1; }}",
            "    if ($http_authorization = \"\") { set $sentinel_a 1; }",
            "    if ($http_cookie = \"\") { set $sentinel_c 1; }",
            "    # Block only the credential-less caller on this route.",
            "    set $sentinel_deny \"${sentinel_m}${sentinel_a}${sentinel_c}\";",
            "    if ($sentinel_deny = \"111\") { return 403; }",
        ]
    else:
        header = rule.principal_headers[0][0]
        var = "$http_" + header.lower().replace("-", "_")
        lines += [
            f"    # Deny the principal identified by the '{header}' header.",
            f"    if ($request_method = {rule.method}) {{ set $sentinel_m 1; }}",
            f"    if ({var}) {{ set $sentinel_p 1; }}",
            "    set $sentinel_deny \"${sentinel_m}${sentinel_p}\";",
            "    if ($sentinel_deny = \"11\") { return 403; }",
        ]
    lines += [
        f"    proxy_pass {upstream_base};",
        "}",
    ]
    return "\n".join(lines)


def _envoy_rbac(rule: AccessControlRule, upstream_base: str) -> str:
    principal = (
        "any: true  # anonymous — pair with a header-absence matcher"
        if _is_anonymous(rule)
        else f"header: {{ name: \"{rule.principal_headers[0][0]}\", "
        "present_match: true }"
    )
    return "\n".join(
        [
            "# Sentinel remediation — Envoy RBAC (deny) filter",
            f"# upstream: {upstream_base}",
            "rules:",
            "  action: DENY",
            "  policies:",
            f"    \"sentinel-deny-{rule.action}\":",
            "      permissions:",
            f"        - and_rules: {{ rules: ["
            f"{{ header: {{ name: \":method\", exact_match: \"{rule.method}\" }} }}, "
            f"{{ url_path: {{ path: {{ exact: \"{rule.path}\" }} }} }} ] }}",
            "      principals:",
            f"        - {principal}",
        ]
    )


def _caddy(rule: AccessControlRule, upstream_base: str) -> str:
    lines = [
        f"# Sentinel remediation — deny {rule.principal_name} "
        f"{rule.method} {rule.path}",
    ]
    if _is_anonymous(rule):
        lines += [
            f"@sentinel_deny {{",
            f"    method {rule.method}",
            f"    path {rule.path}",
            "    not header Authorization *",
            "    not header Cookie *",
            "}",
        ]
    else:
        header = rule.principal_headers[0][0]
        lines += [
            f"@sentinel_deny {{",
            f"    method {rule.method}",
            f"    path {rule.path}",
            f"    header {header} *",
            "}",
        ]
    lines += [
        "respond @sentinel_deny 403",
        f"reverse_proxy {upstream_base}",
    ]
    return "\n".join(lines)


def render_artifacts(
    rule: AccessControlRule,
    upstream_base: str,
) -> RemediationArtifacts:
    """Render all four deployable enforcement configs from the rule."""
    return RemediationArtifacts(
        portable_json=_portable_json(rule, upstream_base),
        nginx=_nginx(rule, upstream_base),
        envoy_rbac=_envoy_rbac(rule, upstream_base),
        caddy=_caddy(rule, upstream_base),
    )
