"""
OpenAPI 3 / Swagger 2  →  CANDIDATE Sentinel policy.

Reads the *declared* authorization intent from an API description and emits a
candidate combined policy an operator reviews and confirms. It reads only what
the spec explicitly declares (an operation's ``security`` requirement) and never
infers intent:

  * an operation requiring a non-empty security scheme → the spec DECLARES it
    needs auth → candidate rule: the anonymous principal MUST be DENIED it;
  * an operation with an explicit ``security: []``      → the spec DECLARES it
    public → candidate rule: anonymous MAY access it (allow);
  * an operation with no security and no global default → the spec is SILENT →
    no authorization rule is emitted (intent is never guessed).

Every emitted document is marked CANDIDATE and must be confirmed by an operator
before use: the importer translates declared spec intent into Sentinel's oracle
format, it does not itself decide any security question. The secure header and
cookie baseline (:mod:`app.security_graph.baseline`) is attached so the
candidate drives all three vulnerability classes out of the box.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import baseline as _baseline
from .cookies.cookie_policy import parse_cookie_policy
from .policy.access_policy import parse_access_policy
from .posture.header_policy import parse_header_policy


_HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)
# Methods that only read state get the coarse "read" action label; the rest are
# state-changing "write". The label is only a matcher tag on the candidate rule.
_READ_METHODS = frozenset({"get", "head", "options"})

_ANON = "anonymous"


@dataclass(frozen=True)
class SpecImportSummary:
    """A human-facing tally of what the importer derived (never a verdict)."""

    spec_kind: str            # "OpenAPI 3.x" / "Swagger 2.0"
    base_path: str
    total_operations: int
    deny_candidates: int      # spec declares auth required → anon denied
    allow_candidates: int     # spec declares public → anon allowed
    silent_operations: int    # spec silent → no rule emitted
    header_expectations: int
    cookie_expectations: int


def _detect_kind(spec: dict) -> str:
    openapi = spec.get("openapi")
    if isinstance(openapi, str) and openapi.strip().startswith("3"):
        return "OpenAPI 3.x"
    swagger = spec.get("swagger")
    if isinstance(swagger, str) and swagger.strip().startswith("2"):
        return "Swagger 2.0"
    raise ValueError(
        "spec import: unrecognised document — expected an 'openapi: 3.x' or "
        "'swagger: 2.0' top-level version field."
    )


def _base_path(spec: dict, kind: str) -> str:
    """Recover the server/base path so candidate paths match the live target."""
    if kind == "Swagger 2.0":
        base = spec.get("basePath") or ""
        return base.rstrip("/") if isinstance(base, str) else ""
    # OpenAPI 3: the path component of the first declared server URL, if any.
    servers = spec.get("servers")
    if isinstance(servers, (list, tuple)) and servers:
        first = servers[0]
        url = first.get("url") if isinstance(first, dict) else None
        if isinstance(url, str) and url.strip():
            path = urlsplit(url).path if "://" in url else url
            return path.rstrip("/")
    return ""


def _join(base: str, path: str) -> str:
    if not base:
        return path if path.startswith("/") else "/" + path
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _requires_auth(security: Any) -> bool | None:
    """
    Interpret an effective ``security`` value into declared intent.

    Returns True (auth required), False (explicitly public), or None (silent —
    no declaration to translate). Only an explicit declaration is ever acted on.
    """
    if security is None:
        return None
    if not isinstance(security, (list, tuple)):
        return None
    if len(security) == 0:
        return False  # explicit empty list == "no security" == public
    # A non-empty requirement with at least one non-empty scheme object means
    # auth is required. An entry that is an empty object ({}) is the OpenAPI
    # idiom for "optional" and is treated as a public alternative.
    for requirement in security:
        if isinstance(requirement, dict) and len(requirement) == 0:
            return False
    return True


def build_candidate_policy(
    spec: dict, *, source_label: str = "spec"
) -> tuple[dict, SpecImportSummary]:
    """Translate a decoded spec into a candidate combined-policy document."""

    if not isinstance(spec, dict):
        raise ValueError("spec import: top level must be a JSON/YAML object.")

    kind = _detect_kind(spec)
    base = _base_path(spec, kind)
    global_security = spec.get("security")

    paths = spec.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("spec import: document has no 'paths' object.")

    rules: list[dict] = []
    total = deny = allow = silent = 0

    for raw_path, item in sorted(paths.items()):
        if not isinstance(item, dict):
            continue
        for method, operation in sorted(item.items()):
            if method.lower() not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            total += 1

            op_security = operation.get("security")
            # An operation-level declaration overrides the global default; only
            # when the operation is silent do we fall back to the global one.
            effective = op_security if op_security is not None else global_security
            required = _requires_auth(effective)

            if required is None:
                silent += 1
                continue

            method_up = method.upper()
            action = "read" if method.lower() in _READ_METHODS else "write"
            summary = operation.get("summary") or operation.get("operationId")
            resource = (
                str(summary).strip()
                if isinstance(summary, str) and summary.strip()
                else f"{method_up} {raw_path}"
            )
            full_path = _join(base, str(raw_path))

            if required:
                deny += 1
                note = (
                    "CANDIDATE — the spec declares this operation requires "
                    "authentication (non-empty `security`); confirm the "
                    "anonymous principal MUST be denied before use."
                )
                decision = "deny"
            else:
                allow += 1
                note = (
                    "CANDIDATE — the spec declares this operation public "
                    "(`security: []`); confirm anonymous access is intended "
                    "before use."
                )
                decision = "allow"

            rules.append(
                {
                    "principal": _ANON,
                    "method": method_up,
                    "path": full_path,
                    "resource": resource,
                    "action": action,
                    "decision": decision,
                    "note": note,
                }
            )

    header_rules = _baseline.header_rules_payload(
        _baseline.default_header_policy()
    )
    cookie_rules = _baseline.cookie_rules_payload(
        _baseline.default_cookie_policy()
    )

    description = (
        f"CANDIDATE policy derived from {source_label} ({kind}). "
        "Machine-translated from the spec's DECLARED `security` intent — NOT a "
        "Sentinel finding and NOT confirmed ground truth. Review every rule, "
        "then use it as an oracle: Sentinel re-probes the live target and only "
        "reports a finding when observed behaviour contradicts a rule you keep. "
        "The header_rules/cookie_rules are Sentinel's built-in secure baseline."
    )

    document: dict = {
        "version": 1,
        "candidate": True,
        "description": description,
        "principals": [
            {"name": _ANON, "kind": "anonymous", "roles": []}
        ],
    }
    # `rules` must stay a non-empty array to load as an access policy; omit it
    # entirely when the spec declared no authorization intent (header/cookie
    # baseline still applies), and say so honestly in the summary.
    if rules:
        document["rules"] = rules
    document["header_rules"] = header_rules
    document["cookie_rules"] = cookie_rules

    summary = SpecImportSummary(
        spec_kind=kind,
        base_path=base,
        total_operations=total,
        deny_candidates=deny,
        allow_candidates=allow,
        silent_operations=silent,
        header_expectations=sum(len(r["expectations"]) for r in header_rules),
        cookie_expectations=sum(len(r["expectations"]) for r in cookie_rules),
    )
    return document, summary


def _decode(text: str) -> dict:
    """Decode a spec document as JSON, falling back to YAML if available."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # lazy: PyYAML is optional for JSON specs
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ValueError(
            "spec import: the document is not valid JSON and PyYAML is not "
            "installed to parse YAML. Install pyyaml or supply a JSON spec."
        ) from exc
    loaded = yaml.safe_load(text)
    if not isinstance(loaded, dict):
        raise ValueError("spec import: decoded document is not a mapping.")
    return loaded


def import_spec_file(
    path: str | Path,
) -> tuple[dict, SpecImportSummary]:
    """Load an OpenAPI/Swagger file and build its candidate policy document."""
    spec_path = Path(path)
    text = spec_path.read_text(encoding="utf-8")
    spec = _decode(text)
    document, summary = build_candidate_policy(spec, source_label=spec_path.name)
    # Fail loud if the emitted candidate does not itself parse cleanly through
    # the real oracle loaders — the importer must never emit an invalid oracle.
    if "rules" in document:
        parse_access_policy(document)
    parse_header_policy(document)
    parse_cookie_policy(document)
    return document, summary
