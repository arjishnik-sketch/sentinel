"""
Remediation domain model — the PATCH + PROVE stage.

Everything here is derived deterministically from a *confirmed* finding.
Nothing in this module invents an authorization decision, re-scores a
finding, or manufactures a fix: it only describes what a confirmed
authorization contradiction implies must be enforced, and records what a
live re-probe actually observed.

Two complementary remediations are modelled:

  * an **enforcement shield** — a provider-agnostic access-control rule
    rendered into deployable gateway artifacts (nginx / Envoy / Caddy /
    portable JSON). This is what Sentinel can *prove* live: it stands the
    rule up in front of the target and re-probes through it.
  * an optional **source-code patch** — a unified diff that adds an
    authorization guard at the route handler, emitted only when the
    target's source repository is provided. This is the root-cause fix;
    its live proof requires the operator's own rebuild.

The AccessControlRule is the single shared truth both paths consume.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AccessControlRule:
    """
    A provider-agnostic access-control rule derived from a confirmed
    authorization contradiction.

    `decision` is what enforcement must apply ("deny"). It is NOT an
    observation — it is the corrective control the confirmed finding
    demands. `principal_headers` are the identifying request headers of a
    non-anonymous principal (empty for the anonymous caller); enforcement
    uses them to recognise the principal the rule targets.
    """

    principal_name: str
    principal_kind: str
    method: str
    path: str
    action: str
    decision: str = "deny"
    principal_headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class RemediationPlan:
    """
    The corrective control implied by one confirmed finding.

    `upstream_base` is the engagement target's scheme://netloc; the
    enforcer only ever forwards to it. `target_url` preserves the exact
    probed URL so verification re-tests the identical property.
    """

    finding_id: str
    hypothesis_id: str
    rule: AccessControlRule
    upstream_base: str
    target_url: str
    strategy: str = "authorization_enforcement"
    rationale: tuple[str, ...] = ()
    # Advisory-only note from the bounded AI. Never authoritative.
    ai_note: str = ""


@dataclass(frozen=True)
class RemediationArtifacts:
    """Deployable enforcement configs rendered from an AccessControlRule."""

    portable_json: str
    nginx: str
    envoy_rbac: str
    caddy: str


@dataclass(frozen=True)
class SourcePatch:
    """
    A generated source-code remediation for the root-cause handler.

    `status` is one of:
      GENERATED  -> a unified diff was produced against a located handler
      ADVISORY   -> handler not pinpointed; a guard stub + guidance emitted
      NOT_PROVIDED -> no source repository was supplied
    Its live proof requires the operator to rebuild the target; the
    enforcement shield carries the live PROVE.
    """

    status: str
    framework: str = "unknown"
    file_path: str = ""
    unified_diff: str = ""
    guidance: str = ""


@dataclass(frozen=True)
class RemediationVerification:
    """
    The deterministic judge's verdict on a fresh re-probe taken THROUGH
    the enforcement layer. `proven` is true only when the same judge that
    confirmed the finding now returns DISPROVED under enforcement — the
    contradiction no longer reproduces.
    """

    experiment_id: str
    after_status: str
    before_status: str
    proven: bool
    observed_status_code: int | None = None
    before_status_code: int | None = None
    reason: str = ""


@dataclass(frozen=True)
class RemediationOutcome:
    """
    Full result of the PATCH + PROVE stage for one confirmed finding.

    `result` is one of FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR.
    """

    finding_id: str
    hypothesis_id: str
    result: str
    plan: "RemediationPlan | None" = None
    artifacts: "RemediationArtifacts | None" = None
    verification: "RemediationVerification | None" = None
    source_patch: "SourcePatch | None" = None
    detail: str = ""
