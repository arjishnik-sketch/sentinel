"""Tool selection — the "tools propose" half of the contract.

Sentinel already drives real OSS tools through ``app/tools/{resolver,runner,
parsers}``. This module is the DECISION layer above them: given an observed
:class:`~app.autonomous.surface.Surface` (and, optionally, the hypotheses in
play), it returns a ranked PLAN of which curated, real tools to bring to bear and
for what purpose. It is pure DATA — it never opens a socket, never installs, never
runs anything. Execution stays behind ``runner.run_tool(..., approve=...)`` with
its ``_deny`` default (no silent install).

CONTRACT — tools PROPOSE, a pure judge DISPOSES. Every tool here is a proposer:
recon/discovery tools widen the Surface (more hosts, endpoints, params); a
"proof-assist" tool (sqlmap, dalfox, nuclei) only NOMINATES candidate params/URLs
— its own "finding" is never trusted. A nomination is a LEAD at most, until the
security_graph differential judge reproduces it. Inventing capability from a tool
we cannot drive (or trusting a tool's unproven verdict) is the analogue of
manufacturing a verdict — forbidden. So the registry is curated + real, and every
spec is ``proposes_only``.
"""
from __future__ import annotations

from dataclasses import dataclass

from .resolver import plan_install


# Tool roles, in pipeline-phase order (used for deterministic grouping + sort).
ROLE_RECON = "recon"                # widen host/URL surface
ROLE_DISCOVERY = "discovery"        # widen params/content
ROLE_FINGERPRINT = "fingerprint"    # WAF/tech signal → informs retry strategy
ROLE_PROOF_ASSIST = "proof_assist"  # nominate candidates for a specific technique
ROLE_SECRETS = "secrets"            # regex/entropy leads (disclosure family)
ROLE_MANUAL = "manual"              # documented operator guidance; never auto-run

_ROLE_ORDER = {
    ROLE_RECON: 0, ROLE_DISCOVERY: 1, ROLE_FINGERPRINT: 2,
    ROLE_PROOF_ASSIST: 3, ROLE_SECRETS: 4, ROLE_MANUAL: 5,
}


@dataclass(frozen=True)
class ToolSpec:
    """One curated, real tool and what it proposes. ``techniques`` empty = a broad
    tool that applies to any live surface; a non-empty set gates the tool to
    hypotheses of those techniques (no SQLi hypothesis → sqlmap is not proposed)."""

    name: str
    role: str
    techniques: frozenset = frozenset()
    surface_flags: tuple = ()          # Surface bool attrs that boost relevance
    proposes_only: bool = True         # HARD invariant: never a verdict source
    note: str = ""

    @property
    def installable(self) -> bool:
        return plan_install(self.name) is not None


# Curated, REAL, drivable registry. Names align with ``resolver.INSTALL_RECIPES``
# where a recipe exists; broad tools carry no technique tag; proof-assist tools are
# gated to their technique; manual-only tools are documented, never auto-run. This
# is the honest reading of "add the tool list" — NOT the fictional PDF encyclopedia.
_REGISTRY_SEED = (
    ToolSpec("subfinder", ROLE_RECON, note="subdomain enumeration"),
    ToolSpec("dnsx", ROLE_RECON, note="DNS resolution / probing"),
    ToolSpec("httpx", ROLE_RECON, note="HTTP prober (alive / tech / title)"),
    ToolSpec("katana", ROLE_RECON, note="JS-aware crawler → endpoints"),
    ToolSpec("gau", ROLE_RECON, note="historical URLs (wayback / otx / cc)"),
    ToolSpec("waybackurls", ROLE_RECON, note="wayback URL harvest"),
    ToolSpec("amass", ROLE_RECON, note="heavyweight asset discovery (optional)"),
    ToolSpec("arjun", ROLE_DISCOVERY, note="hidden HTTP parameter discovery"),
    ToolSpec("ffuf", ROLE_DISCOVERY, note="content / param fuzzing → endpoints"),
    ToolSpec("wafw00f", ROLE_FINGERPRINT, note="WAF fingerprint → retry/evasion hint"),
    ToolSpec("nuclei", ROLE_FINGERPRINT, note="template hits → LEADS, re-proved by judge"),
    ToolSpec("sqlmap", ROLE_PROOF_ASSIST, techniques=frozenset({"sql_injection"}),
             note="nominate SQLi params; judge re-proves"),
    ToolSpec("dalfox", ROLE_PROOF_ASSIST, techniques=frozenset({"xss"}),
             note="nominate XSS params; judge re-proves"),
    ToolSpec("trufflehog", ROLE_SECRETS, note="secret regex / entropy leads"),
    ToolSpec("gitleaks", ROLE_SECRETS, note="secret regex leads"),
    ToolSpec("burpsuite", ROLE_MANUAL, note="Turbo Intruder / manual assist (operator-driven)"),
)

TOOL_REGISTRY = {t.name: t for t in _REGISTRY_SEED}


@dataclass(frozen=True)
class ToolRecommendation:
    spec: ToolSpec
    score: int
    reasons: tuple = ()

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def install(self):
        """The :class:`InstallRecipe` if we know how to obtain the tool, else None.
        Pure lookup; the caller still approval-gates via ``runner.ensure_available``."""
        return plan_install(self.spec.name)


# ---- scoring (pure, deterministic) ------------------------------------------

def _score(spec, techniques_present, surface):
    """Relevance of one spec to (hypotheses, surface), or None to drop it. Broad
    tools (no technique tag) always apply to a live surface; a technique-tagged
    tool is dropped unless a matching hypothesis is in play — we never propose a
    SQLi tool at a target with no SQLi hypothesis."""
    reasons, score = [], 0
    if spec.techniques:
        overlap = sorted(spec.techniques & techniques_present)
        if not overlap:
            return None
        score += 3
        reasons.append("assists " + ", ".join(overlap))
    else:
        score += 1
        reasons.append(f"{spec.role} applies to any surface")
    for attr in spec.surface_flags:
        if bool(getattr(surface, attr, False)):
            score += 1
            reasons.append(f"surface.{attr}")
    return ToolRecommendation(spec, score, tuple(reasons))


# ---- the plan ---------------------------------------------------------------

@dataclass(frozen=True)
class ToolPlan:
    """A ranked, grouped PLAN of proposer tools. DATA only — running any of these
    is the caller's job, always approval-gated."""

    recommendations: tuple = ()

    def _by_role(self, role):
        return tuple(r for r in self.recommendations if r.spec.role == role)

    def recon(self):        return self._by_role(ROLE_RECON)
    def discovery(self):    return self._by_role(ROLE_DISCOVERY)
    def fingerprint(self):  return self._by_role(ROLE_FINGERPRINT)
    def assist(self):       return self._by_role(ROLE_PROOF_ASSIST)
    def secrets(self):      return self._by_role(ROLE_SECRETS)
    def manual(self):       return self._by_role(ROLE_MANUAL)

    def for_technique(self, technique):
        return tuple(r for r in self.recommendations if technique in r.spec.techniques)

    def installable(self):
        """Recommendations we know how to obtain (have an InstallRecipe), excluding
        manual-only tools. The caller approval-gates each before running."""
        return tuple(
            r for r in self.recommendations
            if r.spec.role != ROLE_MANUAL and r.install is not None
        )

    @property
    def names(self):
        return tuple(r.name for r in self.recommendations)


def select_tools(surface, hypotheses=()):
    """Rank the curated registry against an observed surface and (optionally) the
    hypotheses in play. Returns a :class:`ToolPlan` of DATA; opens no socket.

    Deterministic: sorted by descending score, then role phase, then name — so the
    same surface always yields the same plan (offline-testable, reproducible)."""
    techniques_present = frozenset(
        t for t in (getattr(h, "technique", None) for h in (hypotheses or ())) if t
    )
    recs = []
    for spec in TOOL_REGISTRY.values():
        rec = _score(spec, techniques_present, surface)
        if rec is not None:
            recs.append(rec)
    recs.sort(key=lambda r: (-r.score, _ROLE_ORDER.get(r.spec.role, 9), r.spec.name))
    return ToolPlan(tuple(recs))

