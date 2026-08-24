"""
Typed artifacts and the proven-edge finding for the chaining capstone.

A *chain* is an ordered composition of two already-proven single-class findings
in which a **typed artifact** extracted from the first class's real recorded
evidence is consumed as probe input by the second class, and the second class's
OWN pure judge then fires VALIDATED. Nothing here invents a verdict: the value
carried between links is read out of evidence a class already recorded, and the
downstream verdict is produced by that class's unchanged run/judge.

The honesty wall is the **decoy test**. An edge is emitted only when the REAL
extracted value makes the downstream judge fire VALIDATED *and* a same-shaped but
different decoy value does NOT — proving the link is load-bearing on the specific
leaked artifact rather than on a route that would answer for any input. See
:func:`app.security_graph.chaining.compose.compose_chains`.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Severity ladder, low → high. Escalating a chain one rung reflects that
# composing two boundaries is strictly worse than either alone.
_LADDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _rung(severity: str) -> int:
    try:
        return _LADDER.index(severity.upper())
    except (ValueError, AttributeError):
        return len(_LADDER) - 1


def max_severity(first: str, second: str) -> str:
    """The higher of two severities on the shared ladder."""
    return _LADDER[max(_rung(first), _rung(second))]


def escalate(severity: str) -> str:
    """Bump a severity one rung, capped at CRITICAL."""
    return _LADDER[min(_rung(severity) + 1, len(_LADDER) - 1)]


@dataclass(frozen=True)
class ChainArtifact:
    """
    A typed value extracted from ONE class's real recorded evidence, suitable
    for feeding as probe input to another class.

    `value` was read verbatim from the evidence identified by `evidence_id`;
    `locator` records where inside that evidence it was found (provenance, never
    a claim). No artifact is ever synthesised — if the evidence does not contain
    it, it is not produced.
    """

    kind: str                 # e.g. "leaked_object_id"
    value: str
    source_finding_id: str
    source_kind: str          # the class the value was leaked by, e.g. "injection"
    evidence_id: str          # the live probe evidence the value was read from
    locator: str = ""         # JSON key / path it was read from (provenance)


@dataclass(frozen=True)
class ChainLink:
    """One proven step in a chain (a single class's verdict on one identity)."""

    finding_id: str
    kind: str                 # class kind, e.g. "injection" / "privilege_escalation"
    claim: str
    status: str               # "CONFIRMED" (materialised) or "VALIDATED" (judge)


@dataclass(frozen=True)
class ChainFinding:
    """
    A proven 2-link attack chain: link A leaked a typed artifact that provably
    unlocked link B, and the decoy test confirmed the edge is load-bearing.

    `edge_proven` is always True for an emitted ChainFinding — the composer never
    emits an unproven edge. `real_status`/`decoy_status` and `decoy_value` are
    retained so the honest differential is fully auditable after the fact.
    """

    id: str
    links: tuple[ChainLink, ...]      # ordered A → B (this class caps at 2)
    artifact: ChainArtifact
    real_status: str                  # downstream judge on the REAL value: VALIDATED
    decoy_status: str                 # downstream judge on the decoy: NOT VALIDATED
    decoy_value: str
    breach_path: str                  # the concrete B route the leaked value unlocked
    severity: str
    claim: str
    edge_proven: bool = True
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
