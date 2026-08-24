"""
Provable attack-chaining — Sentinel's capstone over the single-class prove-chains.

Every other class answers one question about one boundary. This capstone asks
the question a real adversary asks: *do these boundaries compose into a path?*
It never introduces new verdict logic. An edge A ⇒ B is emitted only when

  1. A is a CONFIRMED single-class finding whose OWN real evidence yields a typed
     artifact (e.g. a SQL injection's boolean-tautology arm dumped a result set
     that leaked another object's id — recorded verbatim in the probe's
     ``response_body_text``),
  2. that artifact is consumed as B's probe input, and B's OWN unchanged pure
     judge fires VALIDATED, AND
  3. the **decoy test** holds: a same-shaped but different value does NOT make B
     fire VALIDATED — proving the edge is load-bearing on the *specific* leaked
     artifact, not on a route that would answer for anything.

``edge_proven = (real == VALIDATED and decoy != VALIDATED)``. Chains are capped
at two links; the first shipped chain is SQLi ⇒ IDOR/BOLA. Nothing is ever
manufactured: if the leaked body carries no id, or the decoy also validates, no
chain is claimed.
"""

from .chain_finding import (
    ChainArtifact,
    ChainFinding,
    ChainLink,
    escalate,
    max_severity,
)
from .artifacts import extract_artifacts
from .consume import DEFAULT_PLACEHOLDER, decoy_value, inject_artifact
from .compose import BolaChainTarget, compose_chains
from .chain_policy import ChainPolicy, load_chain_targets, parse_chain_targets

__all__ = [
    "ChainArtifact",
    "ChainFinding",
    "ChainLink",
    "escalate",
    "max_severity",
    "extract_artifacts",
    "DEFAULT_PLACEHOLDER",
    "decoy_value",
    "inject_artifact",
    "BolaChainTarget",
    "compose_chains",
    "ChainPolicy",
    "load_chain_targets",
    "parse_chain_targets",
]
