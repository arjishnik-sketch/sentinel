"""
Compose proven single-class findings into proven attack chains.

This is the capstone, and it is deliberately thin: it owns ZERO verdict logic.
For the first honest chain (SQLi ⇒ IDOR/BOLA) it

  1. reads a CONFIRMED injection finding's real leaked body and extracts
     ``leaked_object_id`` artifacts (:func:`extract_artifacts`),
  2. substitutes each leaked id into an operator-declared downstream BOLA probe
     template, and runs the privilege-escalation class's UNCHANGED
     :func:`run_privesc_investigation` on a fresh scratch graph to get a real
     verdict from its own pure judge,
  3. runs the SAME downstream probe with a same-shaped **decoy** id, and
  4. emits a :class:`ChainFinding` ONLY when
     ``edge_proven = (real == VALIDATED and decoy != VALIDATED)``.

The decoy test is the honesty wall: it proves the edge is load-bearing on the
*specific* leaked identifier rather than on a route that would answer for any
id (public route / an app that 200s everything — exactly the confound the
downstream judge's own anonymous baseline also guards against). Chains are capped
at 2 links; deeper compositions are a separate `chain_lead` concern and are not
asserted as proven here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..graph import SecurityGraph
from ..privesc.privesc_policy import PrivEscCheck, PrivEscPolicy, PrivEscPrincipal
from ..privesc.run import run_privesc_investigation
from .artifacts import extract_artifacts
from .chain_finding import ChainArtifact, ChainFinding, ChainLink, escalate, max_severity
from .consume import DEFAULT_PLACEHOLDER, decoy_value, inject_artifact


@dataclass(frozen=True)
class BolaChainTarget:
    """
    Operator/discovery-declared downstream BOLA probe for a chain's second link.

    Pure DATA — the engine holds no target specifics. `attacker_headers` is a
    genuine captured session (the liveness anchor), `control_path` is a route the
    attacker legitimately owns (proves the session is alive), and
    `breach_path_template` carries the placeholder the leaked id is substituted
    into (e.g. ``/rest/basket/{id}``).
    """

    breach_path_template: str
    attacker_headers: tuple[tuple[str, str], ...] = ()
    control_path: str = "/"
    control_method: str = "GET"
    breach_method: str = "GET"
    victim: str = "victim"
    severity: str = "HIGH"
    placeholder: str = DEFAULT_PLACEHOLDER
    artifact_kind: str = "leaked_object_id"


def _bola_verdict(
    target_base: str,
    target: BolaChainTarget,
    breach_path: str,
    *,
    executor,
):
    """
    Run the UNCHANGED privesc prove-chain for one concrete breach path on a fresh
    scratch graph. Returns (status, PrivEscProbeResult | None).
    """
    scratch = SecurityGraph()
    principal = PrivEscPrincipal(
        name="chain-attacker",
        headers=tuple(target.attacker_headers),
        control_method=target.control_method,
        control_path=target.control_path,
        role="user",
    )
    check = PrivEscCheck(
        type="horizontal",
        attacker="chain-attacker",
        breach_method=target.breach_method,
        breach_path=breach_path,
        victim=target.victim,
        severity=target.severity,
    )
    policy = PrivEscPolicy(principals=(principal,), checks=(check,))
    results = run_privesc_investigation(
        scratch, policy, target_base=target_base, executor=executor
    )
    if not results:
        return "INCONCLUSIVE", None
    return results[0].status, results[0]


def _chain_claim(artifact: ChainArtifact, breach_path: str) -> str:
    return (
        f"Proven chain: a confirmed SQL injection leaked object id "
        f"'{artifact.value}' (from {artifact.locator or 'the dumped result set'}), "
        f"which then unlocked the forbidden object at {breach_path} — an "
        "unauthenticated attacker escalates injection into direct object access. "
        "A same-shaped decoy id was denied, so the edge is load-bearing on the "
        "leaked identifier."
    )


def compose_chains(
    graph: SecurityGraph,
    *,
    bola_targets: tuple[BolaChainTarget, ...],
    target_base: str,
    executor=None,
    source_kind: str = "injection",
) -> list[ChainFinding]:
    """
    Compose CONFIRMED `source_kind` findings with declared BOLA targets into
    proven 2-link chains. See the module docstring for the honesty contract.

    `executor` is passed straight through to the privesc runner; when None it
    builds a scope-bound live executor, exactly like a standalone privesc run.
    """
    findings = sorted(
        graph.findings_for(kind=source_kind, status="OPEN"),
        key=lambda item: item.id,
    )
    if not findings:
        return []

    chains: list[ChainFinding] = []
    for finding in findings:
        artifacts = [
            artifact
            for artifact in extract_artifacts(graph, finding)
            if artifact.kind == "leaked_object_id"
        ]
        if not artifacts:
            continue

        for target in bola_targets:
            if target.placeholder not in target.breach_path_template:
                continue
            for artifact in artifacts:
                real_path = inject_artifact(
                    target.breach_path_template, artifact.value,
                    placeholder=target.placeholder,
                )
                decoy = decoy_value(artifact.value)
                decoy_path = inject_artifact(
                    target.breach_path_template, decoy,
                    placeholder=target.placeholder,
                )

                real_status, real_result = _bola_verdict(
                    target_base, target, real_path, executor=executor
                )
                decoy_status, _ = _bola_verdict(
                    target_base, target, decoy_path, executor=executor
                )

                edge_proven = (
                    real_status == "VALIDATED" and decoy_status != "VALIDATED"
                )
                if not edge_proven:
                    continue

                severity = escalate(max_severity(finding.severity, target.severity))
                link_a = ChainLink(
                    finding_id=finding.id,
                    kind=finding.kind,
                    claim=finding.claim,
                    status="CONFIRMED",
                )
                link_b = ChainLink(
                    finding_id=f"chainlink:privilege_escalation:{real_path}",
                    kind="privilege_escalation",
                    claim=real_result.claim if real_result is not None else "",
                    status="VALIDATED",
                )
                evidence_ids = (artifact.evidence_id,)
                if real_result is not None and real_result.experiment_id:
                    evidence_ids = evidence_ids + (real_result.experiment_id,)

                chains.append(
                    ChainFinding(
                        id=f"chain:{finding.id}=>{real_path}",
                        links=(link_a, link_b),
                        artifact=artifact,
                        real_status=real_status,
                        decoy_status=decoy_status,
                        decoy_value=decoy,
                        breach_path=real_path,
                        severity=severity,
                        claim=_chain_claim(artifact, real_path),
                        edge_proven=True,
                        evidence_ids=evidence_ids,
                    )
                )
    return chains
