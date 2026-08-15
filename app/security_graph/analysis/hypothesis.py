from ..models import Hypothesis
from .authorization import AuthorizationDifferential


def hypothesis_from_differential(
    differential: AuthorizationDifferential,
) -> Hypothesis:
    source_id = (
        f"diff:{differential.resource_id}:"
        f"{differential.action}"
    )

    claim = (
        "Authorization behavior differs between principals "
        f"for {differential.action} access to "
        f"{differential.resource_id}."
    )

    return Hypothesis(
        id=f"hyp:{source_id}",
        kind="authorization_differential",
        claim=claim,
        confidence=0.75,
        source_ids=(source_id,),
    )


def hypothesis_from_policy_contradiction(
    contradiction,
) -> Hypothesis:
    source_id = (
        f"policy-contradiction:"
        f"{contradiction.principal_id}:"
        f"{contradiction.resource_id}:"
        f"{contradiction.action}"
    )

    claim = (
        "Observed authorization behavior contradicts explicit "
        f"policy for {contradiction.principal_id}: "
        f"{contradiction.action} access to "
        f"{contradiction.resource_id} was expected to be "
        f"{'allowed' if contradiction.expected else 'denied'} "
        f"but was observed as "
        f"{'allowed' if contradiction.observed else 'denied'}."
    )

    return Hypothesis(
        id=f"hyp:{source_id}",
        kind="authorization_policy_violation",
        claim=claim,
        confidence=0.90,
        evidence_ids=contradiction.evidence_ids,
        source_ids=(source_id,),
    )
