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
