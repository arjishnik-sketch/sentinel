from dataclasses import dataclass

from ..models import AuthorizationObservation


@dataclass(frozen=True)
class AuthorizationDifferential:
    resource_id: str
    action: str
    allowed_principals: tuple[str, ...]
    denied_principals: tuple[str, ...]

    @property
    def different_outcomes(self) -> bool:
        return bool(
            self.allowed_principals
            and self.denied_principals
        )


def find_authorization_differentials(
    observations: list[AuthorizationObservation],
) -> list[AuthorizationDifferential]:
    groups: dict[tuple[str, str], list[AuthorizationObservation]] = {}

    for observation in observations:
        key = (
            observation.resource_id,
            observation.action,
        )
        groups.setdefault(key, []).append(observation)

    differentials: list[AuthorizationDifferential] = []

    for (resource_id, action), items in groups.items():
        allowed = sorted({
            item.principal_id
            for item in items
            if item.allowed
        })

        denied = sorted({
            item.principal_id
            for item in items
            if not item.allowed
        })

        differential = AuthorizationDifferential(
            resource_id=resource_id,
            action=action,
            allowed_principals=tuple(allowed),
            denied_principals=tuple(denied),
        )

        if differential.different_outcomes:
            differentials.append(differential)

    return differentials
