from ..graph import SecurityGraph
from ..models import Principal


def select_principal(
    graph: SecurityGraph,
) -> Principal | None:
    """
    Select a deterministic principal from the graph.

    Policy:
    - Only principals currently present in the graph are eligible.
    - Return the lexicographically first principal ID.
    - Return None when no principals exist.

    This deliberately does not infer or invent identities.
    """
    if not graph.principals:
        return None

    principal_id = sorted(graph.principals)[0]

    return graph.principals[principal_id]
