from app.workflows.idor import IDORWorkflow

from ..models import WorkflowPlan


def build_idor_plan(
    parameters: list[str],
    *,
    plan_id: str = "workflow:idor",
) -> WorkflowPlan:
    workflow = IDORWorkflow()

    result = workflow.run(
        {
            "findings": {
                "parameters": parameters,
            }
        }
    )

    return WorkflowPlan(
        id=plan_id,
        workflow=result["workflow"],
        priority=result["priority"],
        interesting=tuple(result["interesting"]),
        tests=tuple(result["tests"]),
    )
