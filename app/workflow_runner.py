from .workflows.idor import IDORWorkflow
from .workflows.engine import WorkflowEngine

class WorkflowRunner:

    def __init__(self):

        self.engine=WorkflowEngine()

        self.engine.register(

            "idor",

            IDORWorkflow().run

        )

    def execute(self,plan,context):

        results=[]

        for step in plan:

            if step=="idor":

                results.append(

                    self.engine.run(

                        "idor",

                        context

                    )

                )

        return results


if __name__=="__main__":

    runner=WorkflowRunner()

    plan=["idor"]

    ctx={

        "findings":{

            "parameters":[

                "id",

                "userid"

            ]

        }

    }

    print(

        runner.execute(

            plan,

            ctx

        )

    )
