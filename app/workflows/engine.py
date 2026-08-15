from rich.console import Console

console = Console()

class WorkflowEngine:

    def __init__(self):

        self.workflows={}

    def register(self,name,func):

        self.workflows[name]=func

    def run(self,name,context):

        if name not in self.workflows:

            raise Exception(f"Unknown workflow: {name}")

        console.print(f"\n[cyan]Running Workflow[/cyan] : {name}")

        return self.workflows[name](context)

    def list(self):

        return sorted(self.workflows.keys())


if __name__=="__main__":

    w=WorkflowEngine()

    w.register(

        "demo",

        lambda x:{

            "status":"ok",

            "context":x

        }

    )

    print(

        w.list()

    )

    print(

        w.run(

            "demo",

            {

                "target":"meta.com"

            }

        )

    )
