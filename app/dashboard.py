from rich.console import Console
from rich.table import Table

console=Console()

class Dashboard:

    def show(

        self,

        engagement,

        findings,

        workflows

    ):

        table=Table(title="Sentinel Session")

        table.add_column("Item")

        table.add_column("Value")

        table.add_row(

            "Engagement",

            engagement

        )

        table.add_row(

            "Findings",

            str(len(findings))

        )

        table.add_row(

            "Workflows",

            ", ".join(workflows)

        )

        console.print(table)


if __name__=="__main__":

    Dashboard().show(

        "meta",

        [

            1,

            2,

            3

        ],

        [

            "idor",

            "graphql"

        ]

    )
