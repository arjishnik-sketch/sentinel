from rich.console import Console
from rich.rule import Rule

console = Console()


class Executor:

    def preview(self, plan):

        console.print()

        console.print(

            Rule(

                f"[bold cyan]{plan.skill}"

            )

        )

        console.print(

            f"[green]Target[/green] : {plan.target}"

        )

        console.print(

            f"[yellow]Confidence[/yellow] : {plan.confidence}%"

        )

        console.print()

        for step in plan.steps:

            console.print(

                f"[cyan]{step.title}[/cyan]"

            )

            console.print()

            for cmd in step.commands:

                console.print(

                    f"$ {cmd.command}"

                )

            console.print()

        console.print(

            "[bold yellow]Execution disabled (Preview Mode)[/bold yellow]"

        )