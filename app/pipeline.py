import time

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn
)

console = Console()


class Pipeline:

    def __init__(self):

        self.steps = []

        self.results = []

    def add(self, plugin):

        self.steps.append(plugin)

        return self

    def run(self, target):

        current = target

        self.results = []

        start = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            transient=True
        ) as progress:

            task = progress.add_task(
                "Running Pipeline",
                total=len(self.steps)
            )

            for plugin in self.steps:

                progress.update(
                    task,
                    description=plugin.name
                )

                result = plugin.run(current)

                console.print(f"[cyan]Plugin:[/cyan] {plugin.name}")
                console.print(f"[cyan]Success:[/cyan] {result['success']}")
                console.print(f"[cyan]Error:[/cyan] {result['error']}")

                self.results.append(result)

                if not result["success"]:

                    console.print(
                        f"[red]❌ {plugin.name} failed[/red]"
                    )

                    if result.get("error"):

                        console.print()

                        console.print(
                            "[yellow]Reason:[/yellow]"
                        )

                        console.print(result["error"])

                        console.print()

                    return {

                        "success": False,

                        "duration": round(
                            time.time()-start,
                            2
                        ),

                        "steps": len(self.results),

                        "results": self.results

                    }

                current = result["results"]

                progress.advance(task)

        duration = round(
            time.time()-start,
            2
        )

        return {

            "success": True,

            "duration": duration,

            "steps": len(self.steps),

            "results": self.results

        }


if __name__=="__main__":

    from .plugins.subfinder import Subfinder
    from .plugins.httpx import Httpx
    from .plugins.katana import Katana

    p = Pipeline()

    p.add(Subfinder())

    p.add(Httpx())

    p.add(Katana())

    result = p.run("meta.com")

    print()

    print("="*60)

    print("PIPELINE SUMMARY")

    print("="*60)

    print()

    for r in result["results"]:

        print(

            f"{r['tool']:12} "

            f"{r['count']:5} results"

        )

    print()

    print(result["duration"],"seconds")
