from rich.console import Console
from rich.table import Table

from app.knowledge.engine import KnowledgeEngine

console = Console()

engine = KnowledgeEngine()


def run(arg):

    if not arg:

        console.print("[red]Usage: search <keyword>[/red]")

        return

    rows = engine.search(arg)

    table = Table(title=f"Knowledge Search : {arg}")

    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Automation")

    for r in rows:

        table.add_row(

            str(r["id"]),

            r["title"],

            "✓" if r["automation"] else ""

        )

    console.print(table)