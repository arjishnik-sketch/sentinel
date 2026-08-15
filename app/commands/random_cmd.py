from rich.console import Console

from app.knowledge.engine import KnowledgeEngine

console = Console()

engine = KnowledgeEngine()


def run(arg):

    r = engine.random()

    console.print()

    console.print(f"[cyan]{r['title']}[/cyan]")

    console.print()

    console.print(f"ID : {r['id']}")

    console.print(

        f"Automation : {'Yes' if r['automation'] else 'No'}"

    )