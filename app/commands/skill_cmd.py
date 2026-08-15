from rich.console import Console

from app.knowledge.engine import KnowledgeEngine

console = Console()

engine = KnowledgeEngine()


def run(arg):

    if not arg:

        console.print("[red]Usage: skill <id>[/red]")

        return

    try:

        text = engine.skill(int(arg))

        if text:

            console.print(text)

        else:

            console.print("[red]Skill not found.[/red]")

    except ValueError:

        console.print("[red]Skill id must be numeric.[/red]")