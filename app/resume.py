from pathlib import Path
from rich.console import Console

console=Console()

class Resume:

    def latest(self):

        root=Path("engagements")

        if not root.exists():

            console.print("[yellow]No engagements found.[/yellow]")

            return

        dirs=[d for d in root.iterdir() if d.is_dir()]

        if not dirs:

            console.print("[yellow]No engagements found.[/yellow]")

            return

        latest=max(

            dirs,

            key=lambda x:x.stat().st_mtime

        )

        console.print(f"[green]Latest Engagement:[/green] {latest.name}")

        return latest.name

if __name__=="__main__":

    Resume().latest()
