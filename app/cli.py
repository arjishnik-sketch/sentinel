from rich.console import Console
from rich.panel import Panel

from .core import SentinelCore

from .command_router import CommandRouter

from .commands.search_cmd import run as search_cmd
from .commands.skill_cmd import run as skill_cmd
from .commands.random_cmd import run as random_cmd

console=Console()

core=SentinelCore()

router=CommandRouter()


def hunt(arg):

    if not arg:

        console.print("[red]Usage : hunt <target>[/red]")

        return

    core.hunt(arg)


def resume(arg):

    console.print(

        f"[cyan]Resume[/cyan] : {arg}"

    )


def report(arg):

    console.print(

        f"[cyan]Opening report[/cyan] : {arg}"

    )


def findings(arg):

    console.print()

    for f in core.findings.all():

        console.print(f)

    console.print()


def config(arg):

    from .settings import SETTINGS

    console.print(SETTINGS)


def help_cmd(arg):

    console.print("""

Commands

hunt <target>

resume <engagement>

search <keyword>

skill <id>

random

findings

report

config

list

help

exit

""")


def list_cmd(arg):

    from pathlib import Path

    root=Path("engagements")

    root.mkdir(exist_ok=True)

    console.print()

    console.print("[bold cyan]Engagements[/bold cyan]")

    console.print()

    for x in sorted(root.iterdir()):

        if x.is_dir():

            console.print(

                "-",x.name

            )

    console.print()


router.register("hunt",hunt)

router.register("resume",resume)

router.register("report",report)

router.register("findings",findings)

router.register("config",config)

router.register("help",help_cmd)

router.register("list",list_cmd)

router.register("search", search_cmd)

router.register("skill", skill_cmd)

router.register("random", random_cmd)

def banner():

    console.print(

        Panel.fit(

"""

[bold cyan]

Sentinel AI v1.0

[/bold cyan]

Local AI Bug Bounty Assistant

"""

        )

    )


def main():

    banner()

    while True:

        try:

            line=console.input(

                "\n[green]Sentinel > [/green]"

            )

        except KeyboardInterrupt:

            break

        if line.strip() in [

            "exit",

            "quit"

        ]:

            break

        router.execute(line)


if __name__=="__main__":

    main()
