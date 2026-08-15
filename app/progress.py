from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn
)

class ProgressManager:

    def __init__(self):

        self.progress = Progress(

            SpinnerColumn(),

            TextColumn("[bold cyan]{task.description}"),

            BarColumn(),

            "[progress.percentage]{task.percentage:>3.0f}%",

            TimeElapsedColumn()

        )

    def __enter__(self):

        self.progress.start()

        return self

    def __exit__(self,*args):

        self.progress.stop()

    def task(self,name,total=100):

        return self.progress.add_task(

            name,

            total=total

        )

    def update(self,task,advance):

        self.progress.update(

            task,

            advance=advance

        )


if __name__=="__main__":

    import time

    with ProgressManager() as p:

        t=p.task("Recon",100)

        for _ in range(10):

            time.sleep(0.2)

            p.update(t,10)
