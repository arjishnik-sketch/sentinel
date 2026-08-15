from pathlib import Path

class MarkdownRenderer:

    def render(self,name,data):

        Path("reports").mkdir(exist_ok=True)

        file=Path("reports")/f"{name}.md"

        with open(file,"w",encoding="utf-8") as f:

            f.write(f"# Sentinel Report\n\n")

            for k,v in data.items():

                f.write(f"## {k}\n\n")

                f.write(f"{v}\n\n")

        return str(file)
