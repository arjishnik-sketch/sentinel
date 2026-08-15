from pathlib import Path
import json

class Stats:

    def summary(self):

        root=Path("engagements")

        reports=Path("reports")

        return{

            "engagements":len(list(root.glob("*"))) if root.exists() else 0,
            "reports":len(list(reports.glob("*"))) if reports.exists() else 0,
            "markdown":len(list(reports.glob("*.md"))) if reports.exists() else 0,
            "html":len(list(reports.glob("*.html"))) if reports.exists() else 0,
            "json":len(list(reports.glob("*.json"))) if reports.exists() else 0

        }

if __name__=="__main__":

    print(

        json.dumps(

            Stats().summary(),

            indent=2

        )

    )
