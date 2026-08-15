from pathlib import Path
import json
from datetime import datetime

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

class Report:

    def __init__(self, engagement, scan):

        self.engagement = engagement
        self.scan = scan
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def markdown(self):

        file = REPORT_DIR / f"{self.engagement}.md"

        with open(file, "w", encoding="utf-8") as f:

            f.write(f"# Sentinel Report\n\n")
            f.write(f"## Target\n{self.engagement}\n\n")
            f.write(f"Generated : {self.timestamp}\n\n")

            for section, value in self.scan.items():

                f.write(f"## {section}\n\n")

                if isinstance(value, dict):

                    for k, v in value.items():
                        f.write(f"- **{k}** : {v}\n")

                elif isinstance(value, list):

                    for item in value:
                        f.write(f"- {item}\n")

                else:

                    f.write(str(value))

                f.write("\n\n")

        return file

    def html(self):

        file = REPORT_DIR / f"{self.engagement}.html"

        html = f"""
<html>
<head>
<title>Sentinel Report</title>

<style>

body{{font-family:Arial;padding:30px;background:#fafafa;}}

h1{{color:#1976d2;}}

pre{{background:white;padding:15px;border:1px solid #ddd;}}

</style>

</head>

<body>

<h1>Sentinel Report</h1>

<h2>{self.engagement}</h2>

<p>{self.timestamp}</p>

"""

        for section, value in self.scan.items():

            html += f"<h3>{section}</h3>"

            html += "<pre>"

            html += json.dumps(value, indent=2)

            html += "</pre>"

        html += "</body></html>"

        file.write_text(html, encoding="utf-8")

        return file

    def json(self):

        file = REPORT_DIR / f"{self.engagement}.json"

        file.write_text(

            json.dumps(

                self.scan,

                indent=2

            ),

            encoding="utf-8"

        )

        return file

    def build(self):

        return {

            "markdown": str(self.markdown()),

            "html": str(self.html()),

            "json": str(self.json())

        }


if __name__=="__main__":

    demo={

        "overview":{

            "alive":92,

            "graphql":2,

            "swagger":1

        },

        "findings":[

            "Potential GraphQL",

            "Interesting Parameters"

        ]

    }

    r=Report("meta",demo)

    print(r.build())
