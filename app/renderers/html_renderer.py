from pathlib import Path

class HTMLRenderer:

    def render(self,name,data):

        Path("reports").mkdir(exist_ok=True)

        file=Path("reports")/f"{name}.html"

        html="<html><body>"

        html+="<h1>Sentinel Report</h1>"

        for k,v in data.items():

            html+=f"<h2>{k}</h2><pre>{v}</pre>"

        html+="</body></html>"

        file.write_text(

            html,

            encoding="utf-8"

        )

        return str(file)
