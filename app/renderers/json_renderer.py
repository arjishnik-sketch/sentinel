import json
from pathlib import Path

class JSONRenderer:

    def render(self,name,data):

        Path("reports").mkdir(exist_ok=True)

        file=Path("reports")/f"{name}.json"

        file.write_text(

            json.dumps(

                data,

                indent=2

            ),

            encoding="utf-8"

        )

        return str(file)
