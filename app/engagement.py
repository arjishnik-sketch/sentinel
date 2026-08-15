import json
from pathlib import Path
from datetime import datetime, UTC

ROOT = Path("engagements")

ROOT.mkdir(exist_ok=True)

class Engagement:

    def __init__(self,name):

        self.name=name

        self.root=ROOT/name

        self.root.mkdir(exist_ok=True)

        (self.root/"reports").mkdir(exist_ok=True)

        (self.root/"evidence").mkdir(exist_ok=True)

        (self.root/"notes").mkdir(exist_ok=True)

        (self.root/"js").mkdir(exist_ok=True)

    def save_json(self,name,data):

        with open(

            self.root/f"{name}.json",

            "w",

            encoding="utf-8"

        ) as f:

            json.dump(

                data,

                f,

                indent=2

            )

    def save_note(self,title,text):

        with open(

            self.root/"notes"/f"{title}.md",

            "w",

            encoding="utf-8"

        ) as f:

            f.write(text)

    def metadata(self):

        return {

            "name":self.name,

            "created":datetime.now(UTC).isoformat(),

            "path":str(self.root)

        }

if __name__=="__main__":

    e=Engagement("meta")

    print(e.metadata())

    e.save_json(

        "summary",

        {

            "alive":92

        }

    )

    e.save_note(

        "todo",

        "- Check GraphQL\n- Test IDOR"

    )

    print("Done.")
