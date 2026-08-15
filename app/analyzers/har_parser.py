import json

class HARParser:

    def parse(self,file):

        with open(file,"r",encoding="utf-8") as f:

            har=json.load(f)

        out={

            "hosts":set(),

            "paths":set(),

            "params":set(),

            "cookies":set(),

            "headers":set(),

            "graphql":[],

            "uploads":[]

        }

        for e in har["log"]["entries"]:

            req=e["request"]

            url=req["url"]

            out["hosts"].add(

                url.split("/")[2]

            )

            out["paths"].add(url)

            for h in req.get("headers",[]):

                out["headers"].add(

                    h["name"]

                )

            for c in req.get("cookies",[]):

                out["cookies"].add(

                    c["name"]

                )

            for q in req.get("queryString",[]):

                out["params"].add(

                    q["name"]

                )

            mime=req.get(

                "postData",

                {}

            ).get(

                "mimeType",

                ""

            )

            if "graphql" in url.lower():

                out["graphql"].append(url)

            if "multipart/form-data" in mime:

                out["uploads"].append(url)

        for k,v in out.items():

            if isinstance(v,set):

                out[k]=sorted(v)

        return out


if __name__=="__main__":

    print(

        "Usage"

    )

    print(

        "parser.parse('session.har')"

    )
