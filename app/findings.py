from datetime import datetime, UTC

class Findings:

    def __init__(self):

        self.items=[]

    def add(

        self,

        title,

        severity,

        evidence,

        workflow,

        confidence="Medium"

    ):

        self.items.append({

            "title":title,

            "severity":severity,

            "workflow":workflow,

            "confidence":confidence,

            "evidence":evidence,

            "status":"Open",

            "created":datetime.now(UTC).isoformat()

        })

    def close(self,index):

        self.items[index]["status"]="Closed"

    def all(self):

        return self.items

    def summary(self):

        out={

            "Critical":0,

            "High":0,

            "Medium":0,

            "Low":0,

            "Info":0

        }

        for i in self.items:

            out[i["severity"]]+=1

        return out


if __name__=="__main__":

    f=Findings()

    f.add(

        "Potential IDOR",

        "Medium",

        "/api/user?id=",

        "idor"

    )

    f.add(

        "GraphQL Endpoint",

        "Info",

        "/graphql",

        "graphql"

    )

    print(f.summary())

    print(f.all())
