from rich.console import Console
from rich.table import Table

console = Console()

class Hunter:

    def rank(self, findings):

        ranking = []

        def add(title, priority, score, reason):

            ranking.append({

                "title": title,

                "priority": priority,

                "score": score,

                "reason": reason

            })

        if findings["graphql"]:

            add(

                "GraphQL",

                "★★★★★",

                100,

                "Often contains authorization and introspection issues."

            )

        if findings["uploads"]:

            add(

                "File Upload",

                "★★★★★",

                95,

                "Upload functionality deserves manual testing."

            )

        if findings["parameters"]:

            add(

                "Interesting Parameters",

                "★★★★★",

                90,

                "Potential IDOR/BOLA candidates."

            )

        if findings["apis"]:

            add(

                "REST APIs",

                "★★★★☆",

                80,

                "Business logic and authorization."

            )

        if findings["admins"]:

            add(

                "Admin Panels",

                "★★★★☆",

                75,

                "Privilege escalation testing."

            )

        if findings["logins"]:

            add(

                "Authentication",

                "★★★★☆",

                70,

                "Session and authentication review."

            )

        if findings["javascript"]:

            add(

                "JavaScript",

                "★★★☆☆",

                60,

                "Hidden endpoints and client-side secrets."

            )

        ranking.sort(

            key=lambda x: x["score"],

            reverse=True

        )

        return ranking


    def display(self, findings):

        table = Table(title="Recommended Attack Surface")

        table.add_column("#")

        table.add_column("Target")

        table.add_column("Priority")

        table.add_column("Reason")

        ranked = self.rank(findings)

        for i, r in enumerate(ranked, 1):

            table.add_row(

                str(i),

                r["title"],

                r["priority"],

                r["reason"]

            )

        console.print(table)

        return ranked


if __name__ == "__main__":

    sample = {

        "graphql": ["/graphql"],

        "uploads": ["/upload"],

        "parameters": ["id"],

        "apis": ["/api"],

        "admins": ["/admin"],

        "logins": ["/login"],

        "javascript": ["app.js"]

    }

    Hunter().display(sample)
