class Playbooks:

    def recommend(self, findings):

        recommendations = []

        if findings["graphql"]:
            recommendations.append({
                "title":"GraphQL",
                "priority":"HIGH",
                "tests":[
                    "Check introspection",
                    "Alias batching",
                    "Field suggestions",
                    "Authorization on object queries",
                    "Mutation authorization",
                    "Deep query DoS"
                ]
            })

        if findings["uploads"]:
            recommendations.append({
                "title":"File Upload",
                "priority":"HIGH",
                "tests":[
                    "Extension bypass",
                    "Double extension",
                    "MIME bypass",
                    "SVG upload",
                    "Filename traversal",
                    "Overwrite existing file"
                ]
            })

        if findings["logins"]:
            recommendations.append({
                "title":"Authentication",
                "priority":"HIGH",
                "tests":[
                    "Username enumeration",
                    "Password reset flow",
                    "Rate limiting",
                    "Remember-me tokens",
                    "Session fixation",
                    "CSRF on login"
                ]
            })

        if findings["admins"]:
            recommendations.append({
                "title":"Admin Panel",
                "priority":"HIGH",
                "tests":[
                    "Access without authentication",
                    "Horizontal privilege escalation",
                    "Vertical privilege escalation",
                    "Hidden endpoints",
                    "Backup files"
                ]
            })

        if findings["apis"]:
            recommendations.append({
                "title":"REST API",
                "priority":"HIGH",
                "tests":[
                    "IDOR/BOLA",
                    "Mass Assignment",
                    "HTTP verb tampering",
                    "CORS",
                    "Rate limiting",
                    "Parameter pollution"
                ]
            })

        if findings["javascript"]:
            recommendations.append({
                "title":"JavaScript",
                "priority":"MEDIUM",
                "tests":[
                    "Secrets",
                    "Hidden endpoints",
                    "Source maps",
                    "Unused APIs",
                    "Hardcoded credentials"
                ]
            })

        if findings["parameters"]:
            recommendations.append({
                "title":"Interesting Parameters",
                "priority":"HIGH",
                "tests":[
                    "IDOR",
                    "Integer increment",
                    "UUID swap",
                    "Negative values",
                    "Null values",
                    "Mass assignment"
                ]
            })

        return recommendations


if __name__=="__main__":

    p=Playbooks()

    sample={

        "graphql":["/graphql"],

        "uploads":["/upload"],

        "logins":["/login"],

        "admins":[],

        "apis":["/api"],

        "javascript":["app.js"],

        "parameters":["id","userid"]

    }

    for x in p.recommend(sample):

        print()

        print("="*50)

        print(x["title"])

        print("Priority:",x["priority"])

        for t in x["tests"]:

            print("-",t)
