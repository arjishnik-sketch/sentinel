class KnowledgeGraph:

    def __init__(self):

        self.graph = {

            "upload": [

                "file upload",

                "multipart",

                "avatar",

                "image upload",

                "media upload",

                "file",

                "mime",

                "content-type"

            ],

            "graphql": [

                "graphql",

                "introspection",

                "schema",

                "query depth",

                "mutation"

            ],

            "swagger": [

                "swagger",

                "openapi",

                "rest api",

                "api security"

            ],

            "jwt": [

                "jwt",

                "json web token",

                "token",

                "authentication"

            ],

            "login": [

                "authentication",

                "oauth",

                "session",

                "login"

            ]

        }

    def expand(self, evidence):

        expanded = []

        for item in evidence:

            expanded.append(item)

            expanded.extend(

                self.graph.get(item, [])

            )

        return list(dict.fromkeys(expanded))