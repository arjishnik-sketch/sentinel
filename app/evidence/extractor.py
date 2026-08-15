import re


class EvidenceExtractor:

    KEYWORDS = {

        "graphql":[
            "graphql",
            "__schema",
            "__type"
        ],

        "jwt":[
            "jwt",
            "bearer",
            "authorization"
        ],

        "swagger":[
            "swagger",
            "openapi"
        ],

        "upload":[
            "upload",
            "multipart/form-data",
            "multipart"
        ],

        "oauth":[
            "oauth",
            "oauth2",
            "openid"
        ],

        "websocket":[
            "websocket",
            "ws://",
            "wss://"
        ],

        "firebase":[
            "firebase"
        ],

        "s3":[
            "amazonaws.com",
            "s3.amazonaws.com"
        ],

        "admin":[
            "/admin",
            "administrator"
        ],

        "api":[
            "/api/",
            "/v1/",
            "/v2/"
        ]

    }

    def extract(self, recon):

        text = str(recon).lower()

        found = []

        for keyword, signatures in self.KEYWORDS.items():

            for sig in signatures:

                if sig.lower() in text:

                    found.append(keyword)

                    break

        return sorted(set(found))