MAPPINGS = {

    "graphql": [
        "graphql",
        "graph ql",
        "graphql api",
        "graphql security",
        "graphql introspection"
    ],

    "swagger": [
        "swagger",
        "openapi",
        "open api",
        "rest api",
        "api documentation",
        "api discovery",
        "api security"
    ],

    "jwt": [
        "jwt",
        "json web token",
        "bearer token",
        "bearer",
        "token security"
    ],

    "oauth": [
        "oauth",
        "oauth2",
        "openid",
        "oidc",
        "authorization"
    ],

    "upload": [
        "file upload",
        "upload",
        "multipart",
        "multipart/form-data",
        "file handling",
        "content-type"
    ],

    "api": [
        "api",
        "rest api",
        "api security",
        "api testing",
        "web api"
    ],

    "admin": [
        "authentication",
        "authorization",
        "access control",
        "admin",
        "administrator"
    ],

    "firebase": [
        "firebase",
        "firestore"
    ],

    "s3": [
        "amazon s3",
        "s3",
        "bucket",
        "storage bucket"
    ],

    "websocket": [
        "websocket",
        "web socket",
        "ws",
        "wss"
    ]

}


def expand(keyword):

    keyword = keyword.lower().strip()

    return MAPPINGS.get(keyword, [keyword])