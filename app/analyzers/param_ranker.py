import re
from urllib.parse import urlparse, parse_qs

HIGH = {
    "id","userid","user_id","account","accountid","tenant",
    "org","organization","project","role","admin","uid",
    "uuid","owner","email","username","profile","token",
    "apikey","api_key","key","secret","redirect","return",
    "callback","next","file","path","filename"
}

MEDIUM = {
    "page","limit","offset","sort","order","filter",
    "lang","locale","country","region","state","city",
    "search","q","query"
}

class ParameterRanker:

    def analyze(self, urls):

        params = {}

        for url in urls:

            try:

                parsed = urlparse(url)

                query = parse_qs(parsed.query)

            except Exception:

                continue

            for p in query.keys():

                score = 1

                reason = "Generic"

                name = p.lower()

                if name in HIGH:

                    score = 5

                    reason = "High-value authorization/object reference parameter"

                elif name in MEDIUM:

                    score = 3

                    reason = "Common application parameter"

                elif re.search(r"id|uuid|guid", name):

                    score = 5

                    reason = "Identifier-like parameter"

                params[name] = {
                    "score": score,
                    "reason": reason
                }

        ranked = sorted(

            params.items(),

            key=lambda x: x[1]["score"],

            reverse=True

        )

        return ranked


if __name__ == "__main__":

    p = ParameterRanker()

    urls = [

        "https://example.com/api/user?id=10",

        "https://example.com/profile?userid=42",

        "https://example.com/list?page=3",

        "https://example.com/file?filename=test.txt"

    ]

    for name,data in p.analyze(urls):

        print(

            f"{name:15}",

            "★"*data["score"],

            "-",data["reason"]

        )
