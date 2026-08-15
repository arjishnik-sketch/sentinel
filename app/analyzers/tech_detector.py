import requests

class TechDetector:

    HEADERS = {

        "Server",

        "X-Powered-By",

        "CF-Cache-Status",

        "X-AspNet-Version",

        "X-Generator"

    }

    def detect(self,url):

        try:

            r=requests.get(

                url,

                timeout=15,

                allow_redirects=True

            )

        except Exception as e:

            return {

                "url":url,

                "error":str(e)

            }

        tech=[]

        headers=dict(r.headers)

        for h,v in headers.items():

            if h in self.HEADERS:

                tech.append(

                    f"{h}: {v}"

                )

        html=r.text.lower()

        if "next/static" in html:

            tech.append("Next.js")

        if "__nuxt" in html:

            tech.append("Nuxt")

        if "wp-content" in html:

            tech.append("WordPress")

        if "graphql" in html:

            tech.append("GraphQL")

        if "swagger-ui" in html:

            tech.append("Swagger")

        if "cloudflare" in html:

            tech.append("Cloudflare")

        return {

            "url":url,

            "status":r.status_code,

            "technology":sorted(set(tech))

        }


if __name__=="__main__":

    t=TechDetector()

    print(

        t.detect(

            "https://example.com"

        )

    )
