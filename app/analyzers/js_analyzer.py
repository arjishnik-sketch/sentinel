import re
import requests


class JSAnalyzer:

    endpoint = re.compile(r'https?://[^\s"\']+')
    graphql = re.compile(r'graphql', re.I)
    fetch = re.compile(r'fetch\s*\(')
    axios = re.compile(r'axios\.')
    websocket = re.compile(r'wss?://[^\s"\']+')
    jwt = re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')
    apikey = re.compile(r'AIza[0-9A-Za-z\-_]{35}')

    def analyze(self, url):

        try:

            r = requests.get(url, timeout=20)

            text = r.text

        except Exception as e:

            return {"error": str(e)}

        return {

            "url": url,

            "size": len(text),

            "graphql": bool(self.graphql.search(text)),

            "fetch": len(self.fetch.findall(text)),

            "axios": len(self.axios.findall(text)),

            "websockets": self.websocket.findall(text),

            "urls": self.endpoint.findall(text),

            "jwt": self.jwt.findall(text),

            "google_api_keys": self.apikey.findall(text)

        }


if __name__ == "__main__":

    js = JSAnalyzer()

    print(

        js.analyze(

            "https://code.jquery.com/jquery-3.7.1.min.js"

        )

    )
