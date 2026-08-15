import re
from pathlib import Path

class EndpointMiner:

    URL = re.compile(r'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+')
    API = re.compile(r'["\\\'](/[A-Za-z0-9_./-]+)["\\\']')
    GRAPHQL = re.compile(r'["\\\']([^"\\\']*graphql[^"\\\']*)["\\\']', re.I)
    WS = re.compile(r'wss?://[^\s"\\\']+')

    def mine_file(self, file):

        text = Path(file).read_text(
            encoding="utf-8",
            errors="ignore"
        )

        return {

            "urls": sorted(set(self.URL.findall(text))),

            "apis": sorted(set(self.API.findall(text))),

            "graphql": sorted(set(self.GRAPHQL.findall(text))),

            "websockets": sorted(set(self.WS.findall(text)))

        }

    def mine_directory(self, directory):

        results=[]

        for js in Path(directory).glob("*.js"):

            results.append({

                "file":js.name,

                "results":self.mine_file(js)

            })

        return results


if __name__=="__main__":

    miner=EndpointMiner()

    data=miner.mine_directory("js_cache")

    for file in data:

        print()

        print("="*60)

        print(file["file"])

        print("="*60)

        for k,v in file["results"].items():

            print()

            print(k.upper())

            for x in v[:20]:

                print(x)
