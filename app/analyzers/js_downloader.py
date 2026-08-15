import hashlib
from pathlib import Path
import requests

CACHE = Path("js_cache")
CACHE.mkdir(exist_ok=True)

class JSDownloader:

    def download(self, urls):

        saved=[]

        for url in urls:

            if not url.lower().endswith(".js"):
                continue

            try:

                r=requests.get(
                    url,
                    timeout=20
                )

                if r.status_code!=200:
                    continue

                name=hashlib.sha1(
                    url.encode()
                ).hexdigest()+".js"

                path=CACHE/name

                path.write_text(
                    r.text,
                    encoding="utf-8",
                    errors="ignore"
                )

                saved.append(
                    {
                        "url":url,
                        "file":str(path),
                        "size":len(r.text)
                    }
                )

            except Exception:
                pass

        return saved


if __name__=="__main__":

    d=JSDownloader()

    files=d.download([

        "https://code.jquery.com/jquery-3.7.1.min.js"

    ])

    print(files)
