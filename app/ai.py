import time
import requests

from .config import (
    OLLAMA_URL,
    OLLAMA_MODEL,
    REQUEST_TIMEOUT,
    logger
)

SYSTEM_PROMPT = """
You are Sentinel.

You are a professional AI Security Assistant.

Rules:

- Never hallucinate.
- Never invent findings.
- Only reason from supplied evidence.
- Be concise.
- Prefer bullet points.
- When uncertain say:
  "Not enough evidence."
"""

class SentinelAI:

    def __init__(self):

        self.url = OLLAMA_URL
        self.model = OLLAMA_MODEL

        self.history = [
            {
                "role":"system",
                "content":SYSTEM_PROMPT
            }
        ]

        self.requests = 0

    def health(self):

        try:

            r = requests.get(
                self.url + "/api/tags",
                timeout=10
            )

            return r.ok

        except Exception:

            return False

    def models(self):

        r = requests.get(
            self.url + "/api/tags"
        )

        r.raise_for_status()

        return [
            x["name"]
            for x in r.json()["models"]
        ]

    def reset(self):

        self.history = [
            {
                "role":"system",
                "content":SYSTEM_PROMPT
            }
        ]

    def ask(
        self,
        prompt,
        stream=False,
        retries=2
    ):

        self.history.append(
            {
                "role":"user",
                "content":prompt
            }
        )

        payload = {

            "model":self.model,

            "messages":self.history,

            "stream":stream

        }

        for attempt in range(retries+1):

            try:

                r = requests.post(

                    self.url+"/api/chat",

                    json=payload,

                    timeout=REQUEST_TIMEOUT,

                    stream=stream

                )

                r.raise_for_status()

                if stream:

                    answer=""

                    for line in r.iter_lines():

                        if not line:

                            continue

                        obj = requests.models.complexjson.loads(line)

                        if "message" in obj:

                            chunk=obj["message"]["content"]

                            print(chunk,end="",flush=True)

                            answer += chunk

                    print()

                else:

                    answer = r.json()["message"]["content"]

                self.history.append(

                    {
                        "role":"assistant",
                        "content":answer
                    }

                )

                self.requests += 1

                return answer

            except Exception as e:

                logger.warning(

                    "Retry %d failed: %s",

                    attempt+1,

                    e

                )

                time.sleep(1)

        raise RuntimeError("AI request failed.")

    def stats(self):

        return {

            "model":self.model,

            "messages":len(self.history),

            "requests":self.requests

        }


if __name__ == "__main__":

    ai = SentinelAI()

    print()

    print("="*50)

    print(" Sentinel AI Test")

    print("="*50)

    print()

    print("Health :", ai.health())

    print("Models :", ai.models())

    print()

    print(ai.ask(

        "Reply with exactly: Sentinel AI Online."

    ))

    print()

    print(ai.stats())

