import os
import requests
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("OLLAMA_URL") + "/api/chat"
model = os.getenv("OLLAMA_MODEL")

payload = {
    "model": model,
    "messages": [
        {
            "role": "user",
            "content": "Reply with exactly: Sentinel online."
        }
    ],
    "stream": False
}

response = requests.post(url, json=payload, timeout=120)
response.raise_for_status()

print(response.json()["message"]["content"])
