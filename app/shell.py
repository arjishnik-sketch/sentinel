import subprocess
import shlex
import time
from pathlib import Path
from .config import logger

ALLOWED_COMMANDS = {
    "subfinder",
    "httpx",
    "katana",
    "gau",
    "waybackurls",
    "assetfinder",
    "amass",
    "ffuf",
    "nuclei",
    "curl",
    "whois",
    "dig",
    "host",
    "nslookup"
}

class Shell:

    def __init__(self):
        self.history = []

    def allowed(self, command: str):

        try:
            cmd = shlex.split(command)[0]
        except Exception:
            return False

        return cmd in ALLOWED_COMMANDS

    def run(self, command, timeout=300):

        start = time.time()

        if not self.allowed(command):

            return {
                "success": False,
                "command": command,
                "error": "Command not allowed.",
                "stdout": "",
                "stderr": "",
                "duration": 0
            }

        logger.info("Running: %s", command)

        try:

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            elapsed = round(time.time() - start, 2)

            data = {
                "success": result.returncode == 0,
                "command": command,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode,
                "duration": elapsed
            }

            self.history.append(data)

            return data

        except subprocess.TimeoutExpired:

            return {
                "success": False,
                "command": command,
                "stdout": "",
                "stderr": "Command timed out.",
                "duration": timeout
            }

    def last(self):

        if not self.history:
            return None

        return self.history[-1]

    def stats(self):

        return {
            "commands": len(self.history),
            "successful": sum(
                1 for x in self.history if x["success"]
            ),
            "failed": sum(
                1 for x in self.history if not x["success"]
            )
        }


if __name__ == "__main__":

    shell = Shell()

    print("=" * 55)
    print(" Sentinel Shell Engine")
    print("=" * 55)

    tests = [
        "subfinder -version",
        "httpx -version",
        "katana -version"
    ]

    for cmd in tests:

        result = shell.run(cmd)

        print()

        print(result["command"])
        print("-" * 40)

        if result["success"]:
            print(result["stdout"])
        else:
            print(result["stderr"])

    print()

    print(shell.stats())
