import subprocess

from ..tools.resolver import resolve

from .base import Plugin

class Httpx(Plugin):
    name = "httpx"

    def run(self, targets):

        if isinstance(targets, str):
            targets = [targets]

        try:

            binary = resolve("httpx")

            r = subprocess.run(
                [binary, "-silent"],
                input="\n".join(targets),
                text=True,
                capture_output=True,
                timeout=300
            )

            if r.returncode != 0:
                return self.result("", [], False, r.stderr.strip())

            data = [
                x.strip()
                for x in r.stdout.splitlines()
                if x.strip()
            ]

            return self.result("", data)

        except Exception as e:
            return self.result("", [], False, str(e))
