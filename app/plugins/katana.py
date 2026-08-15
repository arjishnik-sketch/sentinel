import subprocess

from ..tools.resolver import resolve

from .base import Plugin

class Katana(Plugin):
    name = "katana"

    def run(self, targets):

        if isinstance(targets, str):
            targets = [targets]

        try:

            binary = resolve("katana")

            r = subprocess.run(
                [binary, "-silent"],
                input="\n".join(targets),
                text=True,
                capture_output=True,
                timeout=600
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
