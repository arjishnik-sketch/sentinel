import shutil
import subprocess
import subprocess

from .base import Plugin
from ..tools.resolver import resolve
from .base import Plugin


class Subfinder(Plugin):

    name = "subfinder"

    def run(self, target):

        try:

            binary = resolve("subfinder")

            cmd = [
                binary,
                "-silent",
                "-d",
                target
            ]
            
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if r.returncode != 0:

                error = (
                    f"Command: {' '.join(cmd)}\n"
                    f"Exit Code: {r.returncode}\n"
                    f"STDERR:\n{r.stderr}\n"
                    f"STDOUT:\n{r.stdout}"
                )

                return self.result(
                    target,
                    [],
                    False,
                    error
                )

            data = [
                x.strip()
                for x in r.stdout.splitlines()
                if x.strip()
            ]

            return self.result(target, data)

        except Exception as e:

            return self.result(
                target,
                [],
                False,
                repr(e)
            )