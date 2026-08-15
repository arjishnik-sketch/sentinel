import re
from pathlib import Path


class SkillParser:

    def parse(self, path):

        path = Path(path)

        text = path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

        return {

            "title": self.title(text),

            "commands": self.commands(text),

            "raw": text

        }

    def title(self, text):

        m = re.search(
            r"^#\s+(.+)$",
            text,
            re.M
        )

        if m:

            return m.group(1).strip()

        return "Unknown Skill"

    def commands(self, text):

        cmds = []

        pattern = r"```(?:bash|shell|sh|powershell|cmd)?\n(.*?)```"

        blocks = re.findall(
            pattern,
            text,
            re.S | re.I
        )

        executable = (

            "curl",

            "nuclei",

            "ffuf",

            "python",

            "python3",

            "sqlmap",

            "katana",

            "httpx",

            "subfinder",

            "wget",

            "nc",

            "openssl",

            "docker",

            "git",

            "graphql",

            "./",

            "go "

        )

        for block in blocks:

            for line in block.splitlines():

                line = line.strip()

                if not line:

                    continue

                if line.startswith("#"):

                    continue

                if line.startswith("//"):

                    continue

                if line.startswith("*"):

                    continue

                if line.startswith("###"):

                    continue

                if any(
                    line.startswith(x)
                    for x in executable
                ):

                    cmds.append(line)

        return cmds

