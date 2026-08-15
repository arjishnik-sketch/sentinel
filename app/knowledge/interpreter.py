from pathlib import Path
import re


class KnowledgeInterpreter:

    def interpret(self, path):

        path = Path(path)

        text = path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

        return {

            "title": self.title(text),

            "objective": self.objective(text),

            "tools": self.tools(text),

            "steps": self.steps(text),

            "references": self.references(text),

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

    def objective(self, text):

        lines = []

        started = False

        for line in text.splitlines():

            line = line.strip()

            if line.startswith("# "):
                continue

            if line.startswith("##"):

                if started:
                    break

                continue

            if line:

                started = True

                lines.append(line)

            if len(lines) >= 6:
                break

        return " ".join(lines)

    def tools(self, text):

        known = {

            "curl",

            "ffuf",

            "nuclei",

            "sqlmap",

            "katana",

            "httpx",

            "subfinder",

            "burp",

            "postman",

            "graphql",

            "python",

            "docker",

            "git",

            "jwt"

        }

        found = []

        lower = text.lower()

        for tool in sorted(known):

            if tool in lower:

                found.append(tool)

        return found

    def steps(self, text):

        steps = []

        for line in text.splitlines():

            line = line.strip()

            if re.match(r"^\d+\.", line):

                steps.append(line)

            elif line.startswith("- "):

                steps.append(line[2:])

        return steps[:25]

    def references(self, text):

        refs = []

        for line in text.splitlines():

            if "http://" in line or "https://" in line:

                refs.append(line.strip())

        return refs