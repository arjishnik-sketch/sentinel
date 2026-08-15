from .interpreter import KnowledgeInterpreter


class KnowledgeCompiler:

    def __init__(self):

        self.interpreter = KnowledgeInterpreter()

    def compile(self, path):

        skill = self.interpreter.interpret(path)

        return {

            "title": skill["title"],

            "objective": skill["objective"],

            "tools": skill["tools"],

            "tags": self.tags(skill),

            "prerequisites": self.prerequisites(skill),

            "methodology": self.methodology(skill),

            "references": skill["references"],

            "automation": self.automation(skill),

            "confidence": 0
        }

    def tags(self, skill):

        tags = []

        for step in skill["steps"]:

            s = step.lower()

            if len(s.split()) <= 3:

                tags.append(s)

        return sorted(set(tags))

    def prerequisites(self, skill):

        items = []

        keywords = (

            "require",

            "target",

            "authorization",

            "python",

            "burp",

            "endpoint",

            "access"

        )

        for step in skill["steps"]:

            lower = step.lower()

            if any(k in lower for k in keywords):

                items.append(step)

        return items

    def methodology(self, skill):

        items = []

        verbs = (

            "send",

            "generate",

            "increase",

            "observe",

            "repeat",

            "identify",

            "measure",

            "verify",

            "check",

            "attempt",

            "retrieve",

            "enumerate",

            "test"

        )

        for step in skill["steps"]:

            lower = step.lower()

            if any(lower.startswith(v) for v in verbs):

                items.append(step)

        return items

    def automation(self, skill):

        score = 0

        if "curl" in skill["tools"]:
            score += 20

        if "python" in skill["tools"]:
            score += 20

        if "graphql" in skill["tools"]:
            score += 20

        if len(skill["references"]) > 2:
            score += 20

        if len(skill["steps"]) > 5:
            score += 20

        return min(score, 100)