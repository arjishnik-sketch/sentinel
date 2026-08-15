from app.knowledge.engine import KnowledgeEngine
from .mapper import expand


class EvidenceMatcher:

    def __init__(self):

        self.engine = KnowledgeEngine()

    def match(self, evidence):

        results = {}

        for keyword in evidence:

            matches = []

            seen = set()

            for term in expand(keyword):

                rows = self.engine.search(term, limit=5)

                for r in rows:

                    if r["id"] not in seen:

                        seen.add(r["id"])

                        matches.append(r)

                if len(matches) >= 5:
                    break

            results[keyword] = matches

        return results