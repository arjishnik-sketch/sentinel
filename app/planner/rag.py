from app.evidence.extractor import EvidenceExtractor
from app.evidence.matcher import EvidenceMatcher

from app.knowledge.graph import KnowledgeGraph


class RAGPlanner:

    MIN_SCORE = 25

    def __init__(self):

        self.extractor = EvidenceExtractor()

        self.matcher = EvidenceMatcher()

        self.graph = KnowledgeGraph()

    def analyze(self, recon):

        evidence = self.extractor.extract(recon)

        expanded = self.graph.expand(evidence)

        merged = {}

        for keyword in expanded:

            matches = self.matcher.match([keyword])

            for category, skills in matches.items():

                merged.setdefault(category, [])

                merged[category].extend(skills)

        filtered = {}

        for category, rows in merged.items():

            unique = {}

            for r in rows:

                unique[r["id"]] = r

            rows = list(unique.values())

            rows.sort(

                key=lambda x: x.get("score", 0),

                reverse=True

            )

            rows = [

                r

                for r in rows

                if r.get("score", 0) >= self.MIN_SCORE

            ]

            if rows:

                filtered[category] = rows

        return {

            "evidence": evidence,

            "expanded": expanded,

            "skills": filtered

        }