from .graph import KnowledgeGraph
from .engine import KnowledgeEngine
from .compiler import KnowledgeCompiler
from .models import SkillList, Skill


class KnowledgePipeline:

    def __init__(self):

        self.graph = KnowledgeGraph()

        self.engine = KnowledgeEngine()

        self.compiler = KnowledgeCompiler()

    def run(self, evidence):

        result = SkillList()

        result.evidence = evidence

        result.expanded = self.graph.expand(evidence)

        seen = set()

        for concept in result.expanded:

            rows = self.engine.search(concept)

            for row in rows:

                if row["id"] in seen:
                    continue

                seen.add(row["id"])

                compiled = self.compiler.compile(
                    row["path"]
                )

                skill = Skill(

                    id=row["id"],

                    title=compiled["title"],

                    objective=compiled["objective"],

                    path=row["path"],

                    score=row["score"],

                    automation=row["automation"],

                    tools=compiled["tools"],

                    tags=compiled["tags"],

                    prerequisites=compiled["prerequisites"],

                    methodology=compiled["methodology"],

                    references=compiled["references"]

                )

                result.skills.append(skill)

        return result