class KnowledgeRanker:

    def score(self, skill, evidence):

        score = 0

        title = skill.title.lower()

        objective = skill.objective.lower()

        text = title + " " + objective

        for item in evidence:

            if item.lower() in text:

                score += 30

        score += skill.score

        score += skill.automation * 10

        score += len(skill.tools) * 2

        score += len(skill.tags)

        skill.priority = score

        return score

    def rank(self, skills, evidence):

        for s in skills:

            self.score(s, evidence)

        skills.sort(

            key=lambda x: x.priority,

            reverse=True

        )

        return skills