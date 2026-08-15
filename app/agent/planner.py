from app.knowledge.ranker import KnowledgeRanker


class AgentPlanner:

    def __init__(self):

        self.ranker = KnowledgeRanker()

    def choose(self, state):

        ranked = self.ranker.rank(

            state.skills,

            state.evidence

        )

        state.skills = ranked

        return ranked[:5]