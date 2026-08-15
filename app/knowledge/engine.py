from .database import KnowledgeDB
from .search import Search
from .viewer import Viewer


class KnowledgeEngine:

    def __init__(self):

        self.db = KnowledgeDB()

        self.search_engine = Search(self.db)

        self.viewer = Viewer(self.db)

    def search(self, query, limit=10):

        return self.search_engine.search(query, limit)

    def skill(self, skill_id):

        return self.viewer.open(skill_id)

    def random(self):

        self.db.cur.execute(
            """
            SELECT
                id,
                title,
                automation
            FROM skills
            ORDER BY RANDOM()
            LIMIT 1
            """
        )

        return dict(self.db.cur.fetchone())