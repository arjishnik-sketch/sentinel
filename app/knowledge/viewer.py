from pathlib import Path


class Viewer:

    def __init__(self, db):
        self.db = db

    def open(self, skill_id):

        self.db.cur.execute(
            """
            SELECT path
            FROM skills
            WHERE id=?
            """,
            (skill_id,),
        )

        row = self.db.cur.fetchone()

        if not row:
            return None

        return Path(row["path"]).read_text(
            encoding="utf-8",
            errors="ignore",
        )