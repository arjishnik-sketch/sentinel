from pathlib import Path
import sqlite3

ROOT = Path("knowledge")
ROOT.mkdir(exist_ok=True)

DB = ROOT / "knowledge.db"


class KnowledgeDB:

    def __init__(self):
        self.conn = sqlite3.connect(DB)
        self.conn.row_factory = sqlite3.Row
        self.cur = self.conn.cursor()
        self._create()

    def _create(self):

        self.cur.execute("""
        CREATE TABLE IF NOT EXISTS skills(

            id INTEGER PRIMARY KEY,

            slug TEXT UNIQUE,

            title TEXT,

            description TEXT,

            tags TEXT,

            path TEXT,

            automation INTEGER DEFAULT 0

        )
        """)

        self.cur.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS skills_fts
        USING fts5(
            title,
            description,
            tags,
            content='skills',
            content_rowid='id'
        )
        """)

        self.conn.commit()