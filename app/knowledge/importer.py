from pathlib import Path
import re

from .database import KnowledgeDB

DEFAULT_SKILLS = Path("/mnt/d/downloads backup/Anthropic-Cybersecurity-Skills/skills")


class Importer:
    def __init__(self, db=None):
        self.db = db or KnowledgeDB()

    def import_skills(self, root=DEFAULT_SKILLS):

        root = Path(root)

        if not root.exists():
            raise FileNotFoundError(root)

        imported = 0
        automation = 0
        skipped = 0

        for md in root.rglob("SKILL.md"):

            try:

                slug = md.parent.name

                text = md.read_text(
                    encoding="utf-8",
                    errors="ignore"
                )

                title = slug.replace("-", " ").title()

                m = re.search(r"^#\s+(.+)$", text, re.MULTILINE)

                if m:
                    title = m.group(1).strip()

                desc = ""

                for line in text.splitlines():

                    line = line.strip()

                    if (
                        line
                        and not line.startswith("#")
                        and len(line) > 20
                    ):
                        desc = line
                        break

                has_script = (
                    md.parent /
                    "scripts" /
                    "agent.py"
                ).exists()

                if has_script:
                    automation += 1

                self.db.cur.execute(
                    """
                    INSERT OR REPLACE INTO skills
                    (
                        slug,
                        title,
                        description,
                        tags,
                        path,
                        automation
                    )
                    VALUES
                    (
                        ?,?,?,?,?,?
                    )
                    """,
                    (
                        slug,
                        title,
                        desc,
                        "",
                        str(md),
                        int(has_script)
                    )
                )

                imported += 1

            except Exception:

                skipped += 1

        self.db.conn.commit()

        print(f"Imported : {imported}")
        print(f"Automation : {automation}")
        print(f"Skipped : {skipped}")


if __name__ == "__main__":

    Importer().import_skills()