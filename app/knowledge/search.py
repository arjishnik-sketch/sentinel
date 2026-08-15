class Search:

    def __init__(self, db):
        self.db = db

    def search(self, query, limit=10):

        q = query.lower().strip()

        self.db.cur.execute(
            """
            SELECT
                id,
                slug,
                title,
                description,
                automation,
                path
            FROM skills
            """
        )

        results = []

        for row in self.db.cur.fetchall():

            title = row["title"].lower()
            slug = row["slug"].lower()
            desc = (row["description"] or "").lower()

            score = 0
            matched = False

            # ---------- Exact ----------
            if title == q:
                score += 100
                matched = True

            # ---------- Starts With ----------
            elif title.startswith(q):
                score += 75
                matched = True

            # ---------- Contains ----------
            elif q in title:
                score += 50
                matched = True

            # ---------- Slug ----------
            elif slug.startswith(q):
                score += 40
                matched = True

            elif q in slug:
                score += 25
                matched = True

            # ---------- Description ----------
            elif q in desc:
                score += 10
                matched = True

            # -------------------------------------------------
            # IMPORTANT
            # Never return unrelated skills.
            # -------------------------------------------------

            if not matched:
                continue

            if row["automation"]:
                score += 5

            item = dict(row)
            item["score"] = score

            results.append(item)

        results.sort(
            key=lambda x: x["score"],
            reverse=True
        )

        return results[:limit]