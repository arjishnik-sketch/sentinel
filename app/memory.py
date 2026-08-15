from datetime import datetime, UTC
from pathlib import Path
import json
import sqlite3

try:
    from .config import logger
except Exception:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Sentinel")

DB = Path.home() / ".sentinel.db"

class Memory:
    def __init__(self):
        self.conn = sqlite3.connect(DB)
        self.conn.row_factory = sqlite3.Row
        self.cur = self.conn.cursor()
        self._init_db()

    @staticmethod
    def _now():
        return datetime.now(UTC).isoformat()

    def _init_db(self):
        self.cur.executescript('''
CREATE TABLE IF NOT EXISTS targets(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 domain TEXT UNIQUE NOT NULL,
 created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 target_id INTEGER NOT NULL,
 summary TEXT,
 data TEXT,
 created TEXT NOT NULL,
 FOREIGN KEY(target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS notes(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 target_id INTEGER NOT NULL,
 note TEXT NOT NULL,
 created TEXT NOT NULL,
 FOREIGN KEY(target_id) REFERENCES targets(id)
);
''')
        self.conn.commit()

    def _target_id(self, domain):
        self.cur.execute('SELECT id FROM targets WHERE domain=?',(domain,))
        row=self.cur.fetchone()
        if row:
            return row['id']
        self.cur.execute('INSERT INTO targets(domain,created) VALUES(?,?)',(domain,self._now()))
        self.conn.commit()
        return self.cur.lastrowid

    def save_scan(self,domain,summary,data):
        tid=self._target_id(domain)
        self.cur.execute('INSERT INTO scans(target_id,summary,data,created) VALUES(?,?,?,?)',
                         (tid,summary,json.dumps(data),self._now()))
        self.conn.commit()
        logger.info('Saved scan for %s',domain)

    def latest(self,domain):
        self.cur.execute('''SELECT scans.summary,scans.data,scans.created
FROM scans JOIN targets ON scans.target_id=targets.id
WHERE targets.domain=?
ORDER BY scans.id DESC LIMIT 1''',(domain,))
        row=self.cur.fetchone()
        if not row:
            return None
        return {'summary':row['summary'],'data':json.loads(row['data']),'created':row['created']}

    def history(self):
        self.cur.execute('''SELECT targets.domain AS domain,
COUNT(scans.id) AS total,
MAX(scans.created) AS latest
FROM targets
LEFT JOIN scans ON scans.target_id=targets.id
GROUP BY targets.id
ORDER BY latest DESC''')
        return [dict(r) for r in self.cur.fetchall()]

    def add_note(self,domain,note):
        tid=self._target_id(domain)
        self.cur.execute('INSERT INTO notes(target_id,note,created) VALUES(?,?,?)',
                         (tid,note,self._now()))
        self.conn.commit()

    def notes(self,domain):
        self.cur.execute('''SELECT notes.note,notes.created
FROM notes JOIN targets ON notes.target_id=targets.id
WHERE targets.domain=?
ORDER BY notes.id DESC''',(domain,))
        return [dict(r) for r in self.cur.fetchall()]

    def stats(self):
        out={}
        for t in ('targets','scans','notes'):
            self.cur.execute(f'SELECT COUNT(*) FROM {t}')
            out[t]=self.cur.fetchone()[0]
        return out

if __name__=='__main__':
    m=Memory()
    m.save_scan('meta.com','Pipeline successful',{'alive':92,'crawl':119})
    m.add_note('meta.com','Need to fuzz GraphQL')
    print('\nLATEST')
    print(m.latest('meta.com'))
    print('\nHISTORY')
    print(m.history())
    print('\nNOTES')
    print(m.notes('meta.com'))
    print('\nSTATS')
    print(m.stats())
