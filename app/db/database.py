import sqlite3
from pathlib import Path

DB = Path.home() / ".sentinel.db"

conn = sqlite3.connect(DB)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS scans(
id INTEGER PRIMARY KEY AUTOINCREMENT,
target TEXT,
summary TEXT,
data TEXT,
created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
