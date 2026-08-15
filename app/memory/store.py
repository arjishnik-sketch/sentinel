import sqlite3
from pathlib import Path

DB = Path.home()/".sentinel.db"

def save(target,summary,data):
    conn=sqlite3.connect(DB)
    cur=conn.cursor()
    cur.execute(
        "INSERT INTO scans(target,summary,data) VALUES(?,?,?)",
        (target,summary,data)
    )
    conn.commit()
    conn.close()

def latest(target):
    conn=sqlite3.connect(DB)
    cur=conn.cursor()

    cur.execute(
        "SELECT summary,data,created FROM scans WHERE target=? ORDER BY id DESC LIMIT 1",
        (target,)
    )

    row=cur.fetchone()
    conn.close()

    return row
