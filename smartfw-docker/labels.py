import sqlite3, ipaddress, time
from pathlib import Path

DB = Path("/var/log/smartfw_labels.db")

def init_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS labels(
                ip  TEXT PRIMARY KEY,
                label INTEGER NOT NULL,   -- 1 = bad, 0 = good
                ts  REAL NOT NULL
            );
        """)

def label_ip(ip: str, is_bad: bool):
    with sqlite3.connect(DB) as con:
        con.execute(
            "INSERT OR REPLACE INTO labels(ip,label,ts) VALUES(?,?,?)",
            (ip, 1 if is_bad else 0, time.time())
        )