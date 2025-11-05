import sqlite3, bcrypt, os
from pathlib import Path

DB = Path("/usr/share/nginx/html/users.db")
SECRET_KEY = os.getenv("SECRET KEY") or os.urandom(32).hex()

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id       INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                pw_hash  TEXT NOT NULL
            );
        """)
        if not con.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            add_user("admin", "admin123")

def add_user(username: str, password: str):
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with sqlite3.connect(DB) as con:
        con.execute("INSERT INTO users(username, pw_hash) VALUES(?,?)", (username, pw_hash))

def verify_user(username: str, password: str) -> bool:
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT pw_hash FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            return False
        return bcrypt.checkpw(password.encode(), row[0].encode())