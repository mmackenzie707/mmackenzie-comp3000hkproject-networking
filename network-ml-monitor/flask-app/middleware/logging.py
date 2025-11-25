import sqlite3
import time
import json
from flask import request, g

def init_db(db_path):
    with sqlite3.connect(db_path) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS api_logs (
                timestamp REAL, ip TEXT, method TEXT, endpoint TEXT,
                user_agent TEXT, headers TEXT, body_size INTEGER,
                response_time REAL, status_code INTEGER
            )
        ''')

def log_middleware(app):
    @app.before_request
    def start_timer():
        g.start_time = time.time()

    @app.after_request
    def log(response):
        try:
            with sqlite3.connect('/app/logs/traffic.db') as conn:
                conn.execute('''
                    INSERT INTO api_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    time.time(), request.remote_addr, request.method,
                    request.path, request.headers.get('User-Agent'),
                    json.dumps(dict(request.headers)),
                    request.content_length or 0,
                    time.time() - g.start_time,
                    response.status_code
                ))
        except Exception:
            pass
        return response