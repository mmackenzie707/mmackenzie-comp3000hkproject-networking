import time
import sqlite3
from flask import request, g
import json

def init_logging_db(app, db_path='/app/logs/traffic.db'):
    """Initialize SQLite DB for log storage"""
    with sqlite3.connect(db_path) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS api_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                ip TEXT,
                method TEXT,
                endpoint TEXT,
                user_agent TEXT,
                headers TEXT,
                body_size INTEGER,
                response_time REAL,
                status_code INTEGER,
                FOREIGN KEY (ip) REFERENCES ip_reputation(ip)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS packet_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                port INTEGER,
                packet_size INTEGER,
                flags TEXT
            )
        ''')

def log_request_middleware(app):
    @app.before_request
    def start_timer():
        g.start_time = time.time()

    @app.after_request
    def log_request(response):
        try:
            with sqlite3.connect('/app/logs/traffic.db') as conn:
                conn.execute('''
                    INSERT INTO api_logs (timestamp, ip, method, endpoint, user_agent, 
                                         headers, body_size, response_time, status_code)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    time.time(),
                    request.remote_addr,
                    request.method,
                    request.path,
                    request.headers.get('User-Agent', ''),
                    json.dumps(dict(request.headers)),
                    request.content_length or 0,
                    time.time() - g.start_time,
                    response.status_code
                ))
        except Exception as e:
            app.logger.error(f"Logging failed: {e}")
        return response