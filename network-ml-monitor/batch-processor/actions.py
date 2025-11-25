import sqlite3
import time
import os

def init_alerts_table(db_path="/app/logs/traffic.db"):
    """Initialize the security_alerts table if it doesn't exist"""
    with sqlite3.connect(db_path) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                timestamp REAL, 
                ip TEXT, 
                risk_score REAL, 
                is_bot BOOLEAN, 
                action TEXT, 
                confidence REAL
            )
        ''')

def log_alert(ip: str, risk_score: float, is_bot: bool, confidence: float = 0.0):
    """Log security alert to database"""
    # Ensure table exists before inserting
    init_alerts_table()
    with sqlite3.connect("/app/logs/traffic.db") as conn:
        conn.execute('''
            INSERT INTO security_alerts (timestamp, ip, risk_score, is_bot, action, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (time.time(), ip, risk_score, is_bot, "LOG", confidence))

def block_ip(ip: str, reason: str):
    """Add IP to blocklist"""
    os.makedirs("/app/config", exist_ok=True)
    with open("/app/config/blocklist.txt", 'a') as f:
        f.write(f"{ip} # {reason} - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

def rate_limit_ip(ip: str):
    """Mark IP for rate limiting"""
    print(f"Rate limiting IP: {ip}")