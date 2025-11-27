# batch-processor/main.py
import sqlite3
import time
import os
import subprocess
import logging

# Configure separate log for blocked IPs
logging.basicConfig(
    filename='/app/logs/blocked_ips.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Database for blocked IPs
BLOCKED_DB_PATH = "/app/logs/blocked_ips.db"

def init_blocked_db():
    """Initialize database for blocked IPs"""
    os.makedirs(os.path.dirname(BLOCKED_DB_PATH), exist_ok=True)
    with sqlite3.connect(BLOCKED_DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                confidence REAL,
                first_detected REAL,
                last_seen REAL,
                blocked_count INTEGER DEFAULT 1,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                threat_type TEXT,
                confidence REAL,
                timestamp REAL,
                packet_data TEXT
            )
        ''')
    print(f"✓ Blocked IPs database initialized at {BLOCKED_DB_PATH}")

def get_ml_threat_analysis(packet):
    """Call ML service for threat detection"""
    try:
        # Simulate ML analysis (in real setup, make HTTP call to ml-service)
        # For demo, we'll use simple heuristics
        threat_score = 0
        
        # High rate detection
        if packet['rate_per_minute'] > 200:
            threat_score += 0.3
        
        # Failed login patterns
        if packet['src_ip'].startswith('192.168.') and time.time() % 10 < 2:
            threat_score += 0.4
        
        # Bot patterns
        if 'bot' in str(packet).lower():
            threat_score += 0.3
        
        return threat_score > 0.5, threat_score, "ML-based pattern detection"
    except Exception as e:
        logging.error(f"ML analysis failed: {e}")
        return False, 0.0, "Analysis failed"

def add_iptables_rule(ip_address):
    """Block IP using iptables - requires root"""
    try:
        # Check if already blocked
        check_cmd = f"iptables -C INPUT -s {ip_address} -j DROP 2>/dev/null"
        result = subprocess.run(check_cmd, shell=True, capture_output=True)
        
        if result.returncode != 0:  # Not blocked yet
            cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            logging.info(f"IP {ip_address} blocked via iptables")
            print(f"🔒 Blocked IP: {ip_address}")
            return True
        return False
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip_address}: {e}")
        print(f"✗ Failed to block {ip_address}: {e}")
        return False

def remove_iptables_rule(ip_address):
    """Unblock IP using iptables"""
    try:
        cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
        logging.info(f"IP {ip_address} unblocked via iptables")
        print(f"🔓 Unblocked IP: {ip_address}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to unblock IP {ip_address}: {e}")
        return False

def block_ip(ip_address, reason, confidence):
    """Block IP and log to database"""
    with sqlite3.connect(BLOCKED_DB_PATH) as conn:
        # Check if IP already exists
        existing = conn.execute("SELECT id, blocked_count FROM blocked_ips WHERE ip_address = ?", 
                               (ip_address,)).fetchone()
        
        if existing:
            # Update existing record
            conn.execute("""
                UPDATE blocked_ips 
                SET last_seen = ?, blocked_count = ?, is_active = 1 
                WHERE ip_address = ?
            """, (time.time(), existing[1] + 1, ip_address))
            print(f"🔄 Updated block for {ip_address} (count: {existing[1] + 1})")
        else:
            # Insert new record
            conn.execute("""
                INSERT INTO blocked_ips (ip_address, reason, confidence, first_detected, last_seen) 
                VALUES (?, ?, ?, ?, ?)
            """, (ip_address, reason, confidence, time.time(), time.time()))
            
            # Add iptables rule
            if add_iptables_rule(ip_address):
                logging.warning(f"BLOCKED: {ip_address} | Reason: {reason} | Confidence: {confidence:.2f}")
                print(f"🚨 NEW THREAT BLOCKED: {ip_address}")

def analyze_recent_packets():
    """Analyze recent packets for threats"""
    with sqlite3.connect('/app/logs/traffic.db') as conn:
        # Get packets from last 2 minutes
        cursor = conn.execute("""
            SELECT src_ip, dst_ip, port, packet_size, COUNT(*) as count,
                   AVG(timestamp) as avg_time, GROUP_CONCAT(timestamp) as times
            FROM packet_logs 
            WHERE timestamp > ? 
            GROUP BY src_ip, dst_ip, port
            ORDER BY count DESC
            LIMIT 50
        """, (time.time() - 120,))
        
        packets = cursor.fetchall()
    
    threats_found = 0
    
    for packet in packets:
        src_ip, dst_ip, port, pkt_size, request_count, avg_time, times = packet
        
        # Calculate rate
        rate_per_minute = request_count * (60 / max(1, time.time() - float(times.split(',')[0])))
        
        packet_data = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port': port or 0,
            'packet_size': pkt_size or 0,
            'rate_per_minute': rate_per_minute,
            'failed_logins': 1 if 'bot' in src_ip.lower() else 0,
            'bot_patterns': 'bot' in str(packet).lower()
        }
        
        # Run ML analysis
        is_malicious, confidence, reason = get_ml_threat_analysis(packet_data)
        
        if is_malicious and confidence > 0.6:
            block_ip(src_ip, f"ML: {reason}", confidence)
            threats_found += 1
            
            # Log threat event
            with sqlite3.connect(BLOCKED_DB_PATH) as conn:
                conn.execute("""
                    INSERT INTO threat_events (ip_address, threat_type, confidence, timestamp, packet_data) 
                    VALUES (?, ?, ?, ?, ?)
                """, (src_ip, reason, confidence, time.time(), str(packet_data)))
    
    if threats_found > 0:
        print(f"🎯 Batch analysis complete: {threats_found} threats blocked")
    else:
        print(f"✅ Batch analysis complete: No threats detected")

def list_blocked_ips():
    """Show currently blocked IPs"""
    with sqlite3.connect(BLOCKED_DB_PATH) as conn:
        cursor = conn.execute("""
            SELECT ip_address, reason, confidence, blocked_count, 
                   datetime(first_detected, 'unixepoch') as first_seen
            FROM blocked_ips 
            WHERE is_active = 1 
            ORDER BY last_seen DESC
        """)
        
        blocked = cursor.fetchall()
        
    if blocked:
        print("\n🔒 Currently Blocked IPs:")
        for ip in blocked:
            print(f"  {ip[0]} | {ip[1]} | Confidence: {ip[2]:.2f} | Count: {ip[3]} | First: {ip[4]}")
    else:
        print("\n✅ No IPs currently blocked")

def main():
    """Main monitoring loop"""
    print("🚀 Starting ML Threat Detection & IP Blocking Service")
    print("=" * 60)
    init_blocked_db()
    
    try:
        while True:
            print(f"\n[{time.strftime('%H:%M:%S')}] Running threat analysis...")
            analyze_recent_packets()
            list_blocked_ips()
            
            # Sleep for 30 seconds between analyses
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n👋 Shutting down threat detection service")
        # Optionally unblock all IPs on shutdown
        # unblock_all_ips()

if __name__ == '__main__':
    main()