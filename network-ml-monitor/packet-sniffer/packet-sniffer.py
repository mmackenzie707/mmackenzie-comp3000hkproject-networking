import sqlite3
import time
import sys
import os
import threading
from scapy.all import sniff, IP, TCP, UDP, get_if_list

DB_PATH = "/app/logs/traffic.db"
INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")
CAPTURE_FILTER = "tcp port 80 or tcp port 443 or tcp port 8080 or tcp port 8000"

def init_db():
    """Initialize database for packet logs"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS packet_logs (
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    port INTEGER,
                    packet_size INTEGER,
                    flags TEXT
                )
            ''')
        print(f"✓ Database initialized at {DB_PATH}")
    except Exception as e:
        print(f"✗ Database error: {e}")
        sys.exit(1)

def get_available_interfaces():
    """List all available network interfaces"""
    try:
        interfaces = get_if_list()
        print(f"Available interfaces: {interfaces}")
        return interfaces
    except Exception as e:
        print(f"✗ Could not list interfaces: {e}")
        return []

def process_packet(packet):
    """Log a single packet to database"""
    if IP not in packet:
        return
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            
            # Get destination port
            port = 0
            if TCP in packet:
                port = packet[TCP].dport
            elif UDP in packet:
                port = packet[UDP].dport
            
            # Insert packet data
            conn.execute('''
                INSERT INTO packet_logs VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
                packet[IP].src,
                packet[IP].dst,
                protocol,
                port,
                len(packet),
                str(packet.flags) if hasattr(packet, 'flags') else ''
            ))
    except Exception as e:
        print(f"Packet logging error: {e}")

def capture_loop():
    """Main capture loop with retry logic"""
    retry_count = 0
    max_retries = 10
    
    while retry_count < max_retries:
        try:
            print(f"\n🔍 Starting packet capture on {INTERFACE}")
            print(f"Filter: {CAPTURE_FILTER}")
            
            sniff(
                iface=INTERFACE,
                prn=process_packet,
                store=0,
                filter=CAPTURE_FILTER
            )
            
        except KeyboardInterrupt:
            print("\n✓ User stopped capture")
            return
        except Exception as e:
            retry_count += 1
            print(f"\n✗ Capture error (attempt {retry_count}/{max_retries}): {e}")
            print("Will retry in 5 seconds...")
            time.sleep(5)
    
    print("\n✗ Max retries reached. Exiting.")
    sys.exit(1)

def health_check():
    """Background thread for health checking"""
    while True:
        try:
            # Log packet count every 30 seconds
            with sqlite3.connect(DB_PATH) as conn:
                count = conn.execute("SELECT COUNT(*) FROM packet_logs WHERE timestamp > ?", (time.time() - 30,)).fetchone()[0]
                print(f"📊 Captured {count} packets in last 30 seconds")
        except Exception as e:
            print(f"Health check error: {e}")
        time.sleep(30)

if __name__ == '__main__':
    print("Starting Real Traffic Packet Sniffer")
    print("=" * 50)
    
    init_db()
    get_available_interfaces()
    
    # Start health check thread
    health_thread = threading.Thread(target=health_check, daemon=True)
    health_thread.start()
    
    # Start capture
    capture_loop()