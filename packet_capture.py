from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import time
import threading

def process_packet(packet):
    """Extract features from network packet"""
    if IP in packet:
        try:
            with sqlite3.connect('/app/logs/traffic.db') as conn:
                protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
                conn.execute('''
                    INSERT INTO packet_logs (timestamp, src_ip, dst_ip, protocol, port, packet_size, flags)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    time.time(),
                    packet[IP].src,
                    packet[IP].dst,
                    protocol,
                    packet[IP].dport if hasattr(packet[IP], 'dport') else 0,
                    len(packet),
                    str(packet.flags) if hasattr(packet, 'flags') else ''
                ))
        except Exception as e:
            print(f"Packet logging error: {e}")

def start_packet_sniffer(interface=None, filter_str="port 80 or port 443"):
    """Start packet capture in background thread"""
    def sniffer():
        sniff(iface=interface, filter=filter_str, prn=process_packet, store=0)
    
    thread = threading.Thread(target=sniffer, daemon=True)
    thread.start()