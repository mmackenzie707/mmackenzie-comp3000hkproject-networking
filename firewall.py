#!/usr/bin/env python3
import json
import sys
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.config import conf
import netifaces as ni

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/firewall/firewall.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class StaticFirewall:
    def __init__(self, rules_file):
        self.rules = self.load_rules(rules_file)
        self.stats = {'allowed': 0, 'blocked': 0, 'total': 0}
        self.local_ips = self.get_local_ips()
        
    def get_local_ips(self):
        """Get all local IP addresses"""
        ips = []
        for interface in ni.interfaces():
            try:
                ifaddrs = ni.ifaddresses(interface)
                if ni.AF_INET in ifaddrs:
                    for link in ifaddrs[ni.AF_INET]:
                        ips.append(link['addr'])
            except:
                continue
        return ips

    def load_rules(self, rules_file):
        """Load firewall rules from JSON file"""
        try:
            with open(rules_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load rules: {e}")
            sys.exit(1)
    
    def apply_rules(self, packet):
        """Apply firewall rules to packet"""
        if not packet.haslayer(IP):
            return True  # Allow non-IP packets by default
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # Block private IP spoofing (if not from local interfaces)
        if src_ip.startswith(('192.168.', '10.', '172.16.')) and src_ip not in self.local_ips:
            return False
        
        # Check IP rules
        if 'blocked_ips' in self.rules:
            if src_ip in self.rules['blocked_ips'] or dst_ip in self.rules['blocked_ips']:
                return False
        
        if 'allowed_ips' in self.rules:
            if src_ip not in self.rules['allowed_ips'] and dst_ip not in self.rules['allowed_ips']:
                return False
        
        # Check protocol rules
        if 'blocked_protocols' in self.rules:
            proto_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
            proto_name = proto_map.get(protocol, 'other')
            if proto_name in self.rules['blocked_protocols']:
                return False
        
        # Check port rules for TCP/UDP
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            sport = packet.sport if packet.haslayer(TCP) else packet[UDP].sport
            dport = packet.dport if packet.haslayer(TCP) else packet[UDP].dport
            
            if 'blocked_ports' in self.rules:
                if sport in self.rules['blocked_ports'] or dport in self.rules['blocked_ports']:
                    return False
        
        return True
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        self.stats['total'] += 1
        
        if self.apply_rules(packet):
            self.stats['allowed'] += 1
            action = "ALLOW"
        else:
            self.stats['blocked'] += 1
            action = "BLOCK"
        
        # Log packet details
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            protocol = proto_map.get(ip_layer.proto, 'OTHER')
            
            log_msg = f"{action} - {ip_layer.src}:{packet.sport if hasattr(packet, 'sport') else 'N/A'} -> {ip_layer.dst}:{packet.dport if hasattr(packet, 'dport') else 'N/A'} ({protocol})"
            logging.info(log_msg)
        
        # Print statistics every 100 packets
        if self.stats['total'] % 100 == 0:
            self.print_stats()
    
    def print_stats(self):
        """Print firewall statistics"""
        logging.info(f"--- Statistics --- Total: {self.stats['total']}, Allowed: {self.stats['allowed']}, Blocked: {self.stats['blocked']} ---")
    
    def start(self, interface=None):
        """Start the firewall"""
        logging.info(f"Starting firewall on interface: {interface or 'all'}")
        logging.info(f"Local IPs detected: {self.local_ips}")
        logging.info(f"Loaded {len(self.rules)} rule categories")
        
        try:
            sniff(
                iface=interface,
                prn=self.packet_handler,
                store=0,
                filter="ip"  # Capture only IP packets
            )
        except KeyboardInterrupt:
            logging.info("\nStopping firewall...")
            self.print_stats()
        except Exception as e:
            logging.error(f"Error: {e}")
            sys.exit(1)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Static Firewall Monitor')
    parser.add_argument('-r', '--rules', default='rules.json', help='Rules file path')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-t', '--test', action='store_true', help='Test mode (no actual blocking)')
    
    args = parser.parse_args()
    
    firewall = StaticFirewall(args.rules)
    firewall.start(args.interface)

if __name__ == '__main__':
    main()