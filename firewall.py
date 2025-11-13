#!/usr/bin/env python3
import json
import sys
import logging
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import psutil

# Check if running as root
IS_ROOT = os.geteuid() == 0

def setup_logging():
    """Configure logging with separate files for allowed and blocked traffic"""
    log_dir = "/var/log/firewall" if IS_ROOT else "/app/logs"
    
    try:
        os.makedirs(log_dir, exist_ok=True)
        test_file = os.path.join(log_dir, ".write_test")
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
    except (PermissionError, OSError) as e:
        log_dir = "/tmp/firewall"
        os.makedirs(log_dir, exist_ok=True)
        print(f"Warning: Using fallback log directory {log_dir}")
    
    return log_dir

LOG_DIR = setup_logging()

# Create separate loggers
allowed_logger = logging.getLogger("firewall.allowed")
blocked_logger = logging.getLogger("firewall.blocked")
console_logger = logging.getLogger("firewall.console")

# Prevent log propagation to avoid duplicates
allowed_logger.propagate = False
blocked_logger.propagate = False
console_logger.propagate = False

# Set up formatter
formatter = logging.Formatter('%(asctime)s - %(message)s')

# Allowed traffic log file
allowed_handler = logging.FileHandler(f"{LOG_DIR}/allowed.log")
allowed_handler.setFormatter(formatter)
allowed_logger.addHandler(allowed_handler)
allowed_logger.setLevel(logging.INFO)

# Blocked traffic log file
blocked_handler = logging.FileHandler(f"{LOG_DIR}/blocked.log")
blocked_handler.setFormatter(formatter)
blocked_logger.addHandler(blocked_handler)
blocked_logger.setLevel(logging.INFO)

# Console output
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
console_logger.addHandler(console_handler)
console_logger.setLevel(logging.INFO)

class StaticFirewall:
    def __init__(self, rules_file):
        self.rules = self.load_rules(rules_file)
        self.stats = {'allowed': 0, 'blocked': 0, 'total': 0}
        self.local_ips = self.get_local_ips()
        self.is_rootless = not IS_ROOT
        if self.is_rootless:
            console_logger.warning("Running in rootless mode. Network visibility may be limited.")
        
    def get_local_ips(self):
        """Get all local IP addresses using psutil"""
        ips = []
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == 2:  # AF_INET (IPv4)
                        ips.append(addr.address)
        except Exception as e:
            console_logger.warning(f"Could not detect interfaces: {e}")
        return ips

    def load_rules(self, rules_file):
        """Load firewall rules from JSON file"""
        try:
            with open(rules_file, 'r') as f:
                rules = json.load(f)
            console_logger.info(f"Loaded rules from {rules_file}")
            return rules
        except Exception as e:
            console_logger.error(f"Failed to load rules: {e}")
            sys.exit(1)
    
    def apply_rules(self, packet):
        """Apply firewall rules to packet"""
        if not packet.haslayer(IP):
            return True
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # Block private IP spoofing
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
        
        # Check port rules
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            sport = packet.sport if packet.haslayer(TCP) else packet[UDP].sport
            dport = packet.dport if packet.haslayer(TCP) else packet[UDP].dport
            
            if 'blocked_ports' in self.rules:
                if sport in self.rules['blocked_ports'] or dport in self.rules['blocked_ports']:
                    return False
        
        return True
    
    def packet_handler(self, packet):
        """Handle captured packets and log to separate files"""
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
            
            sport = getattr(packet, 'sport', 'N/A')
            dport = getattr(packet, 'dport', 'N/A')
            
            log_msg = f"{action} - {ip_layer.src}:{sport} -> {ip_layer.dst}:{dport} ({protocol})"
            
            # Log to appropriate files and console
            if action == "ALLOW":
                allowed_logger.info(log_msg)
            else:
                blocked_logger.info(log_msg)
            console_logger.info(log_msg)
        
        # Print statistics every 100 packets
        if self.stats['total'] % 100 == 0:
            self.print_stats()
    
    def print_stats(self):
        """Print firewall statistics"""
        stats_msg = f"--- Statistics --- Total: {self.stats['total']}, Allowed: {self.stats['allowed']}, Blocked: {self.stats['blocked']} ---"
        console_logger.info(stats_msg)
    
    def start(self, interface=None):
        """Start the firewall"""
        console_logger.info(f"Starting firewall on interface: {interface or 'all'}")
        console_logger.info(f"Local IPs detected: {self.local_ips}")
        console_logger.info(f"Loaded {len(self.rules)} rule categories")
        console_logger.info(f"Mode: {'Rootful' if IS_ROOT else 'Rootless'}")
        console_logger.info(f"Logging to: {LOG_DIR}")
        console_logger.info(f"Allowed log: {LOG_DIR}/allowed.log")
        console_logger.info(f"Blocked log: {LOG_DIR}/blocked.log")
        
        if self.is_rootless:
            console_logger.info("Rootless mode: Monitoring container's network namespace only")
        
        try:
            sniff(
                iface=interface,
                prn=self.packet_handler,
                store=0,
                filter="ip",
                promisc=IS_ROOT
            )
        except KeyboardInterrupt:
            console_logger.info("\nStopping firewall...")
            self.print_stats()
        except PermissionError as e:
            console_logger.error(f"Permission denied: {e}")
            console_logger.error("Try running with sudo for full network access")
            sys.exit(1)
        except Exception as e:
            console_logger.error(f"Error: {e}")
            sys.exit(1)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Static Firewall Monitor (Dual Logging)')
    parser.add_argument('-r', '--rules', default='rules.json', help='Rules file path')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    
    args = parser.parse_args()
    
    firewall = StaticFirewall(args.rules)
    firewall.start(args.interface)

if __name__ == '__main__':
    main()