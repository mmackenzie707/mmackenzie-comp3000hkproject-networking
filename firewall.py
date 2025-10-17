import os
import sys
import logging
import iptc
import time
import threading
from datetime import datetime
import config

# Check if running as root (required for iptables)
if os.geteuid() != 0:
    print("This script must be run as root. Try using sudo.")
    sys.exit(1)

# Set up logging
if config.LOG_ENABLED:
    logging.basicConfig(
        filename=config.LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

# Alert level mapping
alert_levels = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

# Set alert level
alert_level = alert_levels.get(config.ALERT_LEVEL, logging.INFO)

# Dictionary to store attack counts
attack_counters = {
    'icmp_flood': 0,
    'syn_flood': 0,
    'port_scan': 0
}

# Lock for thread safety
counter_lock = threading.Lock()

def display_alert(message, level=logging.INFO):
    """Display alert on screen and log it"""
    if config.ALERT_ENABLED and level >= alert_level:
        # Format the alert message
        alert_type = logging.getLevelName(level)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {alert_type}: {message}"
        
        # Print to console
        if level >= logging.WARNING:
            print("\033[91m" + formatted_message + "\033[0m")  # Red for warnings and above
        elif level == logging.INFO:
            print("\033[93m" + formatted_message + "\033[0m")  # Yellow for info
        else:
            print(formatted_message)
        
        logging.log(level, message)

def clear_iptables():
    """Clear all existing iptables rules"""
    logging.info("Clearing existing iptables rules")
    display_alert("Clearing existing iptables rules")
    
    # Clear filter table
    for table_name in ['filter']:
        table = iptc.Table(table_name)
        for chain in table.chains:
            chain.flush()
            if chain.name not in ['INPUT', 'FORWARD', 'OUTPUT']:
                chain.delete()
    
    # Set default policies
    for chain_name in ['INPUT', 'FORWARD', 'OUTPUT']:
        chain = iptc.Chain(iptc.Table('filter'), chain_name)
        chain.set_policy('ACCEPT')
    
    logging.info("All iptables rules cleared")
    display_alert("All iptables rules cleared")

def configure_firewall():
    """Configure firewall based on settings in config.py"""
    logging.info("Configuring firewall rules")
    display_alert("Configuring firewall rules")
    
    # Access the filter table
    table = iptc.Table('filter')
    
    # Set default policies
    input_chain = iptc.Chain(table, 'INPUT')
    input_chain.set_policy(config.DEFAULT_POLICY)
    
    # Allow loopback traffic
    rule = iptc.Rule()
    rule.in_interface = 'lo'
    rule.target = iptc.Target(rule, 'ACCEPT')
    input_chain.insert_rule(rule)
    
    # Allow established connections
    rule = iptc.Rule()
    match = iptc.Match(rule, 'state')
    match.state = 'RELATED,ESTABLISHED'
    rule.add_match(match)
    rule.target = iptc.Target(rule, 'ACCEPT')
    input_chain.insert_rule(rule)
    
    # Allow specific IPs
    for ip in config.ALLOWED_IPs:
        rule = iptc.Rule()
        rule.src = ip
        rule.target = iptc.Target(rule, 'ACCEPT')
        input_chain.insert_rule(rule)
        logging.info(f"Allowing connections from IP: {ip}")
        display_alert(f"Allowing connections from IP: {ip}")
    
    # Allow specific services
    for service in config.ALLOWED_SERVICES:
        rule = iptc.Rule()
        rule.protocol = service['protocol']
        match = iptc.Match(rule, service['protocol'])
        match.dport = str(service['port'])
        rule.add_match(match)
        rule.target = iptc.Target(rule, 'ACCEPT')
        input_chain.insert_rule(rule)
        logging.info(f"Allowing service: {service['name']} on port {service['port']}/{service['protocol']}")
        display_alert(f"Allowing service: {service['name']} on port {service['port']}/{service['protocol']}")
    
    # Block specific ports
    for port in config.BLOCKED_PORTS:
        # Block TCP
        rule = iptc.Rule()
        rule.protocol = 'tcp'
        match = iptc.Match(rule, 'tcp')
        match.dport = str(port)
        rule.add_match(match)
        rule.target = iptc.Target(rule, 'DROP')
        input_chain.append_rule(rule)
        
        # Block UDP
        rule = iptc.Rule()
        rule.protocol = 'udp'
        match = iptc.Match(rule, 'udp')
        match.dport = str(port)
        rule.add_match(match)
        rule.target = iptc.Target(rule, 'DROP')
        input_chain.append_rule(rule)
        
        logging.info(f"Blocking port: {port} (TCP/UDP)")
        display_alert(f"Blocking port: {port} (TCP/UDP)")
    
    # Configure ICMP protection
    if config.ICMP_PROTECTION['enabled']:
        configure_icmp_protection(input_chain)
    
    logging.info("Firewall configuration complete")
    display_alert("Firewall configuration complete")

def configure_icmp_protection(input_chain):
    """Configure protection against ICMP attacks"""
    display_alert("Configuring ICMP attack protection", logging.INFO)
    
    if config.ICMP_PROTECTION['allow_ping']:
        # Allow normal ping requests but rate limit them
        rule = iptc.Rule()
        rule.protocol = 'icmp'
        match = iptc.Match(rule, 'icmp')
        match.icmp_type = 'echo-request'
        rule.add_match(match)
        
        # Add rate limiting with hashlimit
        limit_match = iptc.Match(rule, 'hashlimit')
        limit_match.hashlimit_name = 'icmp_rate'
        limit_match.hashlimit_upto = f"{config.ICMP_PROTECTION['rate_limit']}/sec" 
        limit_match.hashlimit_burst = str(config.ICMP_PROTECTION['burst'])
        limit_match.hashlimit_mode = 'srcip'
        limit_match.hashlimit_htable_expire = '60000'
        rule.add_match(limit_match)
        
        rule.target = iptc.Target(rule, 'ACCEPT')
        input_chain.append_rule(rule)
        
        display_alert(f"Allowing ping requests with rate limit of {config.ICMP_PROTECTION['rate_limit']}/second", logging.INFO)
        
        # Drop excessive ping requests
        if config.ICMP_PROTECTION['block_ping_flood']:
            # LOG rule (insert at beginning for better visibility)
            rule = iptc.Rule()
            rule.protocol = 'icmp'
            icmp_match = iptc.Match(rule, 'icmp')
            icmp_match.icmp_type = 'echo-request'
            rule.add_match(icmp_match)
            
            # Enhanced logging parameters
            log_target = iptc.Target(rule, 'LOG')
            log_target.log_prefix = "ICMP_FLOOD_DETECTED: "
            log_target.log_level = 'warning'
            rule.target = log_target
            input_chain.insert_rule(rule, position=0)
            
            # FINAL DROP RULE (no logging)
            rule = iptc.Rule()
            rule.protocol = 'icmp'
            icmp_match = iptc.Match(rule, 'icmp')
            icmp_match.icmp_type = 'echo-request'
            rule.add_match(icmp_match)
            rule.target = iptc.Target(rule, 'DROP')
            input_chain.append_rule(rule)
            
            display_alert("ICMP flood protection with enhanced logging enabled", logging.INFO)
    else:
        # Block all ICMP echo requests
        rule = iptc.Rule()
        rule.protocol = 'icmp'
        match = iptc.Match(rule, 'icmp')
        match.icmp_type = 'echo-request'
        rule.add_match(match)
        rule.target = iptc.Target(rule, 'DROP')
        input_chain.append_rule(rule)
        
        display_alert("Blocking all ping requests", logging.INFO)
    
    # Allow other ICMP types that are necessary for network functionality
    necessary_icmp_types = ['destination-unreachable', 'time-exceeded', 'parameter-problem']
    for icmp_type in necessary_icmp_types:
        rule = iptc.Rule()
        rule.protocol = 'icmp'
        match = iptc.Match(rule, 'icmp')
        match.icmp_type = icmp_type
        rule.add_match(match)
        rule.target = iptc.Target(rule, 'ACCEPT')
        input_chain.append_rule(rule)
        
        display_alert(f"Allowing necessary ICMP type: {icmp_type}", logging.INFO)

def monitor_attacks():
    """Monitor for attacks and display alerts"""
    
    display_alert("Starting attack monitoring thread", logging.INFO)
    
    while True:
        try:
            if os.path.exists(config.LOG_FILE):
                with open(config.LOG_FILE, 'r') as f:
                    f.seek(0, 2)
                    size = f.tell()
                    f.seek(max(size - 4096, 0), 0)
                    lines = f.readlines()
                
                # Check for ICMP flood indicators
                icmp_attacks = sum(1 for line in lines if "ICMP FLOOD" in line)
                if icmp_attacks > 0:
                    with counter_lock:
                        attack_counters['icmp_flood'] += icmp_attacks
                    display_alert(f"Detected possible ICMP flood attack! ({attack_counters['icmp_flood']} total attempts)", 
                                 logging.WARNING)

            time.sleep(5)
            
        except Exception as e:
            display_alert(f"Error in attack monitoring: {e}", logging.ERROR)
            time.sleep(10)

def main():
    print("Simple Python Firewall")
    print("======================")
    print(f"Starting firewall configuration at {datetime.now()}")
    
    try:
        clear_iptables()
        
        configure_firewall()
        
        print("Firewall configuration successful!")
        print(f"- Default policy: {config.DEFAULT_POLICY}")
        print(f"- Allowed IPs: {len(config.ALLOWED_IPs)}")
        print(f"- Blocked ports: {len(config.BLOCKED_PORTS)}")
        print(f"- Allowed services: {len(config.ALLOWED_SERVICES)}")
        
        if config.ICMP_PROTECTION['enabled']:
            print("- ICMP protection: Enabled")
            print(f"  - Rate limit: {config.ICMP_PROTECTION['rate_limit']} packets/second")
            print(f"  - Ping flood protection: {'Enabled' if config.ICMP_PROTECTION['block_ping_flood'] else 'Disabled'}")
        
        if config.LOG_ENABLED:
            print(f"Logging enabled: {config.LOG_FILE}")
        
        if config.ALERT_ENABLED:
            print(f"Alerts enabled (level: {config.ALERT_LEVEL})")
            
            monitor_thread = threading.Thread(target=monitor_attacks, daemon=True)
            monitor_thread.start()
            
            display_alert("Firewall is now running with alerts enabled", logging.INFO)
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                display_alert("Firewall monitoring stopped by user", logging.INFO)
                sys.exit(0)
    
    except Exception as e:
        logging.error(f"Error configuring firewall: {e}")
        print(f"Error configuring firewall: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
