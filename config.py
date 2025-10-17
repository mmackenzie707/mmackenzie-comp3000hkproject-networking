ALLOWED_IPs = [
    '192.168.1.100',  # Admin workstation
    '192.168.1.101',  # Developer machine
    '192.168.1.200',  # Organization server
]

BLOCKED_PORTS = [
    22,    # SSH - Only allow from specific IPs
    3389,  # RDP
    5432,  # PostgreSQL
]

ALLOWED_SERVICES = [
    {'name': 'HTTP', 'port': 80, 'protocol': 'tcp'},
    {'name': 'HTTPS', 'port': 443, 'protocol': 'tcp'},
    {'name': 'DNS', 'port': 53, 'protocol': 'udp'},
]

# ICMP protection settings
ICMP_PROTECTION = {
    'enabled': True,
    'rate_limit': 5,  # Max ICMP packets per second
    'burst': 10,      # Burst limit
    'block_ping_flood': True,
    'allow_ping': True,  # Allow normal ping requests
}

DEFAULT_POLICY = 'DROP'  # Alternative: 'ACCEPT'

LOG_ENABLED = True
LOG_FILE = '/var/log/simple_firewall.log'

ALERT_ENABLED = True
ALERT_LEVEL = 'INFO'  # Options: 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'

