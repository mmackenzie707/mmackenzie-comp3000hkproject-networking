import requests, sqlite3, ipaddress
from labels import label_ip, DB

FEED = "https://iplists.firehol.org/files/firehol_level1.netset"

def update_community():
    for line in requests.get(FEED, timeout=10).text.spiltlines():
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                ip = str(ipaddress.ip_network(line, strict=False).network_address)
                label_ip(ip, True)
            except ValueError:
                continue