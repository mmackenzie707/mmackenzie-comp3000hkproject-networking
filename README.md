# Simple Firewall Project

This project demonstrates how to create, configure, and test a basic software firewall using Python. It consists of three main components:

1. `firewall.py` - A simple firewall implementation using Python's `iptables` wrapper
2. `config.py` - Configuration settings for the firewall
3. `pentest.py` - A basic penetration testing tool to verify firewall effectiveness

## Prerequisites

- Python 3.6 or higher
- Linux-based system (the firewall uses iptables)
- Root/sudo privileges (required for firewall configuration)
- Python packages: `python-iptables`, `scapy`

## Installation

```bash
# Install required packages
pip install python-iptables scapy

# Clone the repository (or download the files)
git clone https://github.com/yourusername/simple-firewall.git
cd simple-firewall
```

## Usage

### Setting up the Firewall

```bash
# Run as root or with sudo
sudo python firewall.py
```

### Running the Penetration Test

```bash
# In a separate terminal, run the penetration test tool
sudo python pentest.py
```

## Configuration

Edit the `config.py` file to customize firewall rules:

- `ALLOWED_IPS`: List of IP addresses that are allowed to connect
- `BLOCKED_PORTS`: List of ports that should be blocked
- `ALLOWED_SERVICES`: List of services that should be allowed

## Project Structure

```
simple-firewall/
├── README.md           # This file
├── firewall.py         # Main firewall implementation
├── config.py           # Firewall configuration
└── pentest.py          # Penetration testing tool
```

## How It Works

This project creates a simple firewall by configuring iptables rules based on the settings in `config.py`. It blocks unauthorized IPs, closes specified ports, and allows only designated services. The penetration testing tool attempts to breach these rules to verify the firewall's effectiveness.
