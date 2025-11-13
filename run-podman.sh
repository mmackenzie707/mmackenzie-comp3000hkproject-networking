#!/bin/bash
mkdir -p logs

echo "=== Podman Firewall Runner ==="
echo "Select mode:"
echo "1) Rootless mode (limited to container network)"
echo "2) Rootful mode (full host network visibility - requires sudo)"
read -p "Choice [1-2]: " choice

case $choice in
  1)
    echo "Running in ROOTLESS mode..."
    podman-compose up --build -d
    echo "View logs: podman-compose logs -f"
    echo "Or: tail -f logs/firewall.log"
    ;;
  2)
    echo "Running in ROOTFUL mode..."
    sudo podman-compose up --build -d
    echo "View logs: sudo podman-compose logs -f"
    echo "Or: sudo tail -f logs/firewall.log"
    ;;
  *)
    echo "Invalid choice"
    exit 1
    ;;
esac