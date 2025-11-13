# Option A: Rootless (simple, but limited)
podman-compose up --build -d
podman-compose logs -f

# Option B: Rootful (full functionality, requires sudo)
sudo podman-compose up --build -d
sudo podman-compose logs -f

# Option C: Direct podman run (rootful, single command)
sudo podman run --rm -d --name firewall-monitor \
  --network host \
  --privileged \
  -v ./logs:/tmp/firewall:Z \
  -v ./rules.json:/app/rules.json:ro,Z \
  localhost/static-firewall:latest

# View logs from direct run
sudo podman logs -f firewall-monitor

# Stop container
sudo podman stop firewall-monitor