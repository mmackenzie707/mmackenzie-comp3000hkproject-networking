from flask import Flask, request, jsonify
from middleware.logging import init_db, log_middleware
import random
import time
import sqlite3
import os
import ipaddress
import logging

app = Flask(__name__)

# Initialize middleware logging DB
init_db('/app/logs/traffic.db')
log_middleware(app)

# Path to packet capture database (populated by separate packet-sniffer service)
PACKET_DB_PATH = '/app/logs/traffic.db'

# Path to blocked IPs database
BLOCKED_DB_PATH = '/app/logs/blocked_ips.db'

# ========================================
# Public Endpoints (Traffic Generation)
# ========================================

@app.route('/')
def index():
    return jsonify({
        "message": "Network ML Monitor Dashboard", 
        "version": "1.0",
        "features": {
            "traffic_generation": "active",
            "packet_monitoring": "database_connected" if os.path.exists(PACKET_DB_PATH) else "disconnected",
            "threat_detection": "ml_enabled",
            "ip_blocking": "iptables_managed"
        }
    })

@app.route('/api/health')
@app.route('/health')
def health():
    return jsonify({
        "status": "ok", 
        "timestamp": time.time(),
        "service": "flask-app",
        "mode": "monitoring_dashboard"
    })

@app.route('/api/users')
def get_users():
    users = [
        {"id": 1, "name": "Alice", "role": "admin"},
        {"id": 2, "name": "Bob", "role": "user"},
        {"id": 3, "name": "Charlie", "role": "user"}
    ]
    return jsonify(users)

@app.route('/api/data')
def get_data():
    time.sleep(random.uniform(0.01, 0.5))
    return jsonify({
        "data": list(range(random.randint(5, 20))),
        "count": random.randint(1, 100)
    })

@app.route('/api/status')
def status():
    return jsonify({
        "cpu": random.uniform(0, 100),
        "memory": random.uniform(0, 100),
        "requests": random.randint(100, 1000)
    })

# ========================================
# Protected Endpoints (Simulated Auth)
# ========================================

@app.route('/api/profile')
def profile():
    if random.random() > 0.9:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"user": "test_user", "permissions": ["read", "write"]})

@app.route('/api/admin')
def admin():
    return jsonify({"admin_panel": True, "users": 150})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '')
    
    if 'bot' in username.lower():
        time.sleep(0.2)
        return jsonify({"error": "Invalid credentials"}), 403
    
    return jsonify({
        "token": "fake_jwt_token_" + str(random.randint(1000, 9999)),
        "expires_in": 3600
    })

@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    time.sleep(random.uniform(0.05, 0.3))
    return jsonify({
        "query": query,
        "results": random.randint(0, 50),
        "time_ms": random.randint(5, 100)
    })

@app.route('/api/realtime')
def realtime():
    return jsonify({
        "timestamp": time.time(),
        "events": random.randint(0, 10),
        "alerts": random.randint(0, 5)
    })

# ========================================
# Monitoring Dashboard Endpoints
# ========================================

@app.route('/api/packets')
def get_packets():
    """Retrieve captured packet data from database"""
    try:
        limit = min(int(request.args.get('limit', 100)), 1000)
        
        with sqlite3.connect(PACKET_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT timestamp, src_ip, dst_ip, protocol, port, packet_size, flags 
                FROM packet_logs 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            packets = [dict(row) for row in cursor.fetchall()]
            
        return jsonify({
            "packets": packets,
            "count": len(packets),
            "source": "packet-sniffer-service"
        })
    except sqlite3.OperationalError:
        return jsonify({
            "error": "Database not initialized",
            "packets": [],
            "hint": "Ensure packet-sniffer service is running"
        }), 503
    except Exception as e:
        return jsonify({"error": str(e), "packets": []}), 500

@app.route('/api/packets/stats')
def packet_stats():
    """Get packet capture statistics"""
    try:
        with sqlite3.connect(PACKET_DB_PATH) as conn:
            total = conn.execute("SELECT COUNT(*) FROM packet_logs").fetchone()[0]
            protocols = conn.execute("""
                SELECT protocol, COUNT(*) as count 
                FROM packet_logs GROUP BY protocol
            """).fetchall()
            top_sources = conn.execute("""
                SELECT src_ip, COUNT(*) as count 
                FROM packet_logs GROUP BY src_ip ORDER BY count DESC LIMIT 10
            """).fetchall()
            
        return jsonify({
            "total_packets": total,
            "protocols": {p[0]: p[1] for p in protocols},
            "top_sources": [{"ip": s[0], "count": s[1]} for s in top_sources]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/packets/summary')
def packet_summary():
    """Get high-level packet capture summary"""
    try:
        if not os.path.exists(PACKET_DB_PATH):
            return jsonify({"status": "no_database", "message": "Packet database not yet created"})
            
        with sqlite3.connect(PACKET_DB_PATH) as conn:
            result = conn.execute("""
                SELECT COUNT(*) as total, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
                FROM packet_logs
            """).fetchone()
            
        return jsonify({
            "status": "active" if result[0] > 0 else "waiting_for_packets",
            "total_packets": result[0],
            "time_range": {"first": result[1], "last": result[2]}
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ========================================
# IP Blocking Management Endpoints
# ========================================

@app.route('/api/blocked-ips')
def get_blocked_ips():
    """Get list of currently blocked IPs"""
    try:
        if not os.path.exists(BLOCKED_DB_PATH):
            return jsonify({"blocked_ips": [], "message": "No blocked IPs database yet"})
            
        with sqlite3.connect(BLOCKED_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT ip_address, reason, confidence, blocked_count, 
                       first_detected as first_seen, last_seen
                FROM blocked_ips 
                WHERE is_active = 1 
                ORDER BY last_seen DESC
            """)
            
            blocked = [dict(row) for row in cursor.fetchall()]
            
        return jsonify({
            "blocked_ips": blocked,
            "count": len(blocked)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/block-ip', methods=['POST'])
def manual_block_ip():
    """Manually block an IP (database only - iptables handled by batch processor)"""
    data = request.get_json() or {}
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'Manual block')
    
    if not ip_address:
        return jsonify({"error": "IP address required"}), 400
    
    # Validate IP
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    
    # Log the block request for batch processor to action
    try:
        with sqlite3.connect(BLOCKED_DB_PATH) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO blocked_ips (ip_address, reason, confidence, first_detected, last_seen) 
                VALUES (?, ?, ?, ?, ?)
            """, (ip_address, reason, 1.0, time.time(), time.time()))
        
        # Log to separate blocked IPs log file
        logging.basicConfig(
            filename='/app/logs/blocked_ips.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        logging.warning(f"MANUAL BLOCK REQUEST: {ip_address} | Reason: {reason}")
        
        return jsonify({
            "message": f"IP {ip_address} blocked", 
            "reason": reason,
            "note": "iptables rule will be applied by batch processor service"
        })
    except Exception as e:
        return jsonify({"error": f"Failed to block IP: {str(e)}"}), 500

@app.route('/api/unblock-ip/<ip_address>', methods=['DELETE'])
def unblock_ip(ip_address):
    """Unblock an IP"""
    try:
        # Update database
        with sqlite3.connect(BLOCKED_DB_PATH) as conn:
            conn.execute("""
                UPDATE blocked_ips SET is_active = 0 WHERE ip_address = ?
            """, (ip_address,))
        
        # Log the unblock request
        logging.basicConfig(
            filename='/app/logs/blocked_ips.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        logging.info(f"UNBLOCK REQUEST: {ip_address}")
        
        return jsonify({
            "message": f"IP {ip_address} unblocked - iptables rule will be removed by batch processor"
        })
    except Exception as e:
        return jsonify({"error": f"Failed to unblock IP: {str(e)}"}), 500

# ========================================
# NEW: Dashboard Route
# ========================================

@app.route('/dashboard')
def dashboard():
    """Serve the traffic monitoring dashboard HTML with ML threat detection UI"""
    html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network ML Monitor Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 20px;
            text-align: center;
        }
        .status-bar {
            background: #3498db;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .refresh-toggle {
            background: #27ae60;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
        }
        .refresh-toggle.active {
            background: #e74c3c;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card h3 {
            color: #7f8c8d;
            font-size: 14px;
            margin-bottom: 5px;
        }
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #2c3e50;
        }
        .section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .section h2 {
            margin-bottom: 15px;
            color: #2c3e50;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #3498db;
            color: white;
            font-weight: 600;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .error {
            background: #e74c3c;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .timestamp {
            font-size: 14px;
            color: #7f8c8d;
        }
        .protocol-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .protocol-TCP { background: #3498db; color: white; }
        .protocol-UDP { background: #e67e22; color: white; }
        .protocol-Other { background: #95a5a6; color: white; }
        .threat-red { background: #e74c3c; color: white; }
        .threat-orange { background: #f39c12; color: white; }
        .threat-green { background: #27ae60; color: white; }
        .loading {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
        }
        .blocked-ips-table {
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Network ML Monitor Dashboard</h1>
        
        <div class="status-bar">
            <span id="status-text">Loading...</span>
            <button class="refresh-toggle active" id="refreshBtn" onclick="toggleRefresh()">Auto-refresh: ON</button>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Packets</h3>
                <div class="value" id="total-packets">-</div>
            </div>
            <div class="stat-card">
                <h3>TCP Packets</h3>
                <div class="value" id="tcp-packets">-</div>
            </div>
            <div class="stat-card">
                <h3>UDP Packets</h3>
                <div class="value" id="udp-packets">-</div>
            </div>
            <div class="stat-card">
                <h3>Unique Sources</h3>
                <div class="value" id="unique-sources">-</div>
            </div>
            <div class="stat-card">
                <h3>Blocked IPs</h3>
                <div class="value" id="blocked-count" style="color: #e74c3c;">-</div>
            </div>
        </div>

        <div class="section">
            <h2>Recent Packets</h2>
            <div id="packet-table-container">
                <div class="loading">Loading packet data...</div>
            </div>
        </div>

        <div class="section">
            <h2>Traffic Summary</h2>
            <div id="summary-container">
                <div class="loading">Loading summary...</div>
            </div>
        </div>

        <div class="section">
            <h2>🔒 Blocked IPs (ML Threat Detection)</h2>
            <div id="blocked-ips-container">
                <div class="loading">Loading blocked IPs...</div>
            </div>
        </div>
    </div>

    <script>
        let refreshInterval = null;
        const REFRESH_RATE = 2000; // 2 seconds

        async function fetchData() {
            try {
                // Update status
                document.getElementById('status-text').textContent = 'Connected - Last update: ' + new Date().toLocaleTimeString();
                
                // Fetch packets
                const packetsResponse = await fetch('/api/packets?limit=50');
                const packetsData = await packetsResponse.json();
                
                // Fetch stats
                const statsResponse = await fetch('/api/packets/stats');
                const statsData = await statsResponse.json();
                
                // Fetch summary
                const summaryResponse = await fetch('/api/packets/summary');
                const summaryData = await summaryResponse.json();
                
                // Fetch blocked IPs
                const blockedResponse = await fetch('/api/blocked-ips');
                const blockedData = await blockedResponse.json();
                
                // Update UI
                updatePacketTable(packetsData.packets || []);
                updateStats(statsData);
                updateSummary(summaryData);
                updateBlockedIPs(blockedData);
                
            } catch (error) {
                document.getElementById('status-text').textContent = 'Error: ' + error.message;
                console.error('Fetch error:', error);
            }
        }

        function updatePacketTable(packets) {
            const container = document.getElementById('packet-table-container');
            
            if (!packets || packets.length === 0) {
                container.innerHTML = '<div class="loading">No packets captured yet. Generate some HTTP traffic!</div>';
                return;
            }

            let html = `
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Protocol</th>
                            <th>Port</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            packets.forEach(packet => {
                const time = new Date(packet.timestamp * 1000).toLocaleTimeString();
                html += `
                    <tr>
                        <td class="timestamp">${time}</td>
                        <td>${packet.src_ip}</td>
                        <td>${packet.dst_ip}</td>
                        <td><span class="protocol-badge protocol-${packet.protocol}">${packet.protocol}</span></td>
                        <td>${packet.port || '-'}</td>
                        <td>${packet.packet_size} bytes</td>
                    </tr>
                `;
            });
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }

        function updateStats(stats) {
            document.getElementById('total-packets').textContent = stats.total_packets || 0;
            
            // Count protocols
            const protocols = stats.protocols || {};
            document.getElementById('tcp-packets').textContent = protocols.TCP || 0;
            document.getElementById('udp-packets').textContent = protocols.UDP || 0;
            
            // Count unique sources
            const uniqueSources = stats.top_sources ? stats.top_sources.length : 0;
            document.getElementById('unique-sources').textContent = uniqueSources;
        }

        function updateSummary(summary) {
            const container = document.getElementById('summary-container');
            
            if (summary.error) {
                container.innerHTML = `<div class="error">${summary.error}</div>`;
                return;
            }
            
            if (summary.status === 'no_database') {
                container.innerHTML = '<div class="loading">Waiting for packet-sniffer service to start...</div>';
                return;
            }
            
            if (summary.total_packets === 0) {
                container.innerHTML = '<div class="loading">No packets captured yet. Generate some traffic!</div>';
                return;
            }
            
            const firstSeen = new Date(summary.time_range.first * 1000).toLocaleString();
            const lastSeen = new Date(summary.time_range.last * 1000).toLocaleString();
            
            container.innerHTML = `
                <p><strong>Status:</strong> ${summary.status === 'active' ? '✅ Capturing' : '⏸️ Waiting'}</p>
                <p><strong>Total Packets:</strong> ${summary.total_packets.toLocaleString()}</p>
                <p><strong>Time Range:</strong> ${firstSeen} to ${lastSeen}</p>
                <p><strong>Capture Rate:</strong> ${(summary.total_packets / ((summary.time_range.last - summary.time_range.first) || 1) * 60).toFixed(2)} packets/min</p>
            `;
        }

        function updateBlockedIPs(blockedData) {
            const container = document.getElementById('blocked-ips-container');
            const countElement = document.getElementById('blocked-count');
            
            if (!blockedData.blocked_ips || blockedData.blocked_ips.length === 0) {
                container.innerHTML = '<p style="text-align: center; color: #27ae60;">✅ No threats detected - All traffic clean</p>';
                countElement.textContent = '0';
                return;
            }
            
            countElement.textContent = blockedData.count;
            
            let html = `
                <table class="blocked-ips-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Reason</th>
                            <th>Confidence</th>
                            <th>First Seen</th>
                            <th>Block Count</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            blockedData.blocked_ips.forEach(ip => {
                const firstSeen = new Date(ip.first_seen * 1000).toLocaleString();
                const confidence = ip.confidence || 0;
                let badgeClass = 'threat-green';
                if (confidence > 0.7) badgeClass = 'threat-red';
                else if (confidence > 0.4) badgeClass = 'threat-orange';
                
                html += `
                    <tr>
                        <td><strong>${ip.ip_address}</strong></td>
                        <td>${ip.reason}</td>
                        <td><span class="protocol-badge ${badgeClass}">${(confidence * 100).toFixed(0)}%</span></td>
                        <td class="timestamp">${firstSeen}</td>
                        <td>${ip.blocked_count || 1}</td>
                    </tr>
                `;
            });
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }

        function toggleRefresh() {
            const btn = document.getElementById('refreshBtn');
            
            if (refreshInterval) {
                clearInterval(refreshInterval);
                refreshInterval = null;
                btn.textContent = 'Auto-refresh: OFF';
                btn.classList.remove('active');
            } else {
                refreshInterval = setInterval(fetchData, REFRESH_RATE);
                btn.textContent = 'Auto-refresh: ON';
                btn.classList.add('active');
                fetchData(); // Immediate refresh
            }
        }

        // Start auto-refresh on page load
        window.onload = function() {
            fetchData();
            refreshInterval = setInterval(fetchData, REFRESH_RATE);
        };
    </script>
</body>
</html>'''
    return html_content

# ========================================
# MAIN GUARD (Keep this at the very end)
# ========================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)