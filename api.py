#!/usr/bin/env python3
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime
import json
import os
import asyncio
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = FastAPI(title="Firewall Monitor API")

# Connection manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        """Send message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            if conn in self.active_connections:
                self.active_connections.remove(conn)

manager = ConnectionManager()

# Log file watcher
class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file, action_type):
        self.log_file = log_file
        self.action_type = action_type
        self.last_position = 0
    
    def on_modified(self, event):
        if event.src_path == self.log_file:
            self.process_new_lines()
    
    def process_new_lines(self):
        """Read new lines from log file and broadcast them"""
        try:
            with open(self.log_file, 'r') as f:
                # Seek to last known position
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
            
            for line in new_lines:
                event = parse_log_line(line.strip())
                if event:
                    # Add action type if not present
                    event["action"] = self.action_type.upper()
                    # Broadcast to all WebSocket clients
                    asyncio.run(manager.broadcast(event))
                    
        except Exception as e:
            print(f"Error processing log file: {e}")

# Start log watchers
LOG_DIR = os.getenv("LOG_DIR", "/app/logs")

def start_log_watching():
    """Start watching log files for changes"""
    observer = Observer()
    
    # Watch allowed.log
    allowed_log = f"{LOG_DIR}/allowed.log"
    if os.path.exists(allowed_log):
        allowed_handler = LogFileHandler(allowed_log, "ALLOW")
        observer.schedule(allowed_handler, path=LOG_DIR, recursive=False)
    
    # Watch blocked.log
    blocked_log = f"{LOG_DIR}/blocked.log"
    if os.path.exists(blocked_log):
        blocked_handler = LogFileHandler(blocked_log, "BLOCK")
        observer.schedule(blocked_handler, path=LOG_DIR, recursive=False)
    
    observer.start()
    return observer

# Start watcher in background
log_observer = start_log_watching()

def parse_log_line(line):
    """Parse log line into event dictionary"""
    try:
        parts = line.split(" - ")
        if len(parts) < 3:
            return None
        
        timestamp = parts[0]
        action = parts[1]
        conn_part = parts[2]
        
        if " -> " not in conn_part:
            return None
            
        src_part, rest = conn_part.split(" -> ")
        dst_part, protocol_raw = rest.split(" (")
        protocol = protocol_raw.rstrip(")")
        
        src_ip, src_port = src_part.split(":")
        dst_ip, dst_port = dst_part.split(":")
        
        return {
            "timestamp": timestamp,
            "action": action,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol
        }
    except Exception:
        return None

# API Endpoints (unchanged for compatibility)
@app.get("/api/events")
async def get_events(limit: int = 100, action: str = None):
    """Get firewall events (HTTP fallback)"""
    events = []
    
    files = [f"{LOG_DIR}/allowed.log", f"{LOG_DIR}/blocked.log"]
    if action and action.upper() in ["ALLOW", "BLOCK"]:
        files = [f"{LOG_DIR}/{action.lower()}.log"]
    
    for filename in files:
        if not os.path.exists(filename):
            continue
            
        with open(filename, 'r') as f:
            lines = f.readlines()
            
        for line in reversed(lines[-limit:]):
            event = parse_log_line(line.strip())
            if event:
                events.append(event)
    
    events.sort(key=lambda x: x["timestamp"], reverse=True)
    return events[:limit]

@app.get("/api/stats")
async def get_stats():
    """Get firewall statistics"""
    stats = {"allowed": 0, "blocked": 0, "total": 0}
    
    for action in ["allowed", "blocked"]:
        filename = f"{LOG_DIR}/{action}.log"
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                lines = [l for l in f if " -> " in l]
                stats[action] = len(lines)
                stats["total"] += len(lines)
    
    return stats

# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time WebSocket connection"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, wait for messages (optional)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Serve enhanced GUI
@app.get("/", response_class=HTMLResponse)
async def get_gui():
    """Enhanced GUI with WebSocket support"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Firewall Monitor - Real-Time</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1400px; margin: 0 auto; }
            .stats { display: flex; gap: 20px; margin-bottom: 20px; }
            .stat-box { flex: 1; padding: 20px; border-radius: 8px; color: white; text-align: center; }
            .stat-allowed { background: #28a745; }
            .stat-blocked { background: #dc3545; }
            .stat-total { background: #007bff; }
            table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f8f9fa; position: sticky; top: 0; }
            .allow { color: #28a745; font-weight: bold; }
            .block { color: #dc3545; font-weight: bold; }
            .connection-status { padding: 10px; margin: 10px 0; border-radius: 4px; }
            .connected { background: #d4edda; color: #155724; }
            .disconnected { background: #f8d7da; color: #721c24; }
            .filter-section { margin: 20px 0; background: white; padding: 15px; border-radius: 8px; }
            .controls { margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔥 Firewall Monitor (Real-Time)</h1>
            
            <div id="connection-status" class="connection-status disconnected">
                WebSocket: Disconnected - Using polling fallback
            </div>
            
            <div class="stats" id="stats">
                <div class="stat-box stat-total">
                    <h2>Total Events</h2>
                    <p id="total-count">0</p>
                </div>
                <div class="stat-box stat-allowed">
                    <h2>Allowed</h2>
                    <p id="allowed-count">0</p>
                </div>
                <div class="stat-box stat-blocked">
                    <h2>Blocked</h2>
                    <p id="blocked-count">0</p>
                </div>
            </div>
            
            <div class="filter-section">
                <label>Show: </label>
                <select id="filter-select">
                    <option value="all">All Events</option>
                    <option value="ALLOW">Allowed Only</option>
                    <option value="BLOCK">Blocked Only</option>
                </select>
                <button class="controls" onclick="clearEvents()">Clear Display</button>
                <button class="controls" onclick="downloadLogs()">Download Logs</button>
            </div>
            
            <table id="events-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Action</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Protocol</th>
                    </tr>
                </thead>
                <tbody id="events-body">
                </tbody>
            </table>
        </div>
        
        <script>
            let ws = null;
            let autoRefreshInterval = null;
            let events = [];
            
            // WebSocket connection
            function connectWebSocket() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = `${protocol}//${window.location.host}/ws`;
                
                ws = new WebSocket(wsUrl);
                
                ws.onopen = function() {
                    document.getElementById('connection-status').className = 'connection-status connected';
                    document.getElementById('connection-status').textContent = 'WebSocket: Connected - Real-time updates active';
                    console.log('WebSocket connected');
                };
                
                ws.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    if (data.timestamp) {
                        // Add new event to beginning of array
                        events.unshift(data);
                        // Keep only last 1000 events
                        if (events.length > 1000) {
                            events = events.slice(0, 1000);
                        }
                        renderEvents();
                        updateStats();
                    }
                };
                
                ws.onclose = function() {
                    document.getElementById('connection-status').className = 'connection-status disconnected';
                    document.getElementById('connection-status').textContent = 'WebSocket: Disconnected - Attempting to reconnect in 3s';
                    console.log('WebSocket disconnected');
                    // Try to reconnect
                    setTimeout(connectWebSocket, 3000);
                };
                
                ws.onerror = function(error) {
                    console.error('WebSocket error:', error);
                };
            }
            
            // Initial connection
            connectWebSocket();
            
            // Polling fallback
            function startPolling() {
                autoRefreshInterval = setInterval(refreshData, 3000);
            }
            
            function stopPolling() {
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                    autoRefreshInterval = null;
                }
            }
            
            // Fetch data via HTTP (fallback)
            async function refreshData() {
                try {
                    const filter = document.getElementById('filter-select').value;
                    const url = filter === 'all' ? '/api/events' : `/api/events?action=${filter}`;
                    
                    const [eventsResponse, statsResponse] = await Promise.all([
                        fetch(url),
                        fetch('/api/stats')
                    ]);
                    
                    events = await eventsResponse.json();
                    const stats = await statsResponse.json();
                    
                    renderEvents();
                    updateStatsFromData(stats);
                } catch (error) {
                    console.error('Failed to fetch data:', error);
                }
            }
            
            function renderEvents() {
                const tbody = document.getElementById('events-body');
                tbody.innerHTML = '';
                
                const filter = document.getElementById('filter-select').value;
                const filteredEvents = filter === 'all' ? events : events.filter(e => e.action === filter);
                
                filteredEvents.forEach(event => {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td>${event.timestamp}</td>
                        <td class="${event.action.toLowerCase()}">${event.action}</td>
                        <td>${event.src_ip}:${event.src_port}</td>
                        <td>${event.dst_ip}:${event.dst_port}</td>
                        <td>${event.protocol}</td>
                    `;
                });
            }
            
            function updateStats() {
                // Calculate stats from in-memory events
                const stats = {
                    allowed: events.filter(e => e.action === 'ALLOW').length,
                    blocked: events.filter(e => e.action === 'BLOCK').length,
                    total: events.length
                };
                updateStatsFromData(stats);
            }
            
            function updateStatsFromData(stats) {
                document.getElementById('total-count').textContent = stats.total;
                document.getElementById('allowed-count').textContent = stats.allowed;
                document.getElementById('blocked-count').textContent = stats.blocked;
            }
            
            function clearEvents() {
                events = [];
                renderEvents();
                updateStats();
            }
            
            function downloadLogs() {
                window.open('/api/events?limit=10000', '_blank');
            }
            
            // Handle filter change
            document.getElementById('filter-select').addEventListener('change', renderEvents);
            
            // Start polling as fallback
            startPolling();
        </script>
    </body>
    </html>
    """
    return html_content