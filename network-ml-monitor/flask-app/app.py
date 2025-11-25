from flask import Flask, request, jsonify
from middleware.logging import init_db, log_middleware
from packet_capture.sniffer import start_sniffer
import random
import time

app = Flask(__name__)

# Initialize monitoring
init_db('/app/logs/traffic.db')
log_middleware(app)

# Public endpoints (normal traffic)
@app.route('/')
def index():
    return jsonify({"message": "Welcome to Network ML Monitor", "version": "1.0"})

@app.route('/api/health')
@app.route('/health')
def health():
    return jsonify({"status": "ok", "timestamp": time.time()})

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
    # Simulate varying response times
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

# Protected endpoints (require auth simulation)
@app.route('/api/profile')
def profile():
    # Simulate authentication check
    if random.random() > 0.9:  # 10% chance of auth failure
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"user": "test_user", "permissions": ["read", "write"]})

@app.route('/api/admin')
def admin():
    return jsonify({"admin_panel": True, "users": 150})

# Simulate endpoints that might be attacked
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '')
    
    # Simulate failed login attempts
    if 'bot' in username.lower():
        time.sleep(0.2)  # Simulate processing delay
        return jsonify({"error": "Invalid credentials"}), 403
    
    return jsonify({"token": "fake_jwt_token", "expires_in": 3600})

@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    # Simulate search processing
    time.sleep(random.uniform(0.05, 0.3))
    return jsonify({
        "query": query,
        "results": random.randint(0, 50),
        "time_ms": random.randint(5, 100)
    })

# Endpoint that changes frequently
@app.route('/api/realtime')
def realtime():
    return jsonify({
        "timestamp": time.time(),
        "events": random.randint(0, 10),
        "alerts": random.randint(0, 5)
    })

# Start packet sniffer in background
start_sniffer()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)