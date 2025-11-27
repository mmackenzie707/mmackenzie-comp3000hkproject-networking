import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import sqlite3
import time

class ThreatDetector:
    def __init__(self, model_path="/app/models/threat_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.load_model()
    
    def load_model(self):
        """Load pre-trained model or create a simple one for demo"""
        try:
            self.model = joblib.load(self.model_path)
            print(f"✓ Model loaded from {self.model_path}")
        except:
            print("⚠ Model not found, creating demo model...")
            self.create_demo_model()
    
    def create_demo_model(self):
        """Create a simple demonstration model"""
        # Features: [packet_size, port, requests_per_minute, failed_login_ratio, bot_pattern_score]
        X = np.array([
            # Normal traffic patterns
            [500, 80, 50, 0.0, 0.0],  # Normal web browsing
            [800, 443, 30, 0.0, 0.0],  # Normal HTTPS
            [200, 8080, 100, 0.0, 0.0], # Normal API calls
            [300, 8000, 40, 0.0, 0.0],  # Normal custom port
            
            # Malicious patterns
            [1500, 80, 500, 0.0, 0.8],  # Large packets, high rate
            [50, 22, 200, 0.0, 0.7],    # SSH scan on closed port
            [300, 80, 300, 0.9, 0.9],   # Brute force login
            [200, 443, 400, 0.0, 0.8],  # DDoS pattern
            [150, 8080, 600, 0.0, 0.85] # Bot attack
        ])
        
        y = np.array([0, 0, 0, 0, 1, 1, 1, 1, 1])  # 0=normal, 1=malicious
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, y)
        joblib.dump(self.model, self.model_path)
        print(f"✓ Demo model created and saved to {self.model_path}")

if __name__ == '__main__':
    detector = ThreatDetector()