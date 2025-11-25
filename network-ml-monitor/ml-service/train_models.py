import pandas as pd
import sqlite3
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import sys
import os

def load_data(db_path):
    """Load and prepare training data from logs"""
    with sqlite3.connect(db_path) as conn:
        # Load API logs
        df = pd.read_sql_query('''
            SELECT ip, 
                   COUNT(*) as request_count,
                   AVG(response_time) as avg_response_time,
                   COUNT(DISTINCT endpoint) as unique_endpoints,
                   AVG(body_size) as avg_body_size,
                   COUNT(DISTINCT user_agent) as unique_user_agents
            FROM api_logs
            GROUP BY ip
        ''', conn)
        
        # Add simulated labels (replace with real labels in production)
        # IPs with very high request count are simulated as bots
        df['is_bot'] = (df['request_count'] > 1000).astype(int)
        
    return df

def train_models(db_path, model_path):
    """Train and save models"""
    df = load_data(db_path)
    
    if df.empty:
        print("No data found for training. Need at least 1 hour of logs.")
        return False
    
    # Features for training
    feature_cols = ['request_count', 'avg_response_time', 'unique_endpoints', 
                   'avg_body_size', 'unique_user_agents']
    X = df[feature_cols].fillna(0)
    
    # Train anomaly detection
    print("Training anomaly detection model...")
    anomaly_model = IsolationForest(contamination=0.1, random_state=42)
    anomaly_model.fit(X)
    joblib.dump(anomaly_model, f"{model_path}/anomaly_detector.pkl")
    
    # Train bot detection
    print("Training bot detection model...")
    bot_model = RandomForestClassifier(n_estimators=100, random_state=42)
    y = df['is_bot']
    bot_model.fit(X, y)
    joblib.dump(bot_model, f"{model_path}/bot_detector.pkl")
    
    print(f"✓ Models saved to {model_path}/")
    return True

if __name__ == "__main__":
    db_path = "/app/logs/traffic.db"
    model_path = "/app/models"
    
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        print("Run flask-app first to collect some logs, then try again.")
        sys.exit(1)
    
    success = train_models(db_path, model_path)
    sys.exit(0 if success else 1)