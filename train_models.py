import pandas as pd
import sqlite3
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

def load_training_data(db_path='traffic.db'):
    """Load and label historical data"""
    with sqlite3.connect(db_path) as conn:
        # Load features
        df = pd.read_sql_query('''
            SELECT ip, 
                   COUNT(*) as request_count,
                   AVG(response_time) as avg_response_time,
                   COUNT(DISTINCT endpoint) as unique_endpoints,
                   AVG(body_size) as avg_body_size,
                   COUNT(DISTINCT user_agent) as unique_user_agents,
                   -- Simulated labels (replace with actual labels)
                   CASE 
                     WHEN ip IN ('192.168.1.100', '10.0.0.5') THEN 1  -- Known bots
                     ELSE 0 
                   END as is_bot
            FROM api_logs
            GROUP BY ip
        ''', conn)
        
    return df

def train_anomaly_model(df):
    """Train Isolation Forest for anomaly detection"""
    feature_cols = ['request_count', 'avg_response_time', 'unique_endpoints', 'avg_body_size']
    X = df[feature_cols]
    
    # Handle missing values
    X = X.fillna(0)
    
    # Train
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)
    
    joblib.dump(model, '/app/models/anomaly_detector.pkl')
    print("Anomaly model trained and saved")

def train_bot_detection_model(df):
    """Train Random Forest for bot classification"""
    feature_cols = ['request_count', 'avg_response_time', 'unique_endpoints', 
                   'avg_body_size', 'unique_user_agents']
    X = df[feature_cols].fillna(0)
    y = df['is_bot']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    print(f"Bot detection accuracy: {model.score(X_test, y_test):.2f}")
    joblib.dump(model, '/app/models/bot_detector.pkl')
    print("Bot detection model trained and saved")

if __name__ == "__main__":
    df = load_training_data('/app/logs/traffic.db')
    train_anomaly_model(df)
    train_bot_detection_model(df)