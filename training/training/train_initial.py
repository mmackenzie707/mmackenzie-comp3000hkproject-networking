import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ml-service'))

from ml_service.feature_engineering import build_features
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import joblib

def main():
    # Build features from existing logs
    X, y = build_features('/app/logs/traffic.db')
    
    # Train and save models
    anomaly = IsolationForest(contamination=0.1, random_state=42)
    anomaly.fit(X)
    joblib.dump(anomaly, '../models/anomaly_detector.pkl')
    
    bot = RandomForestClassifier(n_estimators=100, random_state=42)
    bot.fit(X, y)
    joblib.dump(bot, '../models/bot_detector.pkl')

if __name__ == '__main__':
    main()