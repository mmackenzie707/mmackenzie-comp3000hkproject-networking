from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import sqlite3
import pandas as pd
import time
import os

app = FastAPI()

class IPBatchRequest(BaseModel):
    ips: list[str]

class AnalysisResult(BaseModel):
    ip: str
    risk_score: float
    is_bot: bool
    action: str
    confidence: float

anomaly_model = None
bot_model = None

@app.on_event("startup")
def load_models():
    global anomaly_model, bot_model
    model_path = "/app/models"
    try:
        if os.path.exists(f"{model_path}/anomaly_detector.pkl"):
            anomaly_model = joblib.load(f"{model_path}/anomaly_detector.pkl")
            bot_model = joblib.load(f"{model_path}/bot_detector.pkl")
            print("✓ Models loaded")
        else:
            print("⚠ Models not found - place training data first")
    except Exception as e:
        print(f"Model loading error: {e}")

def extract_features(ip: str, db_path: str) -> pd.DataFrame:
    # Only use API features (packet_logs disabled)
    with sqlite3.connect(db_path) as conn:
        api_features = pd.read_sql_query('''
            SELECT ip, 
                   COUNT(*) as request_count,
                   AVG(response_time) as avg_response_time,
                   COUNT(DISTINCT endpoint) as unique_endpoints,
                   AVG(body_size) as avg_body_size,
                   COUNT(DISTINCT user_agent) as unique_user_agents
            FROM api_logs
            WHERE ip = ? AND timestamp > ?
            GROUP BY ip
        ''', conn, params=(ip, time.time() - 3600))
        
        return api_features.fillna(0)

@app.post("/analyze", response_model=list[AnalysisResult])
def analyze_ips(request: IPBatchRequest):
    global anomaly_model, bot_model
    
    results = []
    db_path = "/app/logs/traffic.db"
    
    for ip in request.ips:
        features = extract_features(ip, db_path)
        
        if features.empty:
            continue
        
        X = features.drop('ip', axis=1, errors='ignore')
        
        risk_score = 0.5
        is_bot = False
        confidence = 0.5
        
        if anomaly_model is not None and not X.empty:
            try:
                anomaly_score = anomaly_model.decision_function(X)[0]
                risk_score = float((1 - anomaly_score) * 50)
            except:
                pass
        
        if bot_model is not None and not X.empty:
            try:
                bot_prob = bot_model.predict_proba(X)[0][1]
                is_bot = bool(bot_prob > 0.7)
                confidence = float(bot_prob)
            except:
                pass
        
        if risk_score > 80 or is_bot:
            action = "BLOCK"
        elif risk_score > 50:
            action = "RATE_LIMIT"
        else:
            action = "MONITOR"
        
        results.append(AnalysisResult(
            ip=ip,
            risk_score=risk_score,
            is_bot=is_bot,
            action=action,
            confidence=confidence
        ))
    
    return results

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def root():
    return {"message": "ML Service Running", "models_loaded": anomaly_model is not None}

@app.post("/train")
def train():
    from train_models import train_models
    success = train_models("/app/logs/traffic.db", "/app/models")
    if success:
        load_models()
    return {"status": "trained" if success else "failed"}