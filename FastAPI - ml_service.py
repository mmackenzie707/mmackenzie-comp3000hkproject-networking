from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import numpy as np
import sqlite3
import pandas as pd
from typing import List, Dict

app = FastAPI()

# Load models (train these first - see training script)
ANOMALY_MODEL = joblib.load('/app/models/anomaly_detector.pkl')
BOT_MODEL = joblib.load('/app/models/bot_detector.pkl')

class IPBatchRequest(BaseModel):
    ip_addresses: List[str]

class ActionRecommendation(BaseModel):
    ip: str
    risk_score: float
    is_bot: bool
    recommended_action: str
    confidence: float

def extract_features_from_db(ip: str, db_path: str) -> pd.DataFrame:
    """Extract features for an IP from logs"""
    with sqlite3.connect(db_path) as conn:
        # API call patterns
        api_df = pd.read_sql_query('''
            SELECT ip, COUNT(*) as request_count,
                   AVG(response_time) as avg_response_time,
                   COUNT(DISTINCT endpoint) as unique_endpoints,
                   AVG(body_size) as avg_body_size
            FROM api_logs
            WHERE ip = ? AND timestamp > ?
            GROUP BY ip
        ''', conn, params=(ip, time.time() - 3600))
        
        # Packet patterns
        packet_df = pd.read_sql_query('''
            SELECT src_ip, COUNT(*) as packet_count,
                   AVG(packet_size) as avg_packet_size,
                   COUNT(DISTINCT port) as unique_ports
            FROM packet_logs
            WHERE src_ip = ? AND timestamp > ?
            GROUP BY src_ip
        ''', conn, params=(ip, time.time() - 3600))
        
        # Combine features
        if not api_df.empty and not packet_df.empty:
            features = pd.merge(api_df, packet_df, left_on='ip', right_on='src_ip')
            return features
    return pd.DataFrame()

@app.post("/analyze-batch", response_model=List[ActionRecommendation])
async def analyze_ips(request: IPBatchRequest):
    """Analyze batch of IPs and recommend actions"""
    recommendations = []
    
    for ip in request.ip_addresses:
        features = extract_features_from_db(ip, '/app/logs/traffic.db')
        
        if features.empty:
            continue
            
        # Anomaly detection
        anomaly_score = ANOMALY_MODEL.decision_function(features)[0]
        risk_score = (1 - anomaly_score) * 100  # Convert to 0-100 scale
        
        # Bot detection
        is_bot_prob = BOT_MODEL.predict_proba(features)[0][1]
        is_bot = bool(is_bot_prob > 0.7)
        
        # Determine action
        if risk_score > 80 or is_bot:
            action = "BLOCK"
        elif risk_score > 50:
            action = "RATE_LIMIT"
        else:
            action = "MONITOR"
            
        recommendations.append(ActionRecommendation(
            ip=ip,
            risk_score=float(risk_score),
            is_bot=bool(is_bot),
            recommended_action=action,
            confidence=float(max(anomaly_score, is_bot_prob))
        ))
    
    return recommendations

@app.post("/analyze-log-batch")
async def process_log_batch():
    """Process all logs in batch mode"""
    with sqlite3.connect('/app/logs/traffic.db') as conn:
        # Get active IPs from last hour
        ips = pd.read_sql_query('''
            SELECT DISTINCT ip FROM api_logs 
            WHERE timestamp > ? UNION 
            SELECT DISTINCT src_ip FROM packet_logs 
            WHERE timestamp > ?
        ''', conn, params=(time.time() - 3600, time.time() - 3600))
        
        ip_list = ips['ip'].dropna().tolist()
        
    return await analyze_ips(IPBatchRequest(ip_addresses=ip_list))