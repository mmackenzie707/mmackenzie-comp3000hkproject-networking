import json
import time
import pandas as pd
from pathlib import Path

def process_suricata_alerts():
    eve_log = Path("/app/logs/eve.json")
    
    if not eve_log.exists():
        print("Waiting for Suricata logs...")
        return
    
    # Read latest alerts
    with open(eve_log, "r") as f:
        for line in f:
            try:
                alert = json.loads(line)
                
                # Extract features from Suricata's structured data
                features = {
                    'src_ip': alert.get('src_ip'),
                    'dst_port': alert.get('dest_port'),
                    'protocol': alert.get('proto'),
                    'signature': alert.get('alert', {}).get('signature'),
                    'severity': alert.get('alert', {}).get('severity'),
                    'timestamp': alert.get('timestamp')
                }
                
                # Feed to your ML model
                threat_score = ml_model.predict(pd.DataFrame([features]))
                print(f"Threat Score: {threat_score} for {features}")
                
            except Exception as e:
                print(f"Error processing alert: {e}")

while True:
    process_suricata_alerts()
    time.sleep(5)