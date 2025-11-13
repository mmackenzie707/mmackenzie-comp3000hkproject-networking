import schedule
import time
import requests
import sqlite3

def run_batch_analysis():
    """Run batch analysis every hour"""
    try:
        response = requests.post('http://ml-service:8000/analyze-log-batch')
        results = response.json()
        
        # Store recommendations and trigger actions
        with sqlite3.connect('/app/logs/traffic.db') as conn:
            for rec in results:
                conn.execute('''
                    INSERT INTO security_alerts (timestamp, ip, risk_score, is_bot, 
                                                recommended_action, confidence)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (time.time(), rec['ip'], rec['risk_score'], rec['is_bot'],
                      rec['recommended_action'], rec['confidence']))
                
                # Trigger action based on recommendation
                if rec['recommended_action'] == 'BLOCK':
                    block_ip(rec['ip'])
                    
    except Exception as e:
        print(f"Batch processing error: {e}")

def block_ip(ip: str):
    """Example action: Add IP to firewall blocklist"""
    with open('/app/config/blocklist.txt', 'a') as f:
        f.write(f"{ip}\n")
    print(f"IP {ip} added to blocklist")

# Schedule batch jobs
schedule.every().hour.do(run_batch_analysis)

if __name__ == "__main__":
    while True:
        schedule.run_pending()
        time.sleep(60)