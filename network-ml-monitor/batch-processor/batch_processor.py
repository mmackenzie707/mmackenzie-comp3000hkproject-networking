import requests
import sqlite3
import time
import logging
import sys
import threading
from pathlib import Path

# Add current directory to path
sys.path.append(str(Path(__file__).parent))
from actions import log_alert, block_ip, rate_limit_ip, init_alerts_table

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ML_SERVICE_URL = "http://ml-service:8000"
DB_PATH = "/app/logs/traffic.db"
RUNNING = True

def wait_for_ml_service(max_wait=300):
    """Wait for ml-service to be ready"""
    while RUNNING and time.time() - time.time() < max_wait:
        try:
            response = requests.get(f"{ML_SERVICE_URL}/health", timeout=5)
            if response.status_code == 200:
                logger.info("✓ ml-service is ready")
                return True
        except Exception as e:
            logger.info(f"Waiting for ml-service: {e}")
        time.sleep(10)
    return False

def run_batch_analysis():
    """Main batch analysis function"""
    logger.info("Starting batch analysis...")
    
    # Initialize table
    init_alerts_table(DB_PATH)
    
    # Get IPs from last hour
    with sqlite3.connect(DB_PATH) as conn:
        ips = [row[0] for row in conn.execute('''
            SELECT DISTINCT ip FROM api_logs WHERE timestamp > ?
        ''', (time.time() - 3600,))]
    
    if not ips:
        logger.info("No IPs to analyze")
        return False
    
    logger.info(f"Analyzing {len(ips)} IPs...")
    
    try:
        response = requests.post(f"{ML_SERVICE_URL}/analyze", 
                                json={"ips": ips}, timeout=30)
        response.raise_for_status()
        results = response.json()
        logger.info(f"Analysis complete: {len(results)} results")
        
        for r in results:
            ip = r.get('ip')
            risk_score = r.get('risk_score', 0)
            is_bot = r.get('is_bot', False)
            action = r.get('action', 'MONITOR')
            confidence = r.get('confidence', 0.0)
            
            log_alert(ip, risk_score, is_bot, confidence)
            
            if action == "BLOCK":
                block_ip(ip, f"High risk: {risk_score:.2f}")
            elif action == "RATE_LIMIT":
                rate_limit_ip(ip)
            
            logger.info(f"IP {ip}: risk={risk_score:.2f}, bot={is_bot}, action={action}")
            
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return False
    
    return True

def schedule_thread():
    """Run analysis every hour"""
    while RUNNING:
        run_batch_analysis()
        time.sleep(3600)  # Wait 1 hour

def command_listener():
    """Listen for manual trigger commands"""
    logger.info("Batch processor is running. Send SIGUSR1 to trigger analysis.")
    
    def trigger_signal_handler(signum, frame):
        logger.info("Manual trigger received via signal!")
        run_batch_analysis()
    
    import signal
    signal.signal(signal.SIGUSR1, trigger_signal_handler)
    
    # Keep the main thread alive
    while RUNNING:
        time.sleep(60)

if __name__ == '__main__':
    logger.info("Starting batch processor...")
    
    if not wait_for_ml_service():
        logger.error("Exiting - ml-service not available")
        sys.exit(1)
    
    # Run initial analysis
    run_batch_analysis()
    
    # Start hourly scheduler in background thread
    scheduler = threading.Thread(target=schedule_thread, daemon=True)
    scheduler.start()
    
    # Keep main thread alive for signal handling
    command_listener()