"""Action execution service with safety controls"""
import json
import subprocess
import time
from pathlib import Path
from shared.config import ConfigManager
from shared.logger import setup_logger

class ActionService:
    def __init__(self):
        self.config = ConfigManager().action
        self.logger = setup_logger('action-service')
        self._setup_iptables()
        
    def _setup_iptables(self):
        """Create custom chain for firewall rules"""
        if not self.config.enable_blocking:
            self.logger.warning("Blocking disabled - running in monitoring mode")
            return
        
        try:
            subprocess.run([
                'iptables', '-N', self.config.iptables_chain
            ], check=False)
            subprocess.run([
                'iptables', '-A', 'INPUT', '-j', self.config.iptables_chain
            ], check=True)
            self.logger.info(f"Created iptables chain: {self.config.iptables_chain}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to setup iptables: {e}")
    
    def start(self):
        """Monitor ML results and take action"""
        self.logger.info("Starting action service")
        
        while True:
            self._process_results()
            time.sleep(5)
    
    def _process_results(self):
        """Process ML classification results"""
        result_path = Path('/data/results')
        for result_file in result_path.glob('*.json'):
            try:
                with open(result_file, 'r') as f:
                    result = json.load(f)
                
                if result['risk_score'] > self.config.ml.confidence_threshold:
                    self._take_action(result)
                
                result_file.unlink()
                
            except Exception as e:
                self.logger.error(f"Error processing result: {e}")
    
    def _take_action(self, result: dict):
        """Execute blocking or alerting action"""
        flow_id = result['flow_id']
        risk_score = result['risk_score']
        
        # Log action
        log_entry = f"{flow_id},{risk_score},{int(time.time())}\n"
        Path(self.config.log_file).parent.mkdir(exist_ok=True)
        Path(self.config.log_file).open('a').write(log_entry)
        
        # Block if enabled
        if self.config.enable_blocking:
            self._block_flow(flow_id)
        else:
            self.logger.info(f"ALERT: Malicious flow detected: {flow_id} (score: {risk_score})")
    
    def _block_flow(self, flow_id: str):
        """Parse flow ID and create iptables rule"""
        try:
            # Parse flow_id format: ip:port-ip:port-proto
            parts = flow_id.split('-')
            src = parts[0].split(':')
            dst = parts[1].split(':')
            proto = parts[2]
            
            # Create iptables rule
            rule = [
                'iptables', '-A', self.config.iptables_chain,
                '-s', src[0], '--sport', src[1],
                '-d', dst[0], '--dport', dst[1],
                '-p', 'tcp' if proto == '6' else 'udp',
                '-j', 'DROP'
            ]
            
            subprocess.run(rule, check=True)
            self.logger.info(f"Blocked flow: {flow_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to block {flow_id}: {e}")

if __name__ == '__main__':
    service = ActionService()
    service.start()
