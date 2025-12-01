"""Orchestrator to monitor and restart services"""
import time
import subprocess
from shared.logger import setup_logger

class Orchestrator:
    def __init__(self):
        self.logger = setup_logger('orchestrator')
        self.services = [
            {'name': 'capture', 'status': 'stopped'},
            {'name': 'preprocessing', 'status': 'stopped'},
            {'name': 'ml-engine', 'status': 'stopped'},
            {'name': 'action', 'status': 'stopped'}
        ]
    
    def start(self):
        """Monitor all services"""
        self.logger.info("Orchestrator started")
        
        while True:
            for service in self.services:
                self._check_service(service)
            time.sleep(30)
    
    def _check_service(self, service: dict):
        """Health check for a service"""
        try:
            result = subprocess.run([
                'podman', 'exec', f'smart-firewall-{service["name"]}',
                'pgrep', '-f', 'python'
            ], capture_output=True)
            
            if result.returncode == 0:
                service['status'] = 'running'
            else:
                service['status'] = 'stopped'
                self._restart_service(service)
                
        except Exception as e:
            self.logger.error(f"Health check failed for {service['name']}: {e}")
    
    def _restart_service(self, service: dict):
        """Restart a failed service"""
        self.logger.warning(f"Restarting {service['name']} service")
        subprocess.run([
            'podman-compose', 'restart', service['name']
        ])

if __name__ == '__main__':
    orch = Orchestrator()
    orch.start()
