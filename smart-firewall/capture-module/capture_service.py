#!/usr/bin/env python3
"""PURE SNORT 2.9.15.1 CAPTURE - NO TCPDUMP FALLBACK"""
import subprocess
import time
from pathlib import Path
from shared.config import ConfigManager
from shared.logger import setup_logger

class SnortCaptureService:
    def __init__(self):
        self.config = ConfigManager().capture
        self.logger = setup_logger('capture-service')
        self.process = None
        
    def start(self):
        """Start Snort with correct 2.9.15.1 syntax"""
        self.logger.info("Starting Snort 2.9.15.1 capture service")
        
        capture_dir = Path(self.config.capture_dir)
        capture_dir.mkdir(parents=True, exist_ok=True)
        
        self._verify_interface()
        
        # =========================================================================
        # ✅ PURE SNORT COMMAND - NO TCPDUMP, NO INVALID OPTIONS
        # =========================================================================
        cmd = [
            'snort',
            '-c', '/etc/snort/snort_flow_capture.conf',
            '-i', self.config.interface,
            '-l', self.config.capture_dir,
            '-b',     # Binary mode
            '-N',     # No alerts
            '-q',     # Quiet
            '-K', 'none',  # Disable ASCII logging
            '-A', 'none'   # Disable alert file
        ]
        
        self.logger.info(f"Running: {' '.join(cmd)}")
        
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        self.logger.info(f"Snort PID: {self.process.pid}")
        self._monitor()
    
    def _verify_interface(self):
        """Check interface exists"""
        try:
            result = subprocess.run(['ip', 'link', 'show', self.config.interface], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"❌ Interface '{self.config.interface}' NOT FOUND!")
                subprocess.run(['ip', 'a'], check=False)
                raise RuntimeError(f"Interface {self.config.interface} does not exist")
            self.logger.info(f"✅ Interface '{self.config.interface}' verified")
        except FileNotFoundError:
            self.logger.warning("ip command not found")
    
    def _monitor(self):
        """Monitor Snort"""
        while True:
            if self.process.poll() is not None:
                stderr = self.process.stderr.read()
                self.logger.error(f"Snort died: {stderr}")
                time.sleep(5)
                self.start()
                break
            
            self._check_output_files()
            time.sleep(5)
    
    def _check_output_files(self):
        """Look for pcap files"""
        try:
            files = list(Path(self.config.capture_dir).glob('*.pcap'))
            if files:
                latest = max(files, key=lambda f: f.stat().st_mtime)
                size = latest.stat().st_size
                self.logger.info(f"📁 PCAP: {latest.name} ({size} bytes)")
            else:
                self.logger.debug("Waiting for traffic...")
        except Exception as e:
            self.logger.debug(f"File check error: {e}")
    
    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)

if __name__ == '__main__':
    service = SnortCaptureService()
    try:
        service.start()
    except KeyboardInterrupt:
        service.stop()