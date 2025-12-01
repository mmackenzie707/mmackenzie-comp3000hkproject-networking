"""Pluggable ML inference service"""
import time
import json
from pathlib import Path
from typing import Dict, Any
from shared.config import ConfigManager
from shared.logger import setup_logger

class MLEngineService:
    def __init__(self):
        self.config = ConfigManager().ml
        self.logger = setup_logger('ml-engine-service')
        self.model = self._load_model()
        
    def _load_model(self):
        """Load ML model with fallback to dummy classifier"""
        try:
            if self.config.model_type == 'cnn':
                from models.packet_cnn import PacketCNN
                model = PacketCNN()
                model.load_state_dict(torch.load(self.config.model_path))
                return model
        except Exception as e:
            self.logger.warning(f"Failed to load model: {e}, using dummy")
            return self._dummy_classifier()
    
    def _dummy_classifier(self):
        """Placeholder for development"""
        class DummyModel:
            def predict(self, x):
                return {'malicious': 0.1, 'benign': 0.9}
        return DummyModel()
    
    def start(self):
        """Monitor for new flow files and run inference"""
        self.logger.info("Starting ML engine service")
        
        while True:
            self._process_flow_files()
            time.sleep(5)
    
    def _process_flow_files(self):
        """Scan for and classify flows"""
        flow_path = Path('/data/flows')
        for flow_file in flow_path.glob('*.json'):
            try:
                with open(flow_file, 'r') as f:
                    flow_data = json.load(f)
                
                result = self.model.predict(flow_data)
                
                # Export results for action module
                result_file = Path(f"/data/results/{flow_file.stem}.json")
                result_file.parent.mkdir(exist_ok=True)
                
                with open(result_file, 'w') as f:
                    json.dump({
                        'flow_id': flow_file.stem,
                        'risk_score': result.get('malicious', 0),
                        'timestamp': time.time()
                    }, f)
                
                flow_file.unlink()  # Clean up
                self.logger.info(f"Classified flow: {flow_file.stem}")
                
            except Exception as e:
                self.logger.error(f"Error processing {flow_file}: {e}")

if __name__ == '__main__':
    service = MLEngineService()
    service.start()