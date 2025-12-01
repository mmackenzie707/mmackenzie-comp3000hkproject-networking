"""Central configuration management - single source of truth"""
import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class CaptureConfig:
    interface: str = os.getenv('CAPTURE_INTERFACE', 'eth0')
    capture_dir: str = os.getenv('CAPTURE_DIR', '/data/captures')
    pcap_rotation_size: str = os.getenv('PCAP_ROTATION_SIZE', '50M')
    flow_timeout: int = int(os.getenv('FLOW_TIMEOUT', '300'))

@dataclass
class MLConfig:
    model_type: str = os.getenv('ML_MODEL_TYPE', 'cnn')
    model_path: str = os.getenv('ML_MODEL_PATH', '/models/firewall_model.pth')
    confidence_threshold: float = float(os.getenv('CONFIDENCE_THRESHOLD', '0.8'))
    batch_size: int = int(os.getenv('ML_BATCH_SIZE', '32'))

@dataclass
class ActionConfig:
    enable_blocking: bool = os.getenv('ENABLE_BLOCKING', 'false').lower() == 'true'
    iptables_chain: str = os.getenv('IPTABLES_CHAIN', 'SMART_FIREWALL')
    log_file: str = os.getenv('ACTION_LOG', '/data/logs/actions.log')

class ConfigManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.capture = CaptureConfig()
            cls._instance.ml = MLConfig()
            cls._instance.action = ActionConfig()
        return cls._instance
