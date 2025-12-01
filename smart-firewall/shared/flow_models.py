"""Data models for flow-based processing"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime

@dataclass
class PacketFeatures:
    timestamp: float
    packet_size: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    tcp_flags: Optional[int] = None
    payload_len: int = 0
    flow_id: str = ""

@dataclass
class FlowAggregate:
    """Complete flow data for ML inference"""
    flow_id: str
    start_time: float
    end_time: float
    packet_count: int
    total_bytes: int
    features: List[PacketFeatures] = field(default_factory=list)
    risk_score: float = 0.0
    is_malicious: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to ML-ready format"""
        return {
            'flow_duration': self.end_time - self.start_time,
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'avg_packet_size': self.total_bytes / self.packet_count if self.packet_count > 0 else 0,
        }
