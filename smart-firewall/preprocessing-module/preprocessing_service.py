"""Flow-agnostic preprocessing service"""
import time
import json
from pathlib import Path
from typing import Dict, List
import pyshark
from shared.config import ConfigManager
from shared.flow_models import PacketFeatures, FlowAggregate
from shared.logger import setup_logger

class PreprocessingService:
    def __init__(self):
        self.config = ConfigManager().capture
        self.logger = setup_logger('preprocessing-service')
        self.flow_cache: Dict[str, FlowAggregate] = {}
        
    def start(self):
        """Start preprocessing loop"""
        self.logger.info("Starting preprocessing service")
        
        while True:
            self._process_new_captures()
            time.sleep(10)
    
    def _process_new_captures(self):
        """Find and process new pcap files"""
        capture_path = Path(self.config.capture_dir)
        pcap_files = sorted(capture_path.glob('capture.*.pcap'))
        
        for pcap_file in pcap_files:
            if self._is_file_ready(pcap_file):
                self._process_pcap(pcap_file)
    
    def _is_file_ready(self, file: Path) -> bool:
        """Check if file is complete (not being written to)"""
        size1 = file.stat().st_size
        time.sleep(5)
        size2 = file.stat().st_size
        return size1 == size2
    
    def _process_pcap(self, pcap_file: Path):
        """Extract flows from pcap"""
        self.logger.info(f"Processing {pcap_file.name}")
        
        cap = pyshark.FileCapture(str(pcap_file))
        
        for packet in cap:
            flow_id = self._generate_flow_id(packet)
            if not flow_id:
                continue
            
            features = self._extract_features(packet, flow_id)
            self._update_flow_cache(flow_id, features)
        
        cap.close()
        self._export_completed_flows()
    
    def _generate_flow_id(self, packet) -> str:
        """Canonical flow ID generation"""
        try:
            if 'IP' not in packet:
                return None
            
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto = int(packet.ip.proto)
            
            src_port = dst_port = 0
            if 'TCP' in packet:
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
            elif 'UDP' in packet:
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
            
            endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
            return f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}-{proto}"
            
        except AttributeError:
            return None
    
    def _extract_features(self, packet, flow_id: str) -> PacketFeatures:
        """Extract features from single packet"""
        return PacketFeatures(
            timestamp=float(packet.sniff_time.timestamp()),
            packet_size=int(packet.length),
            src_ip=packet.ip.src if 'IP' in packet else '',
            dst_ip=packet.ip.dst if 'IP' in packet else '',
            src_port=int(packet.tcp.srcport) if 'TCP' in packet else 0,
            dst_port=int(packet.tcp.dstport) if 'TCP' in packet else 0,
            protocol=int(packet.ip.proto) if 'IP' in packet else 0,
            tcp_flags=int(packet.tcp.flags, 16) if 'TCP' in packet and hasattr(packet.tcp, 'flags') else None,
            payload_len=len(packet.tcp.payload.replace(':', '')) if 'TCP' in packet and hasattr(packet.tcp, 'payload') else 0,
            flow_id=flow_id
        )
    
    def _update_flow_cache(self, flow_id: str, features: PacketFeatures):
        """Add packet to flow aggregate"""
        if flow_id not in self.flow_cache:
            self.flow_cache[flow_id] = FlowAggregate(
                flow_id=flow_id,
                start_time=features.timestamp,
                end_time=features.timestamp,
                packet_count=0,
                total_bytes=0
            )
        
        flow = self.flow_cache[flow_id]
        flow.end_time = features.timestamp
        flow.packet_count += 1
        flow.total_bytes += features.packet_size
        flow.features.append(features)
    
    def _export_completed_flows(self):
        """Export flows that are complete or timed out"""
        current_time = time.time()
        timeout = self.config.flow_timeout
        
        for flow_id, flow in list(self.flow_cache.items()):
            if current_time - flow.end_time > timeout:
                export_file = Path(f"/data/flows/{flow_id}.json")
                export_file.parent.mkdir(exist_ok=True)
                
                with open(export_file, 'w') as f:
                    json.dump(flow.to_dict(), f, default=str)
                
                del self.flow_cache[flow_id]
                self.logger.info(f"Exported completed flow: {flow_id}")

if __name__ == '__main__':
    service = PreprocessingService()
    service.start()
