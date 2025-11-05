from __future__ import annotations
import numpy as np
from scapy.packet import Packet
from scapy.layers.inet import TCP, UDP

#lightweight data connector
class Flow:
    __slots__ = ("pkt_list", "ts_list", "dir_list", "five_tuple")
    def __init__(self) -> None:
        self.pkt_list: list[Packet] = []
        self.ts_list: list[float] = []
        self.dir_list: list[int] = []
        self.five_tuple: tuple[str, int, int, str, int] | None = None

N_FEATURES = 23

def flow_to_vectors(flow: Flow) -> np.ndarray | None:
    #Return 23-d float32 vector or None if flow to small
    if len(flow.pkt_list) < 2:
        return None
    ts = np.array(flow.ts_list, dtype=np.float32)
    dur = float(ts[-1] - ts[0])
    if dur <= 0.0:
        dur = 1e-3
    sizes = np.array([len(p) for p in flow.pkt_list], dtype=np.float32)
    inter = np.diff(ts)
    dirs = np.array(flow.dir_list, dtype=int8)

    fwd_sizes = sizes[dirs > 0]
    bwd_sizes = sizes[dirs < 0]

    flag_counts: dict[int, int] = {}
    for p in flow.pkt_list:
        if TCP in p:
            f = int(p[TCP].flags)
            flag_counts[f] = flag_counts.get(f, 0) + 1

    
    vec = np.zeros(N_FEATURES, dtype=np.float32)

    vec[0] = dur
    vec[1] = len(sizes)
    vec[2] = np.mean(sizes)
    vec[3] = np.std(sizes)
    vec[4] = np.min(sizes)
    vec[5] = np.max(sizes)
    vec[6] = np.mean(inter) if inter.size else 0.0
    vec[7] = np.std(inter) if inter.size else 0.0
    vec[8] = fwd_sizes.size
    vec[9] = bwd_sizes.size
    vec[10] = np.mean(fwd_sizes) if fwd_sizes.size else 0.0
    vec[11] = np.mean(bwd_sizes) if bwd_sizes.size else 0.0
    vec[12] = np.std(fwd_sizes) if fwd_sizes.size else 0.0
    vec[13] = np.std(bwd_sizes) if bwd_sizes.size else 0.0
    vec[14] = sum(flag_counts.values())
    vec[15] = flag_counts.get(0x02, 0)
    vec[16] = flag_counts.get(0x10, 0)
    vec[17] = flag_counts.get(0x18, 0)
    vec[18] = flag_counts.get(0x04, 0)
    vec[19] = flag_counts.get(0x01, 0)
    if flow.five_tuple:
        vec[20] = float(flow.five_tuple[1])
        vec[21] = float(flow.five_tuple[3])
    vec[22] = 1.0 if flow.pkt_list[0].proto == 6 else 0.0
    return vec