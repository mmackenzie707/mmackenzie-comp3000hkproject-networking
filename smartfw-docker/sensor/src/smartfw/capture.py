from __future__ import annotations
import time, logging, threading, queue
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from .features import Flow
from .config import CAPTURE_IFACE


log = logging.getLogger(__name__)

class CaptureEngine:
    #Produces flow objects with output queue
    def __init__(self, output_queue: "queue.Queue[Flow]") -> None:
        self.out_q = output_queue
        self._table: dict[tuple. Flow] = defaultdict(Flow)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        threading.Thread(target=self._flush_loop, daemon=True).start()
        log.info("Capture engine started")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join()

    
    #scapy callback
    def _handle(self, pkt) -> None:
        if IP not in pkt:
            return
        ip = pkt[IP]
        proto = ip.proto
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            return
        
        #directionless key
        if ip.src < ip.dst:
            key = (ip.src, sport, proto, ip.dst, dport)
            direc = 1
        else:
            key = (ip.dst, dport, proto, ip.src, sport)
            direc = -1
        ts = time.time()
        with self._lock:
            flow = self._table[key]
            if flow.five_tuple is None:
                flow.five_tuple = key
            flow.pkt_list.append(pkt)
            flow.ts_list.append(ts)
            flow.dir_list.append(direc)

    #dataset flushing
    def _flush_loop(self) -> None:
        while self._running:
            time.sleep(60)
            cutoff = time.time() - 60
            with self._lock:
                for key, flow in list(self._table.items()):
                    if flow.ts_list and flow.ts_list[-1] < cutoff:
                        self.out_q.put(flow)
                        del self._table[key]


    def _capture_loop(self) -> None:
        sniff(iface=CAPTURE_IFACE, prn=self._handle, store=False, stop_filter=lambda _: not self._running)