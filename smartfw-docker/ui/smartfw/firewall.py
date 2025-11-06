from __future__ import annotations
import time, logging, subprocess, threading
from ipaddress import ip_address, ip_network
from .config import BLOCK_TIME_SEC, WHITELIST


log = logging.getLogger(__name__)


class Firewall:
    def __init__(self) -> None:
        self.blocked: dict[str, float] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        threading.Thread(target=self._unblock_loop, daemon=True).start()

    def block(self, ip: str) -> None:
        if self._whitelisted(ip):
            return
        with self._lock:
            self._blocked[ip] = time.time() + BLOCK_TIME_SEC
        self._iptables(ip, True)
        log.warning("Blocked %s", ip)

    #Internals Parts
    def _whitelisted(self, ip: str) -> bool:
        try:
            ip_obj = ip_address(ip)
            for net in WHITELIST:
                if ip_obj in ip_network(net, strict=False):
                    return True
            return False
        except ValueError:
            return False
        
    def _iptables(self, ip: str, add: bool) -> None:
        rule = ["iptables", "-I" if add else "-D", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            subprocess.run(rule, check=True, stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            log.error("iptables %s failed: %s", rule, e)

    def _unblock_loop(self) -> None:
        while True:
            time.sleep(5)
            now = time.time()
            with self._lock:
                for ip, t in list(self._blocked.items()):
                    if now >= t:
                        self._iptables(ip, False)
                        del self._blocked[ip]
                        log.info("Unblocked %s", ip)