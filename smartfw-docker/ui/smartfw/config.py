from __future__ import annotations
import os
from ipaddress import ip_network
from typing import Set

MODEL_PATH: str = os.getenv("SMARTFW_MODEL", "/var/lib/smartfw/model.joblib")
SCALER_PATH: str = os.getenv("SMARTFW_SCALER", "/var/lib/smartfw/scaler.joblib")
LOG_PATH: str = os.getenv("SMARTFW_LOG", "/var/log/smartfw/features.csv")

BLOCK_TIME_SEC: int = int(os.getenv("SMARTFW_BLOCK_TIME", "300"))
THRESHOLD: float = float(os.getenv("SMARTFW_THRESHOLD", "-0.25"))
CUT_OFF: float = float(os.getenv("SMARTFW_CUT_OFF", "0.80"))
RETRAIN_INTERVAL_SEC: int = int(os.getenv("SMARTFW_RETRAIN", "86400"))
CAPTURE_IFACE: str = os.getenv("SMARTFW_IFACE")


#CIDR strings that will never be blocked
WHITELIST: Set[str] = {
    "127.0.0.0/8",
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "::1/128"
}