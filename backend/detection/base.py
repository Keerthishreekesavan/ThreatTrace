"""Shared types used by every detection module."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Detection:
    detection_type: str          # "brute_force" | "credential_spray" | "port_scan" | "endpoint_probe" | "unknown_anomaly"
    source_ip: str
    window_start: datetime | None
    window_end: datetime | None
    severity: float               # 0-1, how far over threshold / how anomalous
    evidence: dict = field(default_factory=dict)
    targeted_usernames: list[str] = field(default_factory=list)
    event_count: int = 0
