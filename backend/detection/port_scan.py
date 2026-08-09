"""Port scanning: one source IP contacting many distinct destination ports
in a short window. Near-sequential port activity is flagged as an extra
signal since it's characteristic of automated scanners (nmap-style sweeps)
rather than organic traffic."""

from datetime import timedelta

import pandas as pd

from .base import Detection
from .windowing import densest_window, rows_in_window

WINDOW = timedelta(minutes=5)
DISTINCT_PORT_THRESHOLD = 15


def _sequential_ratio(ports: list[int]) -> float:
    if len(ports) < 2:
        return 0.0
    ordered = sorted(ports)
    close_gaps = sum(1 for a, b in zip(ordered, ordered[1:]) if b - a <= 3)
    return close_gaps / (len(ordered) - 1)


def detect(df: pd.DataFrame) -> list[Detection]:
    if not df["port"].notna().any():
        return []

    scoped = df[df["source_ip"].notna() & df["timestamp"].notna() & df["port"].notna()]
    if scoped.empty:
        return []

    detections = []
    for source_ip, group in scoped.groupby("source_ip"):
        count, start, end = densest_window(group["timestamp"], WINDOW)
        if count == 0:
            continue

        windowed = rows_in_window(group, "timestamp", start, end)
        ports = windowed["port"].dropna().astype(int).unique().tolist()

        if len(ports) < DISTINCT_PORT_THRESHOLD:
            continue

        seq_ratio = _sequential_ratio(ports)
        severity = min(1.0, len(ports) / (3 * DISTINCT_PORT_THRESHOLD))
        targets = windowed["destination_ip"].dropna().unique().tolist()

        detections.append(Detection(
            detection_type="port_scan",
            source_ip=source_ip,
            window_start=start,
            window_end=end,
            severity=severity,
            evidence={
                "distinct_ports_contacted": len(ports),
                "target_hosts": targets[:10],
                "sequential_pattern": seq_ratio >= 0.6,
                "sequential_ratio": round(seq_ratio, 2),
                "window_minutes": WINDOW.total_seconds() / 60,
            },
            event_count=int(len(windowed)),
        ))
    return detections
