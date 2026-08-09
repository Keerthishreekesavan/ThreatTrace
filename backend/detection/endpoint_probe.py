"""Endpoint probing: one source IP hitting many distinct URL paths and/or
generating a high error-response ratio, or explicitly touching a list of
commonly-attacked sensitive paths (admin panels, config/secret files, path
traversal attempts)."""

from datetime import timedelta

import pandas as pd

from .base import Detection
from .windowing import densest_window, rows_in_window

WINDOW = timedelta(minutes=10)
DISTINCT_PATH_THRESHOLD = 10
ERROR_RATIO_THRESHOLD = 0.5
SUSPICIOUS_PATH_HIT_THRESHOLD = 5
ERROR_STATUS_CODES = {400, 401, 403, 404, 500}

SUSPICIOUS_PATH_PATTERNS = (
    "admin", ".env", "wp-login", "phpmyadmin", ".git", "passwd", "shadow",
    ".bak", "debug", "..", "server-status", "actuator",
)


def _is_suspicious(path: str) -> bool:
    lowered = str(path).lower()
    return any(pattern in lowered for pattern in SUSPICIOUS_PATH_PATTERNS)


def detect(df: pd.DataFrame) -> list[Detection]:
    if not df["request_path"].notna().any():
        return []

    scoped = df[df["source_ip"].notna() & df["timestamp"].notna() & df["request_path"].notna()]
    if scoped.empty:
        return []

    detections = []
    for source_ip, group in scoped.groupby("source_ip"):
        count, start, end = densest_window(group["timestamp"], WINDOW)
        if count == 0:
            continue

        windowed = rows_in_window(group, "timestamp", start, end)
        paths = windowed["request_path"].dropna()
        distinct_paths = paths.nunique()

        error_ratio = 0.0
        if windowed["status_code"].notna().any():
            error_ratio = windowed["status_code"].isin(ERROR_STATUS_CODES).mean()

        suspicious_hits = paths.apply(_is_suspicious).sum()

        triggers_volume = distinct_paths >= DISTINCT_PATH_THRESHOLD and error_ratio >= ERROR_RATIO_THRESHOLD
        triggers_suspicious = suspicious_hits >= SUSPICIOUS_PATH_HIT_THRESHOLD

        if not (triggers_volume or triggers_suspicious):
            continue

        severity = max(
            min(1.0, distinct_paths / (3 * DISTINCT_PATH_THRESHOLD)),
            min(1.0, suspicious_hits / (3 * SUSPICIOUS_PATH_HIT_THRESHOLD)),
        )

        detections.append(Detection(
            detection_type="endpoint_probe",
            source_ip=source_ip,
            window_start=start,
            window_end=end,
            severity=severity,
            evidence={
                "distinct_paths_requested": int(distinct_paths),
                "error_response_ratio": round(float(error_ratio), 2),
                "suspicious_path_hits": int(suspicious_hits),
                "sample_paths": paths.unique().tolist()[:10],
                "window_minutes": WINDOW.total_seconds() / 60,
            },
            event_count=int(len(windowed)),
        ))
    return detections
