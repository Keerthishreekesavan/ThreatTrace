"""Brute force: many failed authentication attempts against the same
(source IP, username) pair in a short window. Falls back to grouping by
source IP alone when the dataset has no username field."""

from datetime import timedelta

import pandas as pd

from .base import Detection
from .windowing import densest_window, rows_in_window

WINDOW = timedelta(minutes=10)
THRESHOLD = 8


def detect(df: pd.DataFrame) -> list[Detection]:
    failed = df[(df["failed_attempts"].fillna(0) >= 1) & df["source_ip"].notna() & df["timestamp"].notna()]
    if failed.empty:
        return []

    has_username = df["username"].notna().any()
    group_cols = ["source_ip", "username"] if has_username else ["source_ip"]

    detections = []
    for key, group in failed.groupby(group_cols, dropna=False):
        if has_username and pd.isna(key[1]):
            continue  # unattributed failures handled implicitly by IP-level view elsewhere
        source_ip = key[0] if isinstance(key, tuple) else key
        username = key[1] if has_username and isinstance(key, tuple) else None

        count, start, end = densest_window(group["timestamp"], WINDOW)
        if count < THRESHOLD:
            continue

        severity = min(1.0, count / (3 * THRESHOLD))
        detections.append(Detection(
            detection_type="brute_force",
            source_ip=source_ip,
            window_start=start,
            window_end=end,
            severity=severity,
            evidence={
                "failed_attempts_in_window": int(count),
                "target_username": username or "unattributed",
                "window_minutes": WINDOW.total_seconds() / 60,
            },
            targeted_usernames=[username] if username else [],
            event_count=int(count),
        ))
    return detections
