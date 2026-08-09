"""Credential spraying: one source IP racking up failed authentication
attempts against many distinct usernames in a short window, typically with
few attempts per user (distinguishing it from a focused brute force)."""

from datetime import timedelta

import pandas as pd

from .base import Detection
from .windowing import densest_window, rows_in_window

WINDOW = timedelta(minutes=10)
DISTINCT_USER_THRESHOLD = 8


def detect(df: pd.DataFrame) -> list[Detection]:
    if not df["username"].notna().any():
        return []  # dataset has no user identity field - spraying isn't observable

    failed = df[(df["failed_attempts"].fillna(0) >= 1) & df["source_ip"].notna() & df["timestamp"].notna()]
    if failed.empty:
        return []

    detections = []
    for source_ip, group in failed.groupby("source_ip"):
        count, start, end = densest_window(group["timestamp"], WINDOW)
        if count == 0:
            continue

        windowed = rows_in_window(group, "timestamp", start, end)
        distinct_users = windowed["username"].dropna().unique().tolist()

        if len(distinct_users) < DISTINCT_USER_THRESHOLD:
            continue

        attempts_per_user = len(windowed) / max(len(distinct_users), 1)
        severity = min(1.0, len(distinct_users) / (3 * DISTINCT_USER_THRESHOLD))

        detections.append(Detection(
            detection_type="credential_spray",
            source_ip=source_ip,
            window_start=start,
            window_end=end,
            severity=severity,
            evidence={
                "distinct_usernames_targeted": len(distinct_users),
                "total_failed_attempts": int(len(windowed)),
                "avg_attempts_per_user": round(attempts_per_user, 2),
                "window_minutes": WINDOW.total_seconds() / 60,
                "sample_targeted_usernames": distinct_users[:10],
            },
            targeted_usernames=distinct_users,
            event_count=int(len(windowed)),
        ))
    return detections
