"""Unsupervised behavioural anomaly detection via Isolation Forest.

Builds one feature vector per source IP summarizing its behaviour across the
whole ingested dataset, fits an Isolation Forest, and returns a normalized
0-1 anomaly score per IP plus the features that deviate most from the
population baseline (for explainability). This score feeds two things:

1. `intelligence/risk_engine.py` uses it as the "behaviour anomaly" component
   of the risk score for *every* IP, rule-hit or not.
2. `detect_unknown_anomalies` below turns it into standalone Detection
   records for IPs that are statistically anomalous but did not trip any of
   the four rule-based detectors - the "unknown behavioural anomaly" class
   the brief calls for.
"""

from datetime import timedelta

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .base import Detection

FEATURE_NAMES = [
    "event_count",
    "failed_ratio",
    "distinct_ports",
    "distinct_destinations",
    "distinct_paths",
    "distinct_usernames",
    "avg_payload_size",
    "off_hours_ratio",
]

UNKNOWN_ANOMALY_THRESHOLD = 0.7


def _build_features(df: pd.DataFrame) -> pd.DataFrame:
    scoped = df[df["source_ip"].notna()]
    rows = []
    for source_ip, group in scoped.groupby("source_ip"):
        event_count = len(group)
        failed_ratio = group["failed_attempts"].fillna(0).clip(upper=1).mean()
        distinct_ports = group["port"].nunique()
        distinct_destinations = group["destination_ip"].nunique()
        distinct_paths = group["request_path"].nunique()
        distinct_usernames = group["username"].nunique()
        avg_payload_size = group["payload_size"].fillna(0).mean()

        off_hours_ratio = 0.0
        if group["timestamp"].notna().any():
            hours = group["timestamp"].dt.hour
            off_hours_ratio = ((hours < 6) | (hours >= 22)).mean()

        rows.append({
            "source_ip": source_ip,
            "event_count": event_count,
            "failed_ratio": failed_ratio,
            "distinct_ports": distinct_ports,
            "distinct_destinations": distinct_destinations,
            "distinct_paths": distinct_paths,
            "distinct_usernames": distinct_usernames,
            "avg_payload_size": avg_payload_size,
            "off_hours_ratio": off_hours_ratio,
        })

    if not rows:
        # No usable source IPs: either the dataset has no source-IP column at
        # all, or every value in it is null. Return an empty but correctly
        # shaped frame so callers can treat this as "nothing to score"
        # instead of hitting a set_index KeyError.
        return pd.DataFrame(columns=["source_ip", *FEATURE_NAMES]).set_index("source_ip")

    return pd.DataFrame(rows).set_index("source_ip")


def compute_anomaly_scores(df: pd.DataFrame) -> dict[str, dict]:
    features = _build_features(df)
    if len(features) < 8:
        # Isolation Forest needs a reasonable population to define "normal"
        return {ip: {"anomaly_score": 0.0, "top_features": []} for ip in features.index}

    matrix = features[FEATURE_NAMES].fillna(0).to_numpy()
    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)

    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(scaled)
    raw_scores = -model.decision_function(scaled)  # higher = more anomalous

    lo, hi = raw_scores.min(), raw_scores.max()
    normalized = (raw_scores - lo) / (hi - lo) if hi > lo else np.zeros_like(raw_scores)

    z_scores = np.abs(scaled)  # scaled features are already ~z-scores post-standardization

    results = {}
    for i, ip in enumerate(features.index):
        top_idx = np.argsort(-z_scores[i])[:3]
        results[ip] = {
            "anomaly_score": round(float(normalized[i]), 4),
            "top_features": [
                {"feature": FEATURE_NAMES[j], "value": round(float(matrix[i, j]), 2)}
                for j in top_idx
            ],
        }
    return results


def detect_unknown_anomalies(df: pd.DataFrame, already_flagged_ips: set[str]) -> list[Detection]:
    scores = compute_anomaly_scores(df)
    detections = []
    for ip, info in scores.items():
        if ip in already_flagged_ips or info["anomaly_score"] < UNKNOWN_ANOMALY_THRESHOLD:
            continue

        ip_events = df[df["source_ip"] == ip]
        timestamps = ip_events["timestamp"].dropna()
        window_start = timestamps.min() if not timestamps.empty else None
        window_end = timestamps.max() if not timestamps.empty else None

        detections.append(Detection(
            detection_type="unknown_anomaly",
            source_ip=ip,
            window_start=window_start,
            window_end=window_end,
            severity=info["anomaly_score"],
            evidence={
                "anomaly_score": info["anomaly_score"],
                "deviating_features": info["top_features"],
                "note": "Behaviour differs from baseline but did not match a known attack signature.",
            },
            event_count=len(ip_events),
        ))
    return detections
