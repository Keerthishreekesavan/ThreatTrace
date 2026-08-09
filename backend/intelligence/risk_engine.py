"""Deterministic 0-100 risk scoring.

score = 100 * (0.40 * threat_severity + 0.30 * behaviour_anomaly
             + 0.15 * frequency       + 0.15 * confidence)

All four components are normalized to 0-1 before weighting so the formula
itself stays simple and auditable - exactly what you want in a security
tool where an analyst may need to justify why an IP was scored the way it
was.
"""

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from detection.base import Detection

WEIGHTS = {
    "threat_severity": 0.40,
    "behavior_anomaly": 0.30,
    "frequency": 0.15,
    "confidence": 0.15,
}

CLASSIFICATION_BANDS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (0, "Low"),
]


def classify(score: float) -> str:
    for threshold, label in CLASSIFICATION_BANDS:
        if score >= threshold:
            return label
    return "Low"


@dataclass
class RiskProfile:
    source_ip: str
    risk_score: float
    classification: str
    components: dict
    detections: list[Detection] = field(default_factory=list)
    anomaly_info: dict = field(default_factory=dict)
    event_count: int = 0


def _frequency_component(event_count: int, max_event_count: int) -> float:
    if max_event_count <= 0:
        return 0.0
    return float(np.log1p(event_count) / np.log1p(max_event_count))


def _confidence_component(event_count: int, avg_mapping_confidence: float) -> float:
    evidence_volume_confidence = min(1.0, event_count / 20)
    return 0.6 * evidence_volume_confidence + 0.4 * avg_mapping_confidence


def compute_risk_profiles(
    df: pd.DataFrame,
    detections: list[Detection],
    anomaly_scores: dict[str, dict],
    avg_mapping_confidence: float,
) -> list[RiskProfile]:
    detections_by_ip: dict[str, list[Detection]] = {}
    for d in detections:
        detections_by_ip.setdefault(d.source_ip, []).append(d)

    event_counts = df["source_ip"].value_counts()
    max_event_count = int(event_counts.max()) if not event_counts.empty else 0

    # Every IP with at least one detection OR a meaningful anomaly score gets
    # a risk profile - a totally quiet, unremarkable IP doesn't need one.
    candidate_ips = set(detections_by_ip) | {
        ip for ip, info in anomaly_scores.items() if info.get("anomaly_score", 0) >= 0.4
    }

    profiles = []
    for ip in candidate_ips:
        ip_detections = detections_by_ip.get(ip, [])
        anomaly_info = anomaly_scores.get(ip, {"anomaly_score": 0.0, "top_features": []})
        event_count = int(event_counts.get(ip, 0))

        threat_severity = max((d.severity for d in ip_detections), default=0.0)
        behavior_anomaly = anomaly_info.get("anomaly_score", 0.0)
        frequency = _frequency_component(event_count, max_event_count)
        confidence = _confidence_component(event_count, avg_mapping_confidence)

        components = {
            "threat_severity": round(threat_severity, 4),
            "behavior_anomaly": round(behavior_anomaly, 4),
            "frequency": round(frequency, 4),
            "confidence": round(confidence, 4),
        }
        risk_score = 100 * sum(WEIGHTS[k] * components[k] for k in WEIGHTS)

        profiles.append(RiskProfile(
            source_ip=ip,
            risk_score=round(risk_score, 1),
            classification=classify(risk_score),
            components=components,
            detections=ip_detections,
            anomaly_info=anomaly_info,
            event_count=event_count,
        ))

    profiles.sort(key=lambda p: p.risk_score, reverse=True)
    return profiles
