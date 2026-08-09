"""Runs every detector against a normalized event DataFrame and returns a
single combined list of Detection records, including behavioural-anomaly
scores merged onto every IP (not just ones with rule hits) for use by the
risk engine."""

import pandas as pd

from . import brute_force, credential_spray, endpoint_probe, port_scan
from .anomaly_detector import compute_anomaly_scores, detect_unknown_anomalies
from .base import Detection

RULE_DETECTORS = [brute_force, credential_spray, port_scan, endpoint_probe]


def run_all_detectors(df: pd.DataFrame) -> tuple[list[Detection], dict[str, dict]]:
    # Every detector and the anomaly model group by source IP, so without one
    # there is nothing any of them can attribute a finding to. This is a
    # legitimate outcome for a non-security dataset (or a log whose source-IP
    # column wasn't recognized), not an error - report zero findings rather
    # than failing the upload.
    if "source_ip" not in df.columns or df["source_ip"].isna().all():
        return [], {}

    rule_detections: list[Detection] = []
    for module in RULE_DETECTORS:
        rule_detections.extend(module.detect(df))

    flagged_ips = {d.source_ip for d in rule_detections}
    anomaly_scores = compute_anomaly_scores(df)
    unknown_detections = detect_unknown_anomalies(df, flagged_ips)

    return rule_detections + unknown_detections, anomaly_scores
