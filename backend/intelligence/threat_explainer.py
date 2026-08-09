"""Deterministic, template-based threat explanation generation.

Turns a RiskProfile (detections + evidence + anomaly info) into the
structured "Threat / Evidence / Confidence / Recommendation" shape called
for in the brief - built entirely from the actual evidence data, no
external LLM call, fully reproducible and auditable.
"""

from .risk_engine import RiskProfile

_THREAT_LABELS = {
    "brute_force": "Possible brute-force login attack",
    "credential_spray": "Possible credential spraying attack",
    "port_scan": "Possible port scanning / reconnaissance activity",
    "endpoint_probe": "Possible endpoint or web application probing",
    "unknown_anomaly": "Unclassified behavioural anomaly",
}

_RECOMMENDATIONS = {
    "brute_force": [
        "Temporarily block or rate-limit this source IP",
        "Force a password reset for the targeted account",
        "Review authentication logs for this account over a longer time range",
    ],
    "credential_spray": [
        "Block the source IP temporarily",
        "Review all targeted accounts for signs of compromise",
        "Enforce multi-factor authentication on affected accounts",
        "Check authentication logs for the targeted usernames",
    ],
    "port_scan": [
        "Block or rate-limit the source IP at the firewall",
        "Verify which services are actually exposed on the scanned host(s)",
        "Enable alerting on any follow-up connection attempts from this IP",
    ],
    "endpoint_probe": [
        "Block the source IP or add a WAF rule for the requested paths",
        "Confirm the probed sensitive endpoints are not actually exposed",
        "Review server logs for any request that returned a 2xx response",
    ],
    "unknown_anomaly": [
        "Manually review this IP's full activity history",
        "Correlate with other log sources for additional context",
        "Consider temporary monitoring or throttling pending investigation",
    ],
}

_EVIDENCE_BUILDERS = {
    "brute_force": lambda d: (
        f"{d.evidence['failed_attempts_in_window']} failed authentication attempts "
        f"against user '{d.evidence['target_username']}' within "
        f"{d.evidence['window_minutes']:.0f} minutes"
    ),
    "credential_spray": lambda d: (
        f"Contacted {d.evidence['distinct_usernames_targeted']} distinct user accounts "
        f"with {d.evidence['total_failed_attempts']} failed attempts "
        f"({d.evidence['avg_attempts_per_user']} attempts/user on average) "
        f"within {d.evidence['window_minutes']:.0f} minutes"
    ),
    "port_scan": lambda d: (
        f"Contacted {d.evidence['distinct_ports_contacted']} distinct ports on "
        f"{len(d.evidence['target_hosts'])} host(s) within {d.evidence['window_minutes']:.0f} minutes"
        + (" (sequential scan pattern detected)" if d.evidence["sequential_pattern"] else "")
    ),
    "endpoint_probe": lambda d: (
        f"Requested {d.evidence['distinct_paths_requested']} distinct paths with a "
        f"{d.evidence['error_response_ratio'] * 100:.0f}% error-response rate"
        + (f", including {d.evidence['suspicious_path_hits']} hits on known-sensitive paths"
           if d.evidence["suspicious_path_hits"] else "")
    ),
    "unknown_anomaly": lambda d: (
        "Behaviour differs from the normal baseline for this dataset "
        f"(anomaly score {d.evidence['anomaly_score'] * 100:.0f}%), notably in: "
        + ", ".join(f["feature"].replace("_", " ") for f in d.evidence["deviating_features"])
    ),
}


def explain(profile: RiskProfile) -> dict:
    if profile.detections:
        dominant = max(profile.detections, key=lambda d: d.severity)
        threat_types = sorted({d.detection_type for d in profile.detections})
        if len(threat_types) > 1:
            threat = "Multiple threat indicators: " + ", ".join(
                _THREAT_LABELS[t] for t in threat_types
            )
        else:
            threat = _THREAT_LABELS[dominant.detection_type]
        recommendations = _RECOMMENDATIONS[dominant.detection_type]
    else:
        threat = "No rule-based threat matched; flagged purely on behavioural anomaly"
        recommendations = _RECOMMENDATIONS["unknown_anomaly"]

    evidence_lines = []
    for d in profile.detections:
        builder = _EVIDENCE_BUILDERS.get(d.detection_type)
        if builder:
            evidence_lines.append(f"IP {profile.source_ip}: {builder(d)}")

    if profile.components["behavior_anomaly"] >= 0.4 and not any(
        d.detection_type == "unknown_anomaly" for d in profile.detections
    ):
        top_features = profile.anomaly_info.get("top_features", [])
        if top_features:
            feature_names = ", ".join(f["feature"].replace("_", " ") for f in top_features)
            evidence_lines.append(
                f"Activity differs from the dataset's normal baseline, notably in: {feature_names}"
            )

    reason_parts = []
    if profile.components["threat_severity"] > 0:
        reason_parts.append("rule-based threat indicators")
    if profile.components["behavior_anomaly"] >= 0.4:
        reason_parts.append("abnormal behavioural profile")
    if profile.components["frequency"] >= 0.6:
        reason_parts.append("high event volume")
    reason = (
        ("Elevated risk driven by " + " and ".join(reason_parts) + ".")
        if reason_parts else "Low overall risk indicators."
    )

    return {
        "source_ip": profile.source_ip,
        "threat": threat,
        "evidence": evidence_lines,
        "confidence": round(profile.components["confidence"] * 100, 1),
        "risk_score": profile.risk_score,
        "classification": profile.classification,
        "reason": reason,
        "recommendation": recommendations,
    }
