"""End-to-end validation: for each of the 3 differently-shaped sample
datasets, run ingestion -> normalization -> detection -> risk scoring, and
check that every attacker IP recorded in the corresponding ground-truth
fixture was actually flagged with a matching detection type (or, for the
`unknown_anomaly` scenario, caught by the anomaly detector instead of a
rule - that's the point of that scenario)."""

import json
from pathlib import Path

import pytest

from detection import run_all_detectors
from ingestion.loader import load_dataset
from ingestion.normalizer import normalize
from ingestion.schema_mapper import map_columns
from intelligence.risk_engine import compute_risk_profiles
from intelligence.threat_explainer import explain

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "data" / "samples"

DATASETS = [
    ("auth_logs_a.csv", "auth_logs_a.ground_truth.json"),
    ("web_logs_b.json", "web_logs_b.ground_truth.json"),
    ("network_logs_c.csv", "network_logs_c.ground_truth.json"),
]


@pytest.mark.parametrize("data_file,gt_file", DATASETS)
def test_pipeline_detects_ground_truth_attackers(data_file, gt_file):
    raw_df = load_dataset(SAMPLES_DIR / data_file)
    mappings = map_columns(raw_df)
    canonical_df = normalize(raw_df, mappings)

    detections, anomaly_scores = run_all_detectors(canonical_df)
    avg_confidence = sum(m.confidence for m in mappings) / len(mappings)
    profiles = compute_risk_profiles(canonical_df, detections, anomaly_scores, avg_confidence)
    profiles_by_ip = {p.source_ip: p for p in profiles}

    ground_truth = json.loads((SAMPLES_DIR / gt_file).read_text())

    missed = []
    for ip, info in ground_truth.items():
        expected_type = info["attack_type"]
        profile = profiles_by_ip.get(ip)
        if profile is None:
            missed.append((ip, expected_type, "not flagged at all"))
            continue
        found_types = {d.detection_type for d in profile.detections}
        if expected_type not in found_types:
            missed.append((ip, expected_type, f"flagged, but as {found_types or 'no rule match'}"))

    assert not missed, f"Ground-truth attackers not correctly detected: {missed}"


@pytest.mark.parametrize("data_file,gt_file", DATASETS)
def test_explanations_are_well_formed(data_file, gt_file):
    raw_df = load_dataset(SAMPLES_DIR / data_file)
    mappings = map_columns(raw_df)
    canonical_df = normalize(raw_df, mappings)
    detections, anomaly_scores = run_all_detectors(canonical_df)
    avg_confidence = sum(m.confidence for m in mappings) / len(mappings)
    profiles = compute_risk_profiles(canonical_df, detections, anomaly_scores, avg_confidence)

    assert profiles, "expected at least one flagged IP"
    for profile in profiles:
        result = explain(profile)
        assert result["threat"]
        assert 0 <= result["risk_score"] <= 100
        assert result["classification"] in {"Low", "Medium", "High", "Critical"}
        assert result["recommendation"]


def test_no_unmapped_core_fields_for_dataset_a():
    """auth_logs_a.csv uses the exact column names from the brief's own
    example - source_ip/destination_ip/failed_attempts/timestamp should map
    with high confidence and require no semantic inference at all."""
    raw_df = load_dataset(SAMPLES_DIR / "auth_logs_a.csv")
    mappings = map_columns(raw_df)
    mapped = {m.column_name: m.mapped_field for m in mappings}
    assert mapped["source_ip"] == "source_ip"
    assert mapped["destination_ip"] == "destination_ip"
    assert mapped["failed_attempts"] == "failed_attempts"
    assert mapped["timestamp"] == "timestamp"


def test_renamed_columns_map_to_same_concepts_across_datasets():
    """The core claim of the project: differently-named columns across
    datasets B and C resolve to the same canonical concepts as dataset A."""
    df_b = load_dataset(SAMPLES_DIR / "web_logs_b.json")
    df_c = load_dataset(SAMPLES_DIR / "network_logs_c.csv")

    mapped_b = {m.column_name: m.mapped_field for m in map_columns(df_b)}
    mapped_c = {m.column_name: m.mapped_field for m in map_columns(df_c)}

    assert mapped_b["src_addr"] == "source_ip"
    assert mapped_b["dst_host"] == "destination_ip"
    assert mapped_b["login_fail"] == "failed_attempts"
    assert mapped_b["event_time"] == "timestamp"

    assert mapped_c["client_ip"] == "source_ip"
    assert mapped_c["server_ip"] == "destination_ip"
    assert mapped_c["authentication_errors"] == "failed_attempts"
    assert mapped_c["created_at"] == "timestamp"
