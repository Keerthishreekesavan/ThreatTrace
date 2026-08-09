"""Orchestrates the full ingest -> normalize -> detect -> score -> explain
pipeline and persists every stage's output, so the dashboard can later query
raw events, detections, and alerts independently without re-running anything.

The same routine backs both the initial upload and a re-analysis after an
analyst corrects a column mapping - re-analysis simply replays it against the
retained raw file with `overrides` applied.
"""

import shutil
from pathlib import Path
from uuid import uuid4

import pandas as pd
from sqlalchemy import delete
from sqlalchemy.orm import Session

from db.models import Alert, DetectionRecord, Dataset, Event
from detection import run_all_detectors
from geoip.geoip_lookup import lookup as geoip_lookup
from ingestion.loader import load_dataset
from ingestion.normalizer import normalize
from ingestion.schema_mapper import map_columns
from intelligence.risk_engine import compute_risk_profiles
from intelligence.threat_explainer import explain

UPLOAD_DIR = Path(__file__).resolve().parents[2] / "data" / "uploads"


class SourceFileMissingError(FileNotFoundError):
    """The retained upload is gone, so the dataset can't be re-analyzed."""


def _row_value(value):
    if pd.isna(value):
        return None
    return value


def _retain_upload(filename: str, filepath: Path) -> str:
    """Keeps a copy of the raw upload so the analysis can be re-run later with
    corrected column mappings. Returns the stored path."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    suffix = Path(filename).suffix.lower() or filepath.suffix.lower()
    stored = UPLOAD_DIR / f"{uuid4().hex}{suffix}"
    shutil.copyfile(filepath, stored)
    return str(stored)


def _analyze(db: Session, dataset: Dataset, filepath: Path, overrides: dict) -> Dataset:
    """Runs the pipeline against `filepath` and writes every stage onto
    `dataset`, which must already be persisted (have an id)."""
    raw_df = load_dataset(filepath)
    mappings = map_columns(raw_df, overrides=overrides)
    canonical_df = normalize(raw_df, mappings)

    dataset.row_count = len(canonical_df)
    dataset.mapping_summary = canonical_df.attrs.get("mapping_summary", {})
    dataset.unmapped_columns = canonical_df.attrs.get("unmapped_columns", [])
    dataset.overrides = overrides

    for _, row in canonical_df.iterrows():
        source_location = _row_value(row.get("source_location"))
        source_ip = _row_value(row.get("source_ip"))
        if source_location is None and source_ip is not None:
            source_location = geoip_lookup(source_ip)["country"]

        db.add(Event(
            dataset_id=dataset.id,
            source_ip=source_ip,
            destination_ip=_row_value(row.get("destination_ip")),
            timestamp=_row_value(row.get("timestamp")),
            username=_row_value(row.get("username")),
            event_type=_row_value(row.get("event_type")),
            failed_attempts=_row_value(row.get("failed_attempts")),
            port=_row_value(row.get("port")),
            protocol=_row_value(row.get("protocol")),
            request_path=_row_value(row.get("request_path")),
            status_code=_row_value(row.get("status_code")),
            payload_size=_row_value(row.get("payload_size")),
            device_id=_row_value(row.get("device_id")),
            source_location=source_location,
            extra_fields=_row_value(row.get("extra_fields")),
        ))

    detections, anomaly_scores = run_all_detectors(canonical_df)
    avg_confidence = (
        sum(m.confidence for m in mappings) / len(mappings) if mappings else 0.0
    )
    profiles = compute_risk_profiles(canonical_df, detections, anomaly_scores, avg_confidence)

    for d in detections:
        db.add(DetectionRecord(
            dataset_id=dataset.id,
            detection_type=d.detection_type,
            source_ip=d.source_ip,
            window_start=d.window_start,
            window_end=d.window_end,
            severity=d.severity,
            event_count=d.event_count,
            evidence=d.evidence,
            targeted_usernames=d.targeted_usernames,
        ))

    for profile in profiles:
        explanation = explain(profile)
        geo = geoip_lookup(profile.source_ip)
        db.add(Alert(
            dataset_id=dataset.id,
            source_ip=profile.source_ip,
            risk_score=profile.risk_score,
            classification=profile.classification,
            components=profile.components,
            threat=explanation["threat"],
            evidence=explanation["evidence"],
            confidence=explanation["confidence"],
            reason=explanation["reason"],
            recommendation=explanation["recommendation"],
            event_count=profile.event_count,
            country=geo["country"],
            country_code=geo["country_code"],
            lat=geo["lat"],
            lon=geo["lon"],
        ))

    db.commit()
    db.refresh(dataset)
    return dataset


def run_pipeline_and_persist(db: Session, filename: str, filepath: Path) -> Dataset:
    dataset = Dataset(
        filename=filename,
        source_path=_retain_upload(filename, filepath),
        overrides={},
    )
    db.add(dataset)
    db.flush()
    return _analyze(db, dataset, filepath, {})


def reanalyze_dataset(db: Session, dataset: Dataset, overrides: dict) -> Dataset:
    """Re-runs the analysis with analyst-corrected column mappings.

    Everything derived from the old mapping (events, detections, alerts) is
    deleted first, so results can never be a mix of two mappings.
    """
    if not dataset.source_path or not Path(dataset.source_path).exists():
        raise SourceFileMissingError(
            f"The retained copy of '{dataset.filename}' is no longer available, "
            "so it can't be re-analyzed. Re-upload the file to correct its mapping."
        )

    for model in (Event, DetectionRecord, Alert):
        db.execute(delete(model).where(model.dataset_id == dataset.id))
    db.flush()

    return _analyze(db, dataset, Path(dataset.source_path), overrides)
