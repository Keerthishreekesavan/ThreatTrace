"""Pydantic response models for the API surface."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ColumnMappingOut(BaseModel):
    column_name: str
    mapped_field: str | None
    confidence: float
    source: str = "inferred"
    inferred_dtype: str | None = None
    sample_values: list[str] = []


class OntologyFieldOut(BaseModel):
    key: str
    display_name: str
    description: str
    expected_dtype: str


class SchemaOverrideIn(BaseModel):
    """Analyst corrections: column name -> canonical field key, or null to force
    the column to stay unmapped."""

    overrides: dict[str, str | None]


class DatasetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    uploaded_at: datetime
    row_count: int
    unmapped_columns: list


class DatasetDetailOut(DatasetOut):
    mapping_summary: dict
    overrides: dict = {}


class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    detection_type: str
    source_ip: str
    window_start: datetime | None
    window_end: datetime | None
    severity: float
    event_count: int
    evidence: dict
    targeted_usernames: list


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_ip: str
    risk_score: float
    classification: str
    components: dict
    threat: str
    evidence: list
    confidence: float
    reason: str
    recommendation: list
    event_count: int
    country: str | None
    country_code: str | None
    lat: float | None
    lon: float | None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_ip: str | None
    destination_ip: str | None
    timestamp: datetime | None
    username: str | None
    event_type: str | None
    failed_attempts: float | None
    port: float | None
    protocol: str | None
    request_path: str | None
    status_code: float | None
    payload_size: float | None
    device_id: str | None
    source_location: str | None
    extra_fields: str | None


class OverviewOut(BaseModel):
    dataset_id: int
    total_events: int
    threats_detected: int
    critical_alerts: int
    unique_source_ips: int
    risk_distribution: dict[str, int]
    detection_type_counts: dict[str, int]


class TimelinePoint(BaseModel):
    bucket: datetime
    total_events: int
    detection_counts: dict[str, int]


class TimelineOut(BaseModel):
    dataset_id: int
    bucket_minutes: int
    points: list[TimelinePoint]


class AttackProgressionStep(BaseModel):
    detection_type: str
    window_start: datetime | None
    window_end: datetime | None
    severity: float
    event_count: int


class IpInvestigationOut(BaseModel):
    source_ip: str
    alert: AlertOut | None
    detections: list[DetectionOut]
    attack_progression: list[AttackProgressionStep]
    related_events: list[EventOut]
    total_events: int


class AnalyticsOut(BaseModel):
    dataset_id: int
    top_malicious_ips: list[AlertOut]
    attack_categories: dict[str, int]
    geographic_distribution: list[dict]
    behaviour_anomalies: list[AlertOut]
