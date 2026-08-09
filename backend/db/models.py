"""SQLAlchemy models. A `Dataset` is one uploaded/ingested log file; every
downstream table hangs off it so the dashboard can hold multiple analyses
and let an analyst switch between them."""

from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Dataset(Base):
    __tablename__ = "datasets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC).replace(tzinfo=None)
    )
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    mapping_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    unmapped_columns: Mapped[list] = mapped_column(JSON, default=list)

    # Path to the retained copy of the uploaded file. Re-running the analysis
    # after an analyst corrects a column mapping needs the original raw data -
    # the canonical events alone can't be un-normalized.
    source_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Analyst-supplied column -> canonical field corrections, e.g.
    # {"status": "failed_attempts", "request_count": null}. A null value means
    # "force this column to stay unmapped". Kept so the mapping is reproducible
    # and the UI can show which fields were set by hand.
    overrides: Mapped[dict] = mapped_column(JSON, default=dict)

    events: Mapped[list["Event"]] = relationship(back_populates="dataset", cascade="all, delete-orphan")
    detections: Mapped[list["DetectionRecord"]] = relationship(back_populates="dataset", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="dataset", cascade="all, delete-orphan")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"))

    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failed_attempts: Mapped[float | None] = mapped_column(Float, nullable=True)
    port: Mapped[float | None] = mapped_column(Float, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    request_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[float | None] = mapped_column(Float, nullable=True)
    payload_size: Mapped[float | None] = mapped_column(Float, nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    extra_fields: Mapped[str | None] = mapped_column(Text, nullable=True)

    dataset: Mapped["Dataset"] = relationship(back_populates="events")


class DetectionRecord(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"))

    detection_type: Mapped[str] = mapped_column(String(64))
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    window_start: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    severity: Mapped[float] = mapped_column(Float)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    targeted_usernames: Mapped[list] = mapped_column(JSON, default=list)

    dataset: Mapped["Dataset"] = relationship(back_populates="detections")


class Alert(Base):
    """One risk profile per (dataset, source_ip) - the investigation-view unit."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"))

    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    classification: Mapped[str] = mapped_column(String(16))
    components: Mapped[dict] = mapped_column(JSON, default=dict)
    threat: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float)
    reason: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[list] = mapped_column(JSON, default=list)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    country: Mapped[str | None] = mapped_column(String(128), nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(8), nullable=True)
    lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    lon: Mapped[float | None] = mapped_column(Float, nullable=True)

    dataset: Mapped["Dataset"] = relationship(back_populates="alerts")
