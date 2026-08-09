"""Overview, timeline, investigation, and analytics endpoints - the four
views the SOC dashboard is built from."""

from collections import Counter, defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.schemas import (
    AlertOut,
    AnalyticsOut,
    AttackProgressionStep,
    DetectionOut,
    EventOut,
    IpInvestigationOut,
    OverviewOut,
    TimelineOut,
    TimelinePoint,
)
from db.models import Alert, Dataset, DetectionRecord, Event
from db.session import get_db

router = APIRouter(prefix="/api/datasets/{dataset_id}", tags=["analysis"])


def _require_dataset(db: Session, dataset_id: int) -> Dataset:
    dataset = db.get(Dataset, dataset_id)
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    return dataset


@router.get("/overview", response_model=OverviewOut)
def get_overview(dataset_id: int, db: Session = Depends(get_db)):
    _require_dataset(db, dataset_id)

    total_events = db.scalar(
        select(func.count(Event.id)).where(Event.dataset_id == dataset_id)
    ) or 0
    unique_ips = db.scalar(
        select(func.count(func.distinct(Event.source_ip))).where(Event.dataset_id == dataset_id)
    ) or 0

    alerts = db.scalars(select(Alert).where(Alert.dataset_id == dataset_id)).all()
    detections = db.scalars(
        select(DetectionRecord).where(DetectionRecord.dataset_id == dataset_id)
    ).all()

    risk_distribution = Counter(a.classification for a in alerts)
    detection_counts = Counter(d.detection_type for d in detections)

    return OverviewOut(
        dataset_id=dataset_id,
        total_events=total_events,
        threats_detected=len(detections),
        critical_alerts=risk_distribution.get("Critical", 0),
        unique_source_ips=unique_ips,
        risk_distribution={
            level: risk_distribution.get(level, 0)
            for level in ("Critical", "High", "Medium", "Low")
        },
        detection_type_counts=dict(detection_counts),
    )


@router.get("/timeline", response_model=TimelineOut)
def get_timeline(
    dataset_id: int,
    bucket_minutes: int = Query(default=30, ge=1, le=1440),
    db: Session = Depends(get_db),
):
    """Correlated attack timeline: event volume per time bucket, overlaid with
    how many detections of each type fall in that bucket."""
    _require_dataset(db, dataset_id)

    events = db.scalars(
        select(Event).where(Event.dataset_id == dataset_id, Event.timestamp.isnot(None))
    ).all()
    if not events:
        return TimelineOut(dataset_id=dataset_id, bucket_minutes=bucket_minutes, points=[])

    bucket = timedelta(minutes=bucket_minutes)

    def floor_to_bucket(ts):
        epoch_seconds = ts.timestamp()
        floored = epoch_seconds - (epoch_seconds % bucket.total_seconds())
        return type(ts).fromtimestamp(floored)

    event_buckets = Counter(floor_to_bucket(e.timestamp) for e in events)

    detections = db.scalars(
        select(DetectionRecord).where(
            DetectionRecord.dataset_id == dataset_id,
            DetectionRecord.window_start.isnot(None),
        )
    ).all()
    detection_buckets: dict = defaultdict(Counter)
    for d in detections:
        detection_buckets[floor_to_bucket(d.window_start)][d.detection_type] += 1

    points = [
        TimelinePoint(
            bucket=bucket_time,
            total_events=count,
            detection_counts=dict(detection_buckets.get(bucket_time, {})),
        )
        for bucket_time, count in sorted(event_buckets.items())
    ]
    return TimelineOut(dataset_id=dataset_id, bucket_minutes=bucket_minutes, points=points)


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    dataset_id: int,
    classification: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    _require_dataset(db, dataset_id)

    stmt = select(Alert).where(Alert.dataset_id == dataset_id)
    if classification:
        stmt = stmt.where(Alert.classification == classification)
    stmt = stmt.order_by(Alert.risk_score.desc()).limit(limit)
    return db.scalars(stmt).all()


@router.get("/ips/{source_ip}", response_model=IpInvestigationOut)
def investigate_ip(
    dataset_id: int,
    source_ip: str,
    event_limit: int = Query(default=200, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    """Full investigation view for one IP: its alert, every detection that
    fired, the ordered attack progression, and the underlying raw events that
    constitute the evidence."""
    _require_dataset(db, dataset_id)

    alert = db.scalar(
        select(Alert).where(Alert.dataset_id == dataset_id, Alert.source_ip == source_ip)
    )
    detections = db.scalars(
        select(DetectionRecord)
        .where(DetectionRecord.dataset_id == dataset_id, DetectionRecord.source_ip == source_ip)
        .order_by(DetectionRecord.window_start)
    ).all()

    if alert is None and not detections:
        raise HTTPException(
            status_code=404, detail=f"No analysis found for IP {source_ip} in this dataset"
        )

    total_events = db.scalar(
        select(func.count(Event.id)).where(
            Event.dataset_id == dataset_id, Event.source_ip == source_ip
        )
    ) or 0
    related_events = db.scalars(
        select(Event)
        .where(Event.dataset_id == dataset_id, Event.source_ip == source_ip)
        .order_by(Event.timestamp)
        .limit(event_limit)
    ).all()

    progression = [
        AttackProgressionStep(
            detection_type=d.detection_type,
            window_start=d.window_start,
            window_end=d.window_end,
            severity=d.severity,
            event_count=d.event_count,
        )
        for d in detections
    ]

    return IpInvestigationOut(
        source_ip=source_ip,
        alert=alert,
        detections=list(detections),
        attack_progression=progression,
        related_events=list(related_events),
        total_events=total_events,
    )


@router.get("/analytics", response_model=AnalyticsOut)
def get_analytics(
    dataset_id: int,
    top_n: int = Query(default=10, ge=1, le=100),
    db: Session = Depends(get_db),
):
    _require_dataset(db, dataset_id)

    alerts = db.scalars(
        select(Alert).where(Alert.dataset_id == dataset_id).order_by(Alert.risk_score.desc())
    ).all()
    detections = db.scalars(
        select(DetectionRecord).where(DetectionRecord.dataset_id == dataset_id)
    ).all()

    # Aggregate strictly by country. The bundled GeoIP table has several
    # city-level ranges per country, so keying on lat/lon here would emit the
    # same country repeatedly; a country-level view wants one row per country,
    # with the first-seen coordinates kept as a representative marker.
    geo_counter: dict = defaultdict(
        lambda: {"alert_count": 0, "total_risk": 0.0, "lat": None, "lon": None}
    )
    for a in alerts:
        key = (a.country or "Unknown", a.country_code or "XX")
        stats = geo_counter[key]
        stats["alert_count"] += 1
        stats["total_risk"] += a.risk_score
        if stats["lat"] is None:
            stats["lat"], stats["lon"] = a.lat, a.lon

    geographic_distribution = [
        {
            "country": country,
            "country_code": code,
            "lat": stats["lat"],
            "lon": stats["lon"],
            "alert_count": stats["alert_count"],
            "avg_risk_score": round(stats["total_risk"] / stats["alert_count"], 1),
        }
        for (country, code), stats in sorted(
            geo_counter.items(), key=lambda kv: kv[1]["alert_count"], reverse=True
        )
    ]

    behaviour_anomalies = [
        a for a in alerts if (a.components or {}).get("behavior_anomaly", 0) >= 0.5
    ][:top_n]

    return AnalyticsOut(
        dataset_id=dataset_id,
        top_malicious_ips=list(alerts[:top_n]),
        attack_categories=dict(Counter(d.detection_type for d in detections)),
        geographic_distribution=geographic_distribution,
        behaviour_anomalies=behaviour_anomalies,
    )
