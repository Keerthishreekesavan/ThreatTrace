"""API-level tests: upload each sample dataset through the real HTTP surface
and assert every dashboard view returns coherent data."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.models import Base
from db.session import get_db
from main import app

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "data" / "samples"


@pytest.fixture()
def client(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _upload(client, filename):
    path = SAMPLES_DIR / filename
    with open(path, "rb") as f:
        response = client.post(
            "/api/datasets", files={"file": (filename, f, "application/octet-stream")}
        )
    assert response.status_code == 200, response.text
    return response.json()


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize(
    "filename", ["auth_logs_a.csv", "web_logs_b.json", "network_logs_c.csv"]
)
def test_full_dashboard_flow(client, filename):
    dataset = _upload(client, filename)
    dataset_id = dataset["id"]
    assert dataset["row_count"] > 0

    schema = client.get(f"/api/datasets/{dataset_id}/schema").json()
    assert schema, "expected column mapping info"
    assert any(c["mapped_field"] == "source_ip" for c in schema)

    overview = client.get(f"/api/datasets/{dataset_id}/overview").json()
    assert overview["total_events"] == dataset["row_count"]
    assert overview["threats_detected"] > 0
    assert sum(overview["risk_distribution"].values()) > 0

    timeline = client.get(f"/api/datasets/{dataset_id}/timeline").json()
    assert timeline["points"], "expected timeline buckets"
    assert all(p["total_events"] > 0 for p in timeline["points"])

    alerts = client.get(f"/api/datasets/{dataset_id}/alerts").json()
    assert alerts, "expected at least one alert"
    top_alert = alerts[0]
    assert 0 <= top_alert["risk_score"] <= 100
    assert top_alert["recommendation"]
    assert top_alert["threat"]
    # alerts must be returned highest-risk first for SOC triage
    assert [a["risk_score"] for a in alerts] == sorted(
        (a["risk_score"] for a in alerts), reverse=True
    )

    investigation = client.get(
        f"/api/datasets/{dataset_id}/ips/{top_alert['source_ip']}"
    ).json()
    assert investigation["total_events"] > 0
    assert investigation["related_events"]
    assert investigation["alert"]["source_ip"] == top_alert["source_ip"]

    analytics = client.get(f"/api/datasets/{dataset_id}/analytics").json()
    assert analytics["top_malicious_ips"]
    assert analytics["attack_categories"]
    assert analytics["geographic_distribution"]


def test_rejects_unsupported_file_type(client):
    response = client.post(
        "/api/datasets", files={"file": ("notes.txt", b"hello", "text/plain")}
    )
    assert response.status_code == 400
    assert "Unsupported file type" in response.json()["detail"]


def test_unknown_dataset_returns_404(client):
    assert client.get("/api/datasets/9999/overview").status_code == 404


def test_unmapped_columns_are_preserved(client):
    """network_logs_c.csv has columns the ontology has no concept for; they
    must survive into extra_fields rather than being dropped."""
    dataset = _upload(client, "web_logs_b.json")
    detail = client.get(f"/api/datasets/{dataset['id']}").json()
    assert "mapping_summary" in detail
    assert len(detail["mapping_summary"]) > 0
