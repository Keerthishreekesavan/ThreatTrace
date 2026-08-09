"""Tests for analyst schema overrides and re-analysis.

This closes the mapper's real weakness: a low-confidence match produces a
*wrong* finding rather than no finding, and only a human can tell that (say) a
`request_count` column isn't a failed-login count. These tests pin both halves -
that a correction actually changes the mapping, and that it changes the
resulting detections.
"""

import json

import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.models import Base
from db.session import get_db
from ingestion.normalizer import normalize
from ingestion.schema_mapper import (
    TfidfEmbedder,
    UnknownOntologyFieldError,
    map_columns,
)
from main import app


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


def _misleading_log(tmp_path):
    """A log shaped like the real-world case that motivated this feature: a
    constant `request_count` column that the mapper mistakes for a failed-login
    count, alongside the `status` column that actually records failure."""
    rows = []
    for i in range(40):
        rows.append({
            "timestamp": f"2026-08-08T11:00:{i % 60:02d}",
            "source_ip": "91.204.18.55",
            "status": "FAILED",
            "username": "service_user",
            "request_count": 3,
        })
    for i in range(40):
        rows.append({
            "timestamp": f"2026-08-08T14:{i % 60:02d}:00",
            "source_ip": f"10.20.1.{i % 20 + 2}",
            "status": "SUCCESS",
            "username": f"user{i % 8}",
            "request_count": 3,
        })
    path = tmp_path / "misleading.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def _upload(client, path):
    with open(path, "rb") as f:
        r = client.post("/api/datasets", files={"file": (path.name, f, "application/json")})
    assert r.status_code == 200, r.text
    return r.json()


# ── Mapper-level ──────────────────────────────────────────────────────────────

def test_override_pins_field_and_frees_the_concept():
    df = pd.DataFrame({
        "status": ["FAILED", "SUCCESS", "FAILED"],
        "request_count": [3, 3, 3],
        "source_ip": ["1.2.3.4"] * 3,
    })
    inferred = {m.column_name: m.mapped_field for m in map_columns(df, embedder=TfidfEmbedder())}
    assert inferred["request_count"] == "failed_attempts", "precondition: the mapper is fooled"

    corrected = map_columns(
        df,
        embedder=TfidfEmbedder(),
        overrides={"status": "failed_attempts", "request_count": None},
    )
    by_col = {m.column_name: m for m in corrected}
    assert by_col["status"].mapped_field == "failed_attempts"
    assert by_col["status"].source == "manual"
    assert by_col["status"].confidence == 1.0
    # the concept must not end up claimed twice
    assert by_col["request_count"].mapped_field is None
    assert by_col["request_count"].source == "manual"


def test_pinned_concept_is_withdrawn_from_automatic_matching():
    """If the analyst gives `failed_attempts` to one column, the column that
    previously held it must be re-matched, not left duplicating the field."""
    df = pd.DataFrame({
        "login_failures": [1, 2, 3],
        "auth_errors": [0, 1, 0],
        "source_ip": ["1.2.3.4"] * 3,
    })
    mapped = map_columns(
        df, embedder=TfidfEmbedder(), overrides={"auth_errors": "failed_attempts"}
    )
    fields = [m.mapped_field for m in mapped if m.mapped_field]
    assert fields.count("failed_attempts") == 1
    assert next(m for m in mapped if m.column_name == "auth_errors").mapped_field == (
        "failed_attempts"
    )


def test_override_of_unknown_field_is_rejected():
    df = pd.DataFrame({"a": [1, 2]})
    with pytest.raises(UnknownOntologyFieldError):
        map_columns(df, embedder=TfidfEmbedder(), overrides={"a": "not_a_real_field"})


def test_overrides_for_columns_not_in_the_file_are_ignored():
    df = pd.DataFrame({"a": ["1.2.3.4", "5.6.7.8"]})
    mapped = map_columns(df, embedder=TfidfEmbedder(), overrides={"ghost": "username"})
    assert {m.column_name for m in mapped} == {"a"}


# ── Normalizer-level ──────────────────────────────────────────────────────────

def test_failed_attempts_accepts_a_pass_fail_indicator():
    """Pinning a textual status column to failed_attempts must yield 0/1 rather
    than an all-empty column."""
    df = pd.DataFrame({
        "status": ["FAILED", "SUCCESS", "denied", "ok", "Invalid password"],
        "source_ip": ["1.2.3.4"] * 5,
    })
    mappings = map_columns(
        df, embedder=TfidfEmbedder(), overrides={"status": "failed_attempts"}
    )
    canonical = normalize(df, mappings)
    assert canonical["failed_attempts"].tolist() == [1, 0, 1, 0, 1]


def test_numeric_failed_attempts_still_read_as_counts():
    df = pd.DataFrame({"fails": [0, 7, 3], "source_ip": ["1.2.3.4"] * 3})
    mappings = map_columns(df, embedder=TfidfEmbedder(), overrides={"fails": "failed_attempts"})
    canonical = normalize(df, mappings)
    assert canonical["failed_attempts"].tolist() == [0, 7, 3]


# ── API-level ─────────────────────────────────────────────────────────────────

def test_ontology_endpoint_lists_canonical_fields(client):
    fields = client.get("/api/ontology").json()
    keys = {f["key"] for f in fields}
    assert {"source_ip", "failed_attempts", "timestamp"} <= keys
    assert all(f["display_name"] and f["description"] for f in fields)


def test_override_reruns_analysis_and_changes_the_finding(client, tmp_path):
    dataset = _upload(client, _misleading_log(tmp_path))
    dataset_id = dataset["id"]

    before = client.get(f"/api/datasets/{dataset_id}/schema").json()
    by_col = {c["column_name"]: c for c in before}
    assert by_col["request_count"]["mapped_field"] == "failed_attempts"
    assert by_col["request_count"]["source"] == "inferred"

    response = client.put(
        f"/api/datasets/{dataset_id}/schema",
        json={"overrides": {"status": "failed_attempts", "request_count": None}},
    )
    assert response.status_code == 200, response.text
    after = {c["column_name"]: c for c in response.json()}
    assert after["status"]["mapped_field"] == "failed_attempts"
    assert after["status"]["source"] == "manual"
    assert after["request_count"]["mapped_field"] is None

    # The re-run must replace, not append.
    overview = client.get(f"/api/datasets/{dataset_id}/overview").json()
    assert overview["total_events"] == 80

    # The evidence now counts real failures (40), not every row.
    alerts = client.get(f"/api/datasets/{dataset_id}/alerts").json()
    brute = [a for a in alerts if "brute" in a["threat"].lower()]
    assert brute, "the genuine brute-force attempt should still be caught"
    assert any("40 failed" in e for e in brute[0]["evidence"]), brute[0]["evidence"]

    # And the correction is recorded on the dataset.
    detail = client.get(f"/api/datasets/{dataset_id}").json()
    assert detail["overrides"] == {"status": "failed_attempts", "request_count": None}


def test_unmapped_override_is_preserved_in_extra_fields(client, tmp_path):
    dataset = _upload(client, _misleading_log(tmp_path))
    client.put(
        f"/api/datasets/{dataset['id']}/schema",
        json={"overrides": {"request_count": None}},
    )
    detail = client.get(f"/api/datasets/{dataset['id']}/ips/91.204.18.55").json()
    assert "request_count" in detail["related_events"][0]["extra_fields"]


def test_override_rejects_duplicate_field_assignment(client, tmp_path):
    dataset = _upload(client, _misleading_log(tmp_path))
    response = client.put(
        f"/api/datasets/{dataset['id']}/schema",
        json={"overrides": {"status": "failed_attempts", "request_count": "failed_attempts"}},
    )
    assert response.status_code == 422
    assert "once" in response.json()["detail"]


def test_override_rejects_unknown_column(client, tmp_path):
    dataset = _upload(client, _misleading_log(tmp_path))
    response = client.put(
        f"/api/datasets/{dataset['id']}/schema",
        json={"overrides": {"no_such_column": "username"}},
    )
    assert response.status_code == 422


def test_override_rejects_unknown_field(client, tmp_path):
    dataset = _upload(client, _misleading_log(tmp_path))
    response = client.put(
        f"/api/datasets/{dataset['id']}/schema",
        json={"overrides": {"status": "made_up_field"}},
    )
    assert response.status_code == 422


def test_override_on_missing_dataset_is_404(client):
    assert (
        client.put("/api/datasets/9999/schema", json={"overrides": {}}).status_code == 404
    )
