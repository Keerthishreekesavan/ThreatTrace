"""Schema-mapper tests.

The headline claim of the project is that the *same* concept is recognized
across datasets that name it completely differently. These cases encode the
brief's own example (source_ip / src_addr / client_ip, and
failed_attempts / login_fail / authentication_errors) as an explicit
contract, and check it holds on both embedding backends - the TF-IDF
fallback must be just as correct as sentence-transformers, since the
fallback is what runs when torch isn't installed.
"""

import pandas as pd
import pytest

from ingestion.normalizer import normalize
from ingestion.schema_mapper import (
    _SENTENCE_TRANSFORMERS_AVAILABLE,
    TfidfEmbedder,
    map_columns,
)

# The three schemas from the brief, all describing the same concepts.
DATASET_A = pd.DataFrame({
    "source_ip": ["45.12.3.9", "45.12.3.9", "80.66.1.2"],
    "destination_ip": ["10.0.0.5", "10.0.0.6", "10.0.0.5"],
    "failed_attempts": [3, 7, 0],
    "timestamp": ["2026-08-08T01:00:00", "2026-08-08T01:05:00", "2026-08-08T01:09:00"],
})

DATASET_B = pd.DataFrame({
    "src_addr": ["45.12.3.9", "45.12.3.9", "80.66.1.2"],
    "dst_host": ["10.0.0.5", "10.0.0.6", "10.0.0.5"],
    "login_fail": [3, 7, 0],
    "event_time": ["2026-08-08T01:00:00", "2026-08-08T01:05:00", "2026-08-08T01:09:00"],
})

DATASET_C = pd.DataFrame({
    "client_ip": ["45.12.3.9", "45.12.3.9", "80.66.1.2"],
    "server_ip": ["10.0.0.5", "10.0.0.6", "10.0.0.5"],
    "authentication_errors": [3, 7, 0],
    "created_at": ["2026-08-08T01:00:00", "2026-08-08T01:05:00", "2026-08-08T01:09:00"],
})

EXPECTED = [
    (DATASET_A, {"source_ip": "source_ip", "destination_ip": "destination_ip",
                 "failed_attempts": "failed_attempts", "timestamp": "timestamp"}),
    (DATASET_B, {"src_addr": "source_ip", "dst_host": "destination_ip",
                 "login_fail": "failed_attempts", "event_time": "timestamp"}),
    (DATASET_C, {"client_ip": "source_ip", "server_ip": "destination_ip",
                 "authentication_errors": "failed_attempts", "created_at": "timestamp"}),
]

BACKENDS = [pytest.param(TfidfEmbedder(), id="tfidf")]
if _SENTENCE_TRANSFORMERS_AVAILABLE:
    from ingestion.schema_mapper import SentenceTransformerEmbedder

    BACKENDS.append(pytest.param(SentenceTransformerEmbedder(), id="sentence-transformers"))


@pytest.mark.parametrize("embedder", BACKENDS)
@pytest.mark.parametrize("df,expected", EXPECTED)
def test_equivalent_concepts_map_identically(df, expected, embedder):
    mapped = {m.column_name: m.mapped_field for m in map_columns(df, embedder=embedder)}
    assert mapped == expected


@pytest.mark.parametrize("embedder", BACKENDS)
def test_confidence_is_a_probability(embedder):
    for mapping in map_columns(DATASET_B, embedder=embedder):
        assert 0.0 <= mapping.confidence <= 1.0


def test_unknown_columns_are_preserved_not_dropped():
    """A column the ontology has no concept for must survive verbatim in
    extra_fields rather than being silently discarded."""
    df = DATASET_A.copy()
    df["internal_case_ref"] = ["CASE-9", "CASE-9", "CASE-12"]
    df["cost_centre_code"] = ["ZZ-4491", "ZZ-4491", "ZZ-4492"]

    mappings = map_columns(df, embedder=TfidfEmbedder())
    canonical = normalize(df, mappings)

    unmapped = canonical.attrs["unmapped_columns"]
    assert "internal_case_ref" in unmapped
    assert "cost_centre_code" in unmapped
    # and the values are still recoverable per-row
    assert "CASE-9" in canonical["extra_fields"].iloc[0]
    assert "ZZ-4491" in canonical["extra_fields"].iloc[0]


def test_missing_fields_degrade_gracefully():
    """Dataset A has no username/port/path at all. Normalization must still
    produce the full canonical schema with those fields empty, rather than
    erroring or inventing values."""
    mappings = map_columns(DATASET_A, embedder=TfidfEmbedder())
    canonical = normalize(DATASET_A, mappings)

    for absent in ("username", "port", "request_path", "protocol"):
        assert absent in canonical.columns
        assert canonical[absent].isna().all()

    assert canonical["source_ip"].notna().all()
    assert canonical["failed_attempts"].tolist() == [3, 7, 0]


def test_malformed_rows_do_not_break_normalization():
    """Unparseable timestamps and non-numeric counts become NaT/NaN rather
    than raising - real security logs are messy."""
    df = pd.DataFrame({
        "source_ip": ["45.12.3.9", "not-an-ip", "80.66.1.2"],
        "failed_attempts": [3, "oops", None],
        "timestamp": ["2026-08-08T01:00:00", "garbage", None],
    })
    mappings = map_columns(df, embedder=TfidfEmbedder())
    canonical = normalize(df, mappings)

    assert len(canonical) == 3
    assert pd.isna(canonical["timestamp"].iloc[1])
    assert pd.isna(canonical["failed_attempts"].iloc[1])
