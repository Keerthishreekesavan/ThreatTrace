"""Generalization tests: real-world log shapes the system was NOT designed
around.

The synthetic samples in data/samples/ were written alongside the ingestion
layer, so passing on them proves less than it looks. These fixtures imitate
formats from actual tools (Zeek conn.log, Windows Security event export,
an Elasticsearch/ECS nested response, newline-delimited JSON) plus the
degenerate cases a user will inevitably hit - a non-security spreadsheet, a
3-row file, an empty file.

The bar here is deliberately about *robustness, not accuracy*: the pipeline
must complete and attribute findings honestly rather than crash. Each of
these crashed with a 500 before the fixes they now guard.
"""

import json

import pandas as pd
import pytest

from detection import run_all_detectors
from ingestion.loader import load_dataset
from ingestion.normalizer import normalize
from ingestion.schema_mapper import TfidfEmbedder, map_columns


def run_pipeline(path):
    df = load_dataset(path)
    mappings = map_columns(df, embedder=TfidfEmbedder())
    canonical = normalize(df, mappings)
    detections, scores = run_all_detectors(canonical)
    return df, mappings, canonical, detections


def test_zeek_style_conn_log(tmp_path):
    """Dotted column names (id.orig_h), epoch-float timestamps."""
    path = tmp_path / "conn.csv"
    rows = ["ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,orig_bytes"]
    for i in range(120):
        rows.append(
            f"17700000{i:02d}.5,C{i:04d},178.104.55.9,{40000 + i},10.50.0.3,{i + 1},tcp,{i}"
        )
    path.write_text("\n".join(rows), encoding="utf-8")

    df, mappings, canonical, detections = run_pipeline(path)
    mapped = {m.mapped_field for m in mappings if m.mapped_field}
    assert "source_ip" in mapped
    assert canonical["source_ip"].notna().any()


def test_windows_security_export(tmp_path):
    """US-style datetime with AM/PM, and a SINGLE IP column - which must be
    read as the source, since every detector groups by source_ip."""
    path = tmp_path / "win.csv"
    rows = ["TimeCreated,EventID,AccountName,IpAddress,IpPort"]
    for i in range(60):
        rows.append(
            f"03/04/2026 09:{i // 60:02d}:{i % 60:02d} AM,4625,administrator,91.207.44.18,{1024 + i}"
        )
    path.write_text("\n".join(rows), encoding="utf-8")

    df, mappings, canonical, detections = run_pipeline(path)
    by_column = {m.column_name: m.mapped_field for m in mappings}
    assert by_column["IpAddress"] == "source_ip"
    assert canonical["timestamp"].notna().any(), "AM/PM datetime should parse"


def test_single_ip_column_is_treated_as_source():
    """The rule directly: one IP column means 'who did this'."""
    df = pd.DataFrame({
        "rhost": ["203.0.113.9"] * 5,
        "user": ["root"] * 5,
        "result": ["FAILED"] * 5,
    })
    mapped = {m.column_name: m.mapped_field for m in map_columns(df, embedder=TfidfEmbedder())}
    assert mapped["rhost"] == "source_ip"


def test_nested_elasticsearch_response(tmp_path):
    """Records buried under an arbitrary wrapper (hits.hits) must be found,
    not treated as one row containing a list."""
    records = [
        {
            "@timestamp": f"2026-03-04T09:{i % 60:02d}:00Z",
            "client": {"address": "36.82.90.7"},
            "url": {"path": "/.env"},
            "http": {"response": {"status_code": 404}},
        }
        for i in range(40)
    ]
    path = tmp_path / "ecs.json"
    path.write_text(
        json.dumps({"took": 3, "hits": {"total": len(records), "hits": records}}),
        encoding="utf-8",
    )

    df, mappings, canonical, detections = run_pipeline(path)
    assert len(df) == 40, "should unwrap to 40 records, not 1"
    assert canonical["source_ip"].notna().any()


def test_newline_delimited_json(tmp_path):
    """NDJSON is not valid JSON as a document, but is very common for logs."""
    path = tmp_path / "events.json"
    path.write_text(
        "\n".join(
            json.dumps({"time": f"2026-03-04T09:00:{i:02d}Z", "src": "45.9.1.2", "usr": "admin"})
            for i in range(20)
        ),
        encoding="utf-8",
    )
    df, mappings, canonical, detections = run_pipeline(path)
    assert len(df) == 20


def test_non_security_data_yields_no_findings(tmp_path):
    """A spreadsheet with nothing security-related must report zero findings
    rather than crashing or inventing threats."""
    path = tmp_path / "orders.csv"
    path.write_text(
        "order_ref,sku,qty,unit_price\n"
        + "\n".join(f"ORD-{i},SKU-{i},{i},{i}.99" for i in range(30)),
        encoding="utf-8",
    )
    df, mappings, canonical, detections = run_pipeline(path)
    assert detections == []


def test_tiny_file(tmp_path):
    path = tmp_path / "tiny.csv"
    path.write_text(
        "when,who,from_ip,outcome\n"
        "2026-03-04 09:00:00,root,203.0.113.9,FAILED\n"
        "2026-03-04 09:00:04,root,203.0.113.9,FAILED\n",
        encoding="utf-8",
    )
    df, mappings, canonical, detections = run_pipeline(path)
    assert len(canonical) == 2
    assert detections == []  # far below any threshold


def test_empty_and_malformed_json_are_rejected_clearly(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        load_dataset(empty)

    junk = tmp_path / "junk.json"
    junk.write_text("this is not json at all", encoding="utf-8")
    with pytest.raises(ValueError):
        load_dataset(junk)


def test_column_of_nested_objects_does_not_crash(tmp_path):
    """A cell holding a list/dict is unhashable and used to blow up dtype
    inference."""
    path = tmp_path / "nested.json"
    path.write_text(
        json.dumps([
            {"src_ip": "45.9.1.2", "tags": ["a", "b"], "meta": {"k": "v"}}
            for _ in range(12)
        ]),
        encoding="utf-8",
    )
    df, mappings, canonical, detections = run_pipeline(path)
    assert len(df) == 12
