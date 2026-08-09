"""Builds the canonical event DataFrame from raw input + column mappings.

Any column that the schema mapper couldn't confidently place is never
dropped - it's preserved verbatim, per-row, inside an `extra_fields` JSON
blob so nothing is silently lost, and an analyst can still inspect it during
investigation even though the detection engines don't reason over it
directly.
"""

import json

import pandas as pd

from .schema_mapper import ColumnMapping

CANONICAL_FIELDS = [
    "source_ip",
    "destination_ip",
    "timestamp",
    "username",
    "event_type",
    "failed_attempts",
    "port",
    "protocol",
    "request_path",
    "status_code",
    "payload_size",
    "device_id",
    "source_location",
]

_NUMERIC_FIELDS = {"failed_attempts", "port", "status_code", "payload_size"}

# Words that mark a row as a failed/denied attempt in a textual status field.
_FAILURE_PATTERN = r"fail|denied|invalid|error|reject|refus|unauthor|forbidden|lock|bad"


def _as_failure_indicator(series: pd.Series) -> pd.Series:
    """Turns a textual status/outcome column into a 0/1 failure count."""
    return (
        series.astype("string")
        .str.contains(_FAILURE_PATTERN, case=False, na=False)
        .astype(int)
    )


def normalize(df: pd.DataFrame, mappings: list[ColumnMapping]) -> pd.DataFrame:
    mapped_columns = {m.mapped_field: m.column_name for m in mappings if m.mapped_field}
    unmapped_columns = [m.column_name for m in mappings if not m.mapped_field]

    canonical = pd.DataFrame(index=df.index)

    for field in CANONICAL_FIELDS:
        if field in mapped_columns:
            canonical[field] = df[mapped_columns[field]]
        else:
            canonical[field] = pd.NA

    if canonical["timestamp"].notna().any():
        canonical["timestamp"] = pd.to_datetime(
            canonical["timestamp"], errors="coerce", format="mixed"
        )

    # `failed_attempts` is the one numeric field that is just as often recorded
    # as a pass/fail *indicator* ("SUCCESS"/"FAILED", "denied", true/false) as
    # it is a running count. Coerce numerically first; if that yields nothing
    # usable but the column did have values, read it as an indicator instead.
    # Without this, pinning a textual status column to failed_attempts would
    # silently produce an all-empty column.
    if "failed_attempts" in mapped_columns:
        raw_failed = canonical["failed_attempts"]
        numeric_failed = pd.to_numeric(raw_failed, errors="coerce")
        if numeric_failed.isna().all() and raw_failed.notna().any():
            canonical["failed_attempts"] = _as_failure_indicator(raw_failed)
        else:
            canonical["failed_attempts"] = numeric_failed

    for field in _NUMERIC_FIELDS:
        if field == "failed_attempts" and "failed_attempts" in mapped_columns:
            continue
        canonical[field] = pd.to_numeric(canonical[field], errors="coerce")

    # event_type / status_code together imply failed_attempts when the
    # source dataset only logs discrete auth events rather than a running
    # failure count (e.g. one row per login attempt).
    if canonical["failed_attempts"].isna().all() and canonical["event_type"].notna().any():
        canonical["failed_attempts"] = _as_failure_indicator(canonical["event_type"])

    for field in ["source_ip", "destination_ip", "username", "event_type",
                  "protocol", "request_path", "device_id", "source_location"]:
        canonical[field] = canonical[field].astype("string")

    def build_extra_fields(row_idx) -> str:
        extras = {col: df.at[row_idx, col] for col in unmapped_columns}
        return json.dumps(extras, default=str)

    canonical["extra_fields"] = [build_extra_fields(idx) for idx in df.index]

    # Carries the dtype and a few sample values as well as the match itself, so
    # the UI can show an analyst enough context to judge (and correct) a mapping
    # without re-reading the source file.
    mapping_summary = {
        m.column_name: {
            "mapped_field": m.mapped_field,
            "confidence": m.confidence,
            "source": m.source,
            "inferred_dtype": m.profile.inferred_dtype,
            "sample_values": [str(v) for v in m.profile.sample_values[:3]],
        }
        for m in mappings
    }
    canonical.attrs["mapping_summary"] = mapping_summary
    canonical.attrs["unmapped_columns"] = unmapped_columns

    return canonical
