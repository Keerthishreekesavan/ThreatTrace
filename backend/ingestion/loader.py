"""Loads an uploaded CSV or JSON log file into a DataFrame, tolerating the
kind of malformed input real-world security logs actually have: stray
unparsable rows, inconsistent encodings, or a JSON file that's a single
object instead of a list of records.
"""

import json
from pathlib import Path

import pandas as pd


class UnsupportedFileTypeError(ValueError):
    pass


def load_dataset(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix == ".csv":
        return _load_csv(path)
    if suffix == ".json":
        return _load_json(path)
    raise UnsupportedFileTypeError(f"Unsupported file type: {suffix}. Only .csv and .json are supported.")


def _load_csv(path: Path) -> pd.DataFrame:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return pd.read_csv(path, encoding=encoding, on_bad_lines="skip", engine="python")
        except UnicodeDecodeError:
            continue
    raise ValueError(f"Could not decode {path} with any supported encoding")


def _is_record_list(value) -> bool:
    return (
        isinstance(value, list)
        and len(value) > 0
        and all(isinstance(item, dict) for item in value)
    )


def _find_record_list(node, depth: int = 0) -> list | None:
    """Recursively locate the largest list-of-objects in a JSON structure.

    Log exports bury their records under wildly different wrapper keys -
    Elasticsearch uses `hits.hits`, AWS CloudTrail uses `Records`, Azure uses
    `value`, and plenty of tools invent their own. Rather than maintaining a
    list of known key names, find the biggest list of objects anywhere in the
    document and treat that as the event records.
    """
    if depth > 6:
        return None
    if _is_record_list(node):
        return node
    if isinstance(node, dict):
        candidates = [
            found
            for child in node.values()
            if (found := _find_record_list(child, depth + 1)) is not None
        ]
        if candidates:
            return max(candidates, key=len)
    return None


def _load_json(path: Path) -> pd.DataFrame:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        raise ValueError(f"{path.name} is empty")

    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        # Newline-delimited JSON (one object per line) is extremely common for
        # log exports and is not valid JSON as a whole document.
        records = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip unparseable lines rather than losing the file
        if not records:
            raise ValueError(
                f"{path.name} is not valid JSON or newline-delimited JSON"
            ) from None
        raw = records

    if isinstance(raw, dict):
        raw = _find_record_list(raw) or [raw]

    if not isinstance(raw, list):
        raise ValueError(f"Unrecognized JSON structure in {path.name}")
    if not raw:
        raise ValueError(f"{path.name} contains no records")

    # max_level keeps deeply nested blobs as single values instead of
    # exploding into hundreds of sparse columns.
    return pd.json_normalize(raw, max_level=3)
