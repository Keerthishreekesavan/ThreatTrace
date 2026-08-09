"""Produces 3 sample cybersecurity log datasets with entirely different
column names for the same underlying concepts (per the brief's own
source_ip/src_addr/client_ip example), each mixing normal baseline traffic
with several instances of every attack scenario. Also writes a
`ground_truth.json` per dataset (attacker IP -> expected attack type) used
by the test suite to check detector precision/recall - this file is a test
fixture, not something a real-world log would ever contain.

Run with:  python -m synthetic.generate_datasets
"""

import csv
import json
import random
from pathlib import Path

from synthetic.attack_scenarios import (
    SCENARIO_GENERATORS,
    generate_normal_traffic,
)

OUTPUT_DIR = Path(__file__).resolve().parents[2] / "data" / "samples"

# canonical_field -> dataset-specific column name. Fields omitted from a
# mapping are genuinely absent from that dataset (tests "missing fields
# handled intelligently, not just discarded").
DATASET_A_COLUMNS = {
    "source_ip": "source_ip",
    "destination_ip": "destination_ip",
    "failed_attempts": "failed_attempts",
    "timestamp": "timestamp",
}

DATASET_B_COLUMNS = {
    "source_ip": "src_addr",
    "destination_ip": "dst_host",
    "failed_attempts": "login_fail",
    "timestamp": "event_time",
    "username": "acct_name",
    "port": "dst_port",
    "protocol": "svc_proto",
    "request_path": "uri_path",
    "status_code": "http_status",
    "device_id": "host_tag",
    "payload_size": "bytes_out",
}

DATASET_C_COLUMNS = {
    "source_ip": "client_ip",
    "destination_ip": "server_ip",
    "failed_attempts": "authentication_errors",
    "timestamp": "created_at",
    "username": "user_acct",
    "port": "conn_port",
    "protocol": "l4_protocol",
    "payload_size": "data_len",
    "device_id": "asset_tag",
}


def _build_canonical_rows(seed: int, scenario_types: list[str]) -> list[dict]:
    rng = random.Random(seed)
    rows = generate_normal_traffic(rng, count=650)
    for scenario_name in scenario_types:
        generator = SCENARIO_GENERATORS[scenario_name]
        for instance in range(2):
            rows.extend(generator(rng, scenario_id=instance))
    rng.shuffle(rows)
    return rows


def _reshape(rows: list[dict], column_map: dict[str, str]) -> list[dict]:
    reshaped = []
    for row in rows:
        out = {column_map[field]: row[field] for field in column_map if field in row}
        reshaped.append(out)
    return reshaped


def _write_csv(rows: list[dict], path: Path) -> None:
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_json(rows: list[dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, default=str)


def _ground_truth(rows: list[dict]) -> dict:
    by_ip: dict[str, dict] = {}
    for row in rows:
        label = row["_ground_truth"]
        if label == "normal":
            continue
        ip = row["source_ip"]
        entry = by_ip.setdefault(ip, {"attack_type": label, "event_count": 0})
        entry["event_count"] += 1
    return by_ip



# Each dataset only gets attack scenarios its own column set can actually
# reveal - e.g. dataset A has no username field, so a credential-spraying
# burst is genuinely indistinguishable from a plain brute force there. That
# is correct, honest behaviour (missing fields degrade gracefully rather
# than producing a confident-but-wrong label), not a detector bug, so we
# don't manufacture ground truth the schema can't support.
DATASET_A_SCENARIOS = ["brute_force"]
DATASET_B_SCENARIOS = ["brute_force", "credential_spray", "port_scan", "endpoint_probe", "unknown_anomaly"]
DATASET_C_SCENARIOS = ["brute_force", "credential_spray", "port_scan", "unknown_anomaly"]  # no request_path/status_code


def generate_all() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    datasets = [
        ("auth_logs_a", 1, DATASET_A_COLUMNS, "csv", DATASET_A_SCENARIOS),
        ("web_logs_b", 2, DATASET_B_COLUMNS, "json", DATASET_B_SCENARIOS),
        ("network_logs_c", 3, DATASET_C_COLUMNS, "csv", DATASET_C_SCENARIOS),
    ]

    for name, seed, column_map, fmt, scenario_types in datasets:
        canonical_rows = _build_canonical_rows(seed, scenario_types)
        ground_truth = _ground_truth(canonical_rows)
        shaped_rows = _reshape(canonical_rows, column_map)

        data_path = OUTPUT_DIR / f"{name}.{fmt}"
        if fmt == "csv":
            _write_csv(shaped_rows, data_path)
        else:
            _write_json(shaped_rows, data_path)

        gt_path = OUTPUT_DIR / f"{name}.ground_truth.json"
        with open(gt_path, "w", encoding="utf-8") as f:
            json.dump(ground_truth, f, indent=2)

        print(f"wrote {data_path} ({len(shaped_rows)} rows) + {gt_path}")


if __name__ == "__main__":
    generate_all()
