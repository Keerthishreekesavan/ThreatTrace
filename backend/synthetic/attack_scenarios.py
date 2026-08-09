"""Generates canonical-form event rows: normal baseline traffic plus five
labeled attack scenarios (brute force, credential spraying, port scanning,
endpoint probing, and an unknown-anomaly pattern meant only to be caught by
Isolation Forest, not the rule-based detectors).

Everything here is deterministic (seeded RNG) and produced in the *canonical*
event shape - `generate_datasets.py` is responsible for renaming/reshuffling
columns into each dataset's own differently-named schema. Every generated
row also carries a `_ground_truth` tag (attack scenario name or "normal")
that is stripped before writing the sample files but exported separately for
tests to check detector precision/recall against.
"""

import random
from datetime import datetime, timedelta

from geoip.geoip_lookup import sample_ip_for_country

BASE_TIME = datetime(2026, 8, 8, 0, 0, 0)

_NORMAL_COUNTRIES = ["US", "GB", "DE", "FR", "CA", "AU", "JP", "IN"]
_ATTACKER_COUNTRIES = ["RU", "CN", "NG", "UA", "KR"]

_NORMAL_USERS = [
    "jsmith", "amartin", "priya.n", "wchen", "k.oconnor", "dsingh",
    "mgarcia", "l.nguyen", "rpatel", "e.rossi", "t.muller", "n.dubois",
]

_NORMAL_PATHS = ["/", "/dashboard", "/api/v1/profile", "/login", "/static/app.js",
                  "/api/v1/orders", "/favicon.ico", "/api/v1/health"]

_SUSPICIOUS_PATHS = [
    "/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/.git/config",
    "/etc/passwd", "/config.php.bak", "/api/internal/debug",
    "/../../../../etc/shadow", "/server-status", "/actuator/env",
]

_COMMON_PORTS = [22, 80, 443, 3389]


def _server_ip(rng: random.Random) -> str:
    return f"10.50.{rng.randint(0, 5)}.{rng.randint(1, 254)}"


def _ts(offset_seconds: float) -> str:
    return (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat()


def generate_normal_traffic(rng: random.Random, count: int) -> list[dict]:
    rows = []
    for _ in range(count):
        country = rng.choice(_NORMAL_COUNTRIES)
        ip = sample_ip_for_country(country, rng)
        hour_offset = rng.uniform(8 * 3600, 19 * 3600)  # business hours
        day_offset = rng.randint(0, 6) * 86400
        success = rng.random() > 0.03  # occasional real typo/failed login
        rows.append({
            "source_ip": ip,
            "destination_ip": _server_ip(rng),
            "timestamp": _ts(day_offset + hour_offset + rng.uniform(0, 300)),
            "username": rng.choice(_NORMAL_USERS),
            "event_type": "login_success" if success else "login_failed",
            "failed_attempts": 0 if success else 1,
            "port": rng.choice(_COMMON_PORTS),
            "protocol": "tcp",
            "request_path": rng.choice(_NORMAL_PATHS),
            "status_code": 200 if success else 401,
            "payload_size": rng.randint(200, 4000),
            "device_id": f"host-{rng.randint(1000, 9999)}",
            "_ground_truth": "normal",
        })
    return rows


def generate_brute_force(rng: random.Random, scenario_id: int) -> list[dict]:
    attacker_ip = sample_ip_for_country(rng.choice(_ATTACKER_COUNTRIES), rng)
    victim = rng.choice(_NORMAL_USERS)
    start = scenario_id * 7200 + rng.uniform(0, 3600)
    n_attempts = rng.randint(30, 90)
    rows = []
    for i in range(n_attempts):
        rows.append({
            "source_ip": attacker_ip,
            "destination_ip": _server_ip(rng),
            "timestamp": _ts(start + i * rng.uniform(1, 6)),
            "username": victim,
            "event_type": "login_failed",
            "failed_attempts": 1,
            "port": 22,
            "protocol": "tcp",
            "request_path": "/login",
            "status_code": 401,
            "payload_size": rng.randint(80, 300),
            "device_id": f"host-{rng.randint(1000, 9999)}",
            "_ground_truth": "brute_force",
        })
    return rows


def generate_credential_spray(rng: random.Random, scenario_id: int) -> list[dict]:
    attacker_ip = sample_ip_for_country(rng.choice(_ATTACKER_COUNTRIES), rng)
    targets = [f"user{n}" for n in rng.sample(range(1000, 9999), rng.randint(20, 60))]
    start = 20000 + scenario_id * 7200 + rng.uniform(0, 3600)
    rows = []
    t = start
    for user in targets:
        n_tries = rng.randint(1, 2)
        for _ in range(n_tries):
            rows.append({
                "source_ip": attacker_ip,
                "destination_ip": _server_ip(rng),
                "timestamp": _ts(t),
                "username": user,
                "event_type": "login_failed",
                "failed_attempts": 1,
                "port": 22,
                "protocol": "tcp",
                "request_path": "/login",
                "status_code": 401,
                "payload_size": rng.randint(80, 300),
                "device_id": f"host-{rng.randint(1000, 9999)}",
                "_ground_truth": "credential_spray",
            })
            t += rng.uniform(1, 4)
    return rows


def generate_port_scan(rng: random.Random, scenario_id: int) -> list[dict]:
    attacker_ip = sample_ip_for_country(rng.choice(_ATTACKER_COUNTRIES), rng)
    target_ip = _server_ip(rng)
    start = 40000 + scenario_id * 7200 + rng.uniform(0, 3600)
    n_ports = rng.randint(40, 200)
    start_port = rng.randint(1, 60000)
    ports = [(start_port + i) % 65535 or 1 for i in range(n_ports)]
    rng.shuffle(ports)
    rows = []
    for i, port in enumerate(ports):
        rows.append({
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "timestamp": _ts(start + i * rng.uniform(0.05, 0.5)),
            "username": None,
            "event_type": "connection_attempt",
            "failed_attempts": 0,
            "port": port,
            "protocol": rng.choice(["tcp", "udp"]),
            "request_path": None,
            "status_code": None,
            "payload_size": rng.randint(0, 64),
            "device_id": f"host-{rng.randint(1000, 9999)}",
            "_ground_truth": "port_scan",
        })
    return rows


def generate_endpoint_probe(rng: random.Random, scenario_id: int) -> list[dict]:
    attacker_ip = sample_ip_for_country(rng.choice(_ATTACKER_COUNTRIES), rng)
    start = 60000 + scenario_id * 7200 + rng.uniform(0, 3600)
    n_requests = rng.randint(25, 80)
    rows = []
    for i in range(n_requests):
        path = rng.choice(_SUSPICIOUS_PATHS) if rng.random() > 0.2 else rng.choice(_NORMAL_PATHS)
        not_found = path in _SUSPICIOUS_PATHS
        rows.append({
            "source_ip": attacker_ip,
            "destination_ip": _server_ip(rng),
            "timestamp": _ts(start + i * rng.uniform(0.2, 3)),
            "username": None,
            "event_type": "http_request",
            "failed_attempts": 0,
            "port": 443,
            "protocol": "tcp",
            "request_path": path,
            "status_code": 404 if not_found else rng.choice([403, 500]),
            "payload_size": rng.randint(100, 800),
            "device_id": f"host-{rng.randint(1000, 9999)}",
            "_ground_truth": "endpoint_probe",
        })
    return rows


def generate_unknown_anomaly(rng: random.Random, scenario_id: int) -> list[dict]:
    """A slow, low-and-slow exfiltration-like pattern: not enough volume to
    trip any rule threshold, but statistically distinct from baseline
    (huge payloads, narrow off-hours window, single fixed destination) -
    meant to be caught only by Isolation Forest."""
    attacker_ip = sample_ip_for_country(rng.choice(_ATTACKER_COUNTRIES), rng)
    target_ip = _server_ip(rng)
    start = 80000 + scenario_id * 7200 + rng.uniform(0, 3600)
    n_requests = rng.randint(6, 12)
    rows = []
    for i in range(n_requests):
        rows.append({
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "timestamp": _ts(start + i * rng.uniform(240, 400)),  # ~5-6 min apart
            "username": rng.choice(_NORMAL_USERS),
            "event_type": "login_success",
            "failed_attempts": 0,
            "port": 443,
            "protocol": "tcp",
            "request_path": "/api/v1/export",
            "status_code": 200,
            "payload_size": rng.randint(50_000, 200_000),
            "device_id": f"host-{rng.randint(1000, 9999)}",
            "_ground_truth": "unknown_anomaly",
        })
    return rows


SCENARIO_GENERATORS = {
    "brute_force": generate_brute_force,
    "credential_spray": generate_credential_spray,
    "port_scan": generate_port_scan,
    "endpoint_probe": generate_endpoint_probe,
    "unknown_anomaly": generate_unknown_anomaly,
}
