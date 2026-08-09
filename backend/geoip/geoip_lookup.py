"""Offline, bundled IP -> country/city lookup.

`country_ranges.csv` is a small, illustrative IP-range-to-location table
shipped with this repo. It is NOT a production-grade GeoIP database (no
MaxMind/IP2Location signup or license involved) - it exists purely to make
the dashboard's "geographic distribution" analytics meaningful for demo and
synthetic data without any external service calls or account requirements.
Real-world accuracy is approximate; unmatched IPs resolve to "Unknown".
"""

import csv
import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_CSV_PATH = Path(__file__).parent / "country_ranges.csv"

UNKNOWN_LOCATION = {
    "country": "Unknown",
    "country_code": "XX",
    "city": "Unknown",
    "lat": None,
    "lon": None,
}


@dataclass(frozen=True)
class _Range:
    network: ipaddress.IPv4Network
    country: str
    country_code: str
    city: str
    lat: float
    lon: float


@lru_cache(maxsize=1)
def _load_ranges() -> list[_Range]:
    ranges = []
    with open(_CSV_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ranges.append(
                _Range(
                    network=ipaddress.ip_network(row["cidr"]),
                    country=row["country"],
                    country_code=row["country_code"],
                    city=row["city"],
                    lat=float(row["lat"]),
                    lon=float(row["lon"]),
                )
            )
    # longest-prefix-match first
    ranges.sort(key=lambda r: r.network.prefixlen, reverse=True)
    return ranges


def lookup(ip_str: str) -> dict:
    try:
        ip = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return dict(UNKNOWN_LOCATION)

    if not isinstance(ip, ipaddress.IPv4Address):
        return dict(UNKNOWN_LOCATION)

    for r in _load_ranges():
        if ip in r.network:
            return {
                "country": r.country,
                "country_code": r.country_code,
                "city": r.city,
                "lat": r.lat,
                "lon": r.lon,
            }
    return dict(UNKNOWN_LOCATION)


def sample_ip_for_country(country_code: str, rng) -> str:
    """Used by the synthetic data generator to draw a plausible IP that will
    resolve back to a given country via this same lookup table."""
    candidates = [r for r in _load_ranges() if r.country_code == country_code]
    if not candidates:
        raise ValueError(f"No range defined for country code {country_code}")
    network = rng.choice(candidates).network
    host_bits = network.max_prefixlen - network.prefixlen
    offset = rng.randint(1, max(1, (2**host_bits) - 2))
    return str(network.network_address + offset)
