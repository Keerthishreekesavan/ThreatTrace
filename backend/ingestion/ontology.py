"""Canonical cybersecurity event ontology.

Every concept below is what the semantic column mapper tries to match
incoming, arbitrarily-named columns against. Each concept carries a rich
natural-language description (used to build its embedding) plus light
metadata that the semantic analyzer can use as corroborating signal
(expected dtype, value-shape hints) when scoring a candidate column.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class OntologyConcept:
    key: str
    display_name: str
    description: str
    expected_dtype: str  # "ip", "datetime", "categorical", "integer", "string"
    name_hints: tuple[str, ...] = field(default_factory=tuple)


ONTOLOGY: list[OntologyConcept] = [
    OntologyConcept(
        key="source_ip",
        display_name="Source IP Address",
        description=(
            "The IP address that originated or initiated the network connection, "
            "request, or authentication attempt. Also called client IP, requester "
            "address, or originating host."
        ),
        expected_dtype="ip",
        name_hints=("src", "source", "client", "origin", "from"),
    ),
    OntologyConcept(
        key="destination_ip",
        display_name="Destination IP Address",
        description=(
            "The IP address that received the network connection or request, such "
            "as the target server, host, or endpoint being contacted. Also called "
            "server IP, target address, or destination host."
        ),
        expected_dtype="ip",
        name_hints=("dst", "dest", "destination", "target", "server", "to"),
    ),
    OntologyConcept(
        key="timestamp",
        display_name="Event Timestamp",
        description=(
            "The date and time at which the logged event occurred, was recorded, "
            "or was created. Often an ISO 8601 datetime, epoch value, or "
            "human-readable date string."
        ),
        expected_dtype="datetime",
        name_hints=("time", "date", "timestamp", "occurred", "created", "logged"),
    ),
    OntologyConcept(
        key="username",
        display_name="User Identifier",
        description=(
            "The account name, user identifier, or login name associated with the "
            "event, such as the username attempting authentication or performing "
            "an action."
        ),
        expected_dtype="string",
        name_hints=("user", "username", "account", "acct", "login", "uid"),
    ),
    OntologyConcept(
        key="event_type",
        display_name="Authentication / Event Type",
        description=(
            "The category or type of event being logged, such as login success, "
            "login failure, logout, access granted, access denied, or connection "
            "attempt. Describes what kind of action took place."
        ),
        expected_dtype="categorical",
        name_hints=("event", "action", "type", "status", "auth", "result"),
    ),
    OntologyConcept(
        key="failed_attempts",
        display_name="Failed Login Count",
        description=(
            "A numeric count of failed authentication attempts, login failures, "
            "authentication errors, or unsuccessful access tries associated with "
            "a user or IP address."
        ),
        expected_dtype="integer",
        name_hints=("fail", "failed", "failure", "denied", "invalid", "error"),
    ),
    OntologyConcept(
        key="source_location",
        display_name="Source Location",
        description=(
            "The geographic location, country, region, or city associated with "
            "the source of an event, typically derived from IP geolocation."
        ),
        expected_dtype="string",
        name_hints=("location", "country", "region", "city", "geo"),
    ),
    OntologyConcept(
        key="port",
        display_name="Destination Port",
        description=(
            "The network port number that was contacted or targeted, such as a "
            "TCP or UDP destination port used to identify a service (e.g. 22, "
            "80, 443, 3389)."
        ),
        expected_dtype="integer",
        name_hints=("port", "dport", "service_port"),
    ),
    OntologyConcept(
        key="protocol",
        display_name="Network Protocol",
        description=(
            "The network or application protocol used for the connection or "
            "request, such as TCP, UDP, ICMP, HTTP, HTTPS, SSH, or FTP."
        ),
        expected_dtype="categorical",
        name_hints=("protocol", "proto"),
    ),
    OntologyConcept(
        key="request_path",
        display_name="Request Type / Path",
        description=(
            "The HTTP method and URL path or endpoint requested, such as a web "
            "request URI, API route, or resource path being accessed."
        ),
        expected_dtype="string",
        name_hints=("path", "url", "uri", "endpoint", "request", "resource"),
    ),
    OntologyConcept(
        key="status_code",
        display_name="Response Code",
        description=(
            "The response or status code returned for a request, such as an "
            "HTTP status code (200, 404, 403, 500) or an authentication result "
            "code indicating success or failure."
        ),
        expected_dtype="integer",
        name_hints=("status", "code", "response", "resp"),
    ),
    OntologyConcept(
        key="payload_size",
        display_name="Payload Size",
        description=(
            "The size in bytes of the request or response payload, packet, or "
            "transferred data associated with the event. Also called data "
            "length, content length, or byte count."
        ),
        expected_dtype="integer",
        name_hints=("size", "bytes", "length", "payload", "len"),
    ),
    OntologyConcept(
        key="device_id",
        display_name="Device Identifier",
        description=(
            "A unique identifier for the device, host, asset, or endpoint "
            "involved in the event, such as a hostname, MAC address, or asset "
            "tag."
        ),
        expected_dtype="string",
        name_hints=("device", "host", "hostname", "asset", "mac"),
    ),
]

ONTOLOGY_BY_KEY: dict[str, OntologyConcept] = {c.key: c for c in ONTOLOGY}

# Columns whose best-matching concept scores below this (softmax-calibrated,
# 0-1) confidence are left unmapped and preserved verbatim rather than
# forced into a canonical field.
MIN_MAPPING_CONFIDENCE = 0.35
