"""Utility for generating synthetic incidents that mirror the in-memory store structure."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import random
from typing import Any, Iterable

CATEGORIES = (
    "Traffic",
    "Cybersecurity",
    "Public Safety",
    "Utilities",
    "Environmental",
)

SEVERITIES = ("low", "medium", "high", "critical")
STATUSES = ("open", "acknowledged", "resolved")

LOCATIONS = {
    "Traffic": (
        "Central Station",
        "Ring Road East",
        "Airport Tunnel",
        "Harbour Bridge",
    ),
    "Cybersecurity": (
        "Datacenter West",
        "Civic Cloud Cluster",
        "Identity Gateway",
        "E-services API",
    ),
    "Public Safety": (
        "Museum Quarter",
        "City Plaza",
        "Riverfront",
        "Stadium District",
    ),
    "Utilities": (
        "Water Treatment Plant",
        "North Power Substation",
        "Waste Processing Hub",
        "District Heating Loop",
    ),
    "Environmental": (
        "Canal District",
        "Urban Forest",
        "Industrial Park",
        "Riverside Wetlands",
    ),
}

SENSOR_IDS = {
    "Traffic": ("traffic-001", "traffic-014", "traffic-027", "traffic-042"),
    "Cybersecurity": ("sec-201", "sec-237", "sec-448", "sec-509"),
    "Public Safety": ("ps-118", "ps-204", "ps-317", "ps-466"),
    "Utilities": ("util-031", "util-066", "util-082", "util-119"),
    "Environmental": ("env-441", "env-552", "env-618", "env-733"),
}

ROOT_CAUSES = (
    "Hardware fault",
    "Human error",
    "External attack",
    "Weather related",
    "Scheduled maintenance",
    "Supply disruption",
    "Sensor malfunction",
    "Network congestion",
)

TITLES = {
    "Traffic": "Traffic congestion alert",
    "Cybersecurity": "Unauthorized access attempt",
    "Public Safety": "Public safety anomaly",
    "Utilities": "Utilities infrastructure warning",
    "Environmental": "Environmental quality deviation",
}

DESCRIPTIONS = {
    "Traffic": "Generated from city mobility telemetry feed.",
    "Cybersecurity": "Generated from perimeter security analytics.",
    "Public Safety": "Generated from surveillance anomaly detection.",
    "Utilities": "Generated from utilities SCADA monitoring.",
    "Environmental": "Generated from distributed environmental sensors.",
}

IMPACTS = {
    "Traffic": "Potential delays across connected routes.",
    "Cybersecurity": "Possible disruption to digital citizen services.",
    "Public Safety": "On-site response team recommended.",
    "Utilities": "Utility delivery stability under review.",
    "Environmental": "Environmental compliance threshold exceeded.",
}

SEVERITY_WEIGHTS = {
    "Traffic": (0.18, 0.39, 0.31, 0.12),
    "Cybersecurity": (0.1, 0.3, 0.37, 0.23),
    "Public Safety": (0.22, 0.33, 0.3, 0.15),
    "Utilities": (0.28, 0.38, 0.24, 0.1),
    "Environmental": (0.34, 0.4, 0.2, 0.06),
}

STATUS_WEIGHTS = {
    "low": (0.55, 0.25, 0.2),
    "medium": (0.33, 0.33, 0.34),
    "high": (0.22, 0.32, 0.46),
    "critical": (0.12, 0.28, 0.6),
}

FALSE_POSITIVE_PROBABILITY = {
    "low": 0.26,
    "medium": 0.14,
    "high": 0.07,
    "critical": 0.03,
}

TRAFFIC_PAYLOAD_RANGES = {
    "low": {
        "vehicle_count": (240, 720),
        "avg_speed_kmh": (26.0, 38.0),
    },
    "medium": {
        "vehicle_count": (680, 1280),
        "avg_speed_kmh": (16.0, 26.0),
    },
    "high": {
        "vehicle_count": (980, 1560),
        "avg_speed_kmh": (10.0, 18.0),
    },
    "critical": {
        "vehicle_count": (1280, 1850),
        "avg_speed_kmh": (4.0, 11.0),
    },
}

CYBER_PAYLOAD_RANGES = {
    "low": {
        "failed_attempts": (45, 140),
        "unique_ips": (4, 12),
    },
    "medium": {
        "failed_attempts": (140, 360),
        "unique_ips": (8, 24),
    },
    "high": {
        "failed_attempts": (360, 760),
        "unique_ips": (18, 44),
    },
    "critical": {
        "failed_attempts": (720, 1200),
        "unique_ips": (32, 70),
    },
}

PUBLIC_SAFETY_ANOMALY_RANGE = {
    "low": (0.32, 0.5),
    "medium": (0.5, 0.7),
    "high": (0.7, 0.88),
    "critical": (0.85, 0.97),
}

UTILITIES_CHLORINE_RANGE = {
    "low": (0.8, 1.3),
    "medium": (0.6, 1.6),
    "high": (0.45, 1.8),
    "critical": (0.3, 2.0),
}

ENVIRONMENTAL_PM25_RANGE = {
    "low": (14.0, 32.0),
    "medium": (28.0, 60.0),
    "high": (54.0, 96.0),
    "critical": (90.0, 150.0),
}

DATASET_SIZE = 1500
RNG_SEED = 20241202


@dataclass(frozen=True)
class IncidentRecord:
    id: int
    title: str
    category: str
    severity: str
    status: str
    detected_at: str
    acknowledged_at: str | None
    resolved_at: str | None
    location: str
    description: str
    impact: str
    root_cause: str | None
    sensor_measurement: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "detected_at": self.detected_at,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "location": self.location,
            "description": self.description,
            "impact": self.impact,
            "root_cause": self.root_cause,
            "sensor_measurement": self.sensor_measurement,
        }


def _pick_severity(category: str, rng: random.Random) -> str:
    return rng.choices(SEVERITIES, weights=SEVERITY_WEIGHTS[category], k=1)[0]


def _pick_status(severity: str, rng: random.Random) -> str:
    return rng.choices(STATUSES, weights=STATUS_WEIGHTS[severity], k=1)[0]


def _detected_at(index: int, rng: random.Random) -> datetime:
    window_days = 90
    minutes_offset = rng.randint(0, window_days * 24 * 60)
    base = datetime.now(UTC)
    return base - timedelta(minutes=minutes_offset + index * 3)


def _acknowledged_and_resolved(
    status: str,
    severity: str,
    detected_at: datetime,
    rng: random.Random,
) -> tuple[str | None, str | None]:
    ack_bounds = {
        "low": (45, 360),
        "medium": (30, 180),
        "high": (10, 90),
        "critical": (3, 45),
    }
    res_bounds = {
        "low": (240, 1440),
        "medium": (180, 960),
        "high": (120, 720),
        "critical": (60, 480),
    }

    if status == "open":
        return None, None

    ack_min, ack_max = ack_bounds[severity]
    ack_minutes = rng.randint(ack_min, ack_max)
    acknowledged = detected_at + timedelta(minutes=ack_minutes)

    if status == "acknowledged":
        return acknowledged.isoformat(), None

    res_min, res_max = res_bounds[severity]
    resolve_minutes = rng.randint(res_min, res_max)
    resolved = acknowledged + timedelta(minutes=resolve_minutes)
    return acknowledged.isoformat(), resolved.isoformat()


def _root_cause(severity: str, false_positive: bool, rng: random.Random) -> str | None:
    if false_positive:
        return None
    return rng.choice(ROOT_CAUSES)


def _choose_location(category: str, rng: random.Random) -> str:
    return rng.choice(LOCATIONS[category])


def _choose_title(category: str) -> str:
    return TITLES[category]


def _choose_description(category: str) -> str:
    return DESCRIPTIONS[category]


def _choose_impact(category: str, severity: str) -> str:
    base = IMPACTS[category]
    if severity in {"high", "critical"}:
        return f"{base} Escalation priority elevated."
    return base


def _sensor_status(severity: str, false_positive: bool, rng: random.Random) -> str:
    if false_positive:
        return rng.choices(["healthy", "warning"], weights=[0.7, 0.3], k=1)[0]
    if severity == "critical":
        return rng.choices(["alert", "warning"], weights=[0.8, 0.2], k=1)[0]
    if severity == "high":
        return rng.choices(["alert", "warning", "healthy"], weights=[0.5, 0.35, 0.15], k=1)[0]
    if severity == "medium":
        return rng.choices(["warning", "healthy", "alert"], weights=[0.55, 0.35, 0.1], k=1)[0]
    return rng.choices(["healthy", "warning"], weights=[0.75, 0.25], k=1)[0]


def _traffic_payload(severity: str, rng: random.Random) -> dict[str, Any]:
    bounds = TRAFFIC_PAYLOAD_RANGES[severity]
    vehicle_count = rng.randint(*bounds["vehicle_count"])
    avg_speed = round(rng.uniform(*bounds["avg_speed_kmh"]), 1)
    return {
        "vehicle_count": vehicle_count,
        "avg_speed_kmh": avg_speed,
    }


def _cyber_payload(severity: str, rng: random.Random) -> dict[str, Any]:
    bounds = CYBER_PAYLOAD_RANGES[severity]
    failed_attempts = rng.randint(*bounds["failed_attempts"])
    unique_ips = rng.randint(*bounds["unique_ips"])
    return {
        "failed_attempts": failed_attempts,
        "unique_ips": unique_ips,
    }


def _public_safety_payload(severity: str, rng: random.Random) -> dict[str, Any]:
    anomaly = round(rng.uniform(*PUBLIC_SAFETY_ANOMALY_RANGE[severity]), 2)
    return {
        "anomaly_score": anomaly,
    }


def _utilities_payload(severity: str, rng: random.Random) -> dict[str, Any]:
    chlorine = round(rng.uniform(*UTILITIES_CHLORINE_RANGE[severity]), 2)
    ph = round(rng.uniform(6.5, 8.3), 2)
    return {
        "chlorine_ppm": chlorine,
        "ph": ph,
    }


def _environmental_payload(severity: str, rng: random.Random) -> dict[str, Any]:
    pm25 = round(rng.uniform(*ENVIRONMENTAL_PM25_RANGE[severity]), 1)
    return {
        "pm2_5": pm25,
    }


def _sensor_payload(category: str, severity: str, rng: random.Random) -> dict[str, Any]:
    if category == "Traffic":
        return _traffic_payload(severity, rng)
    if category == "Cybersecurity":
        return _cyber_payload(severity, rng)
    if category == "Public Safety":
        return _public_safety_payload(severity, rng)
    if category == "Utilities":
        return _utilities_payload(severity, rng)
    return _environmental_payload(severity, rng)


def _sensor_measurement(
    category: str,
    severity: str,
    detected_at: datetime,
    false_positive: bool,
    rng: random.Random,
) -> dict[str, Any]:
    sensor_id = rng.choice(SENSOR_IDS[category])
    status = _sensor_status(severity, false_positive, rng)
    captured_at = detected_at - timedelta(minutes=rng.randint(1, 12))
    payload = _sensor_payload(category, severity, rng)
    return {
        "sensor_id": sensor_id,
        "type": category,
        "status": status,
        "captured_at": captured_at.isoformat(),
        "payload": payload,
    }


def _build_record(index: int, rng: random.Random) -> IncidentRecord:
    category = rng.choice(CATEGORIES)
    severity = _pick_severity(category, rng)
    status = _pick_status(severity, rng)
    detected_at_dt = _detected_at(index, rng)
    detected_at = detected_at_dt.isoformat()
    false_positive = rng.random() < FALSE_POSITIVE_PROBABILITY[severity]
    acknowledged_at, resolved_at = _acknowledged_and_resolved(status, severity, detected_at_dt, rng)

    return IncidentRecord(
        id=1000 + index,
        title=_choose_title(category),
        category=category,
        severity=severity,
        status=status,
        detected_at=detected_at,
        acknowledged_at=acknowledged_at,
        resolved_at=resolved_at,
        location=_choose_location(category, rng),
        description=_choose_description(category),
        impact=_choose_impact(category, severity),
        root_cause=_root_cause(severity, false_positive, rng),
        sensor_measurement=_sensor_measurement(category, severity, detected_at_dt, false_positive, rng),
    )


def generate_dataset(size: int = DATASET_SIZE, seed: int = RNG_SEED) -> list[IncidentRecord]:
    rng = random.Random(seed)
    return [_build_record(index, rng) for index in range(size)]


def write_dataset(records: Iterable[IncidentRecord], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    serialised = [record.to_dict() for record in records]
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(serialised, handle, indent=2)


DEFAULT_OUTPUT = Path(__file__).parent / "data" / "synthetic_incidents.json"


def main() -> None:
    dataset = generate_dataset()
    write_dataset(dataset, DEFAULT_OUTPUT)
    print(f"Wrote {len(dataset)} synthetic incidents to {DEFAULT_OUTPUT}")


if __name__ == "__main__":
    main()
