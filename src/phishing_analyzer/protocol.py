"""Shared temporal rules for preregistered offline evaluations."""
from datetime import datetime, timezone

CUTOFF = datetime(2026, 10, 23, tzinfo=timezone.utc)


def parse_time(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Missing UTC timestamp")
    try:
        date = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Malformed UTC timestamp") from exc
    if date.tzinfo is None or date.utcoffset().total_seconds() != 0:
        raise ValueError("Timestamp must carry UTC offset Z/+00:00")
    return date.astimezone(timezone.utc)


def evaluation_time(now=None):
    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset().total_seconds() != 0:
        raise ValueError("Evaluation time must be explicit UTC")
    return current


def valid_window(observed, verified, current, cutoff=CUTOFF):
    return cutoff <= observed <= verified <= current
