from typing import Dict, Any


VALID_SCHEDULE_INTERVALS = {
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800
}


def validate_schedule_interval(interval: str) -> bool:
    """
    Check if a schedule interval string is valid.
    """
    return interval.lower() in VALID_SCHEDULE_INTERVALS


def get_interval_seconds(interval: str) -> int:
    """
    Get duration in seconds for a schedule interval.
    """
    return VALID_SCHEDULE_INTERVALS.get(interval.lower(), 86400)
