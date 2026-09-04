import pytest
from datetime import datetime, timezone, timedelta

from backend.scheduler.parser import (
    validate_interval_minutes,
    validate_cron_expression,
    calculate_next_run_at,
    parse_interval_preset
)


def test_preset_intervals():
    assert parse_interval_preset("hourly") == 60
    assert parse_interval_preset("every_6_hours") == 360
    assert parse_interval_preset("daily") == 1440
    assert parse_interval_preset("weekly") == 10080
    assert parse_interval_preset("unknown") is None


def test_interval_validation():
    # Valid intervals >= 60
    assert validate_interval_minutes(60)[0] is True
    assert validate_interval_minutes(120)[0] is True
    assert validate_interval_minutes(1440)[0] is True

    # Invalid intervals < 60
    valid_5, err_5 = validate_interval_minutes(5)
    assert valid_5 is False
    assert "violates safety policy" in err_5

    valid_30, err_30 = validate_interval_minutes(30)
    assert valid_30 is False
    assert "minimum allowed interval is 60 minutes" in err_30

    valid_0, _ = validate_interval_minutes(0)
    assert valid_0 is False

    valid_neg, _ = validate_interval_minutes(-10)
    assert valid_neg is False

    valid_none, _ = validate_interval_minutes(None)
    assert valid_none is False


def test_cron_safety_validation_rules():
    # Unsafe cron expressions (frequency < 60 minutes) MUST be rejected
    unsafe_expressions = [
        "* * * * *",       # Every minute
        "*/5 * * * *",     # Every 5 minutes
        "*/10 * * * *",    # Every 10 minutes
        "*/30 * * * *",    # Every 30 minutes
        "0,30 * * * *",    # Twice an hour
        "0-30 * * * *",    # Range of minutes
        "*/59 * * * *",    # Every 59 minutes
    ]
    for expr in unsafe_expressions:
        valid, msg = validate_cron_expression(expr)
        assert valid is False, f"Expected '{expr}' to be REJECTED by safety policy"
        assert "violates safety policy" in msg or "expected 5 fields" in msg

    # Safe cron expressions (frequency >= 60 minutes) MUST be allowed
    safe_expressions = [
        "0 * * * *",       # Hourly on the hour
        "15 * * * *",      # Hourly at minute 15
        "0 */2 * * *",     # Every 2 hours
        "0 */6 * * *",     # Every 6 hours
        "0 0 * * *",       # Daily at midnight
        "30 2 * * *",      # Daily at 02:30
        "0 0 * * 0",       # Weekly on Sunday
        "0 0 1 * *",       # Monthly on the 1st
    ]
    for expr in safe_expressions:
        valid, msg = validate_cron_expression(expr)
        assert valid is True, f"Expected '{expr}' to be ALLOWED, but got error: {msg}"


def test_cron_malformed_expressions():
    assert validate_cron_expression("")[0] is False
    assert validate_cron_expression("not a cron")[0] is False
    assert validate_cron_expression("0 0 0")[0] is False
    assert validate_cron_expression("99 0 * * *")[0] is False  # Invalid minute
    assert validate_cron_expression("0 99 * * *")[0] is False  # Invalid hour


def test_calculate_next_run_interval():
    base = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    next_run = calculate_next_run_at(
        schedule_type="INTERVAL",
        interval_minutes=60,
        from_time=base
    )
    assert next_run == base + timedelta(minutes=60)

    next_daily = calculate_next_run_at(
        schedule_type="INTERVAL",
        interval_minutes=1440,
        from_time=base
    )
    assert next_daily == base + timedelta(days=1)


def test_calculate_next_run_cron():
    base = datetime(2026, 9, 1, 12, 10, 0, tzinfo=timezone.utc)
    # Next run for '0 * * * *' should be 13:00
    next_run = calculate_next_run_at(
        schedule_type="CRON",
        cron_expression="0 * * * *",
        from_time=base
    )
    assert next_run == datetime(2026, 9, 1, 13, 0, 0, tzinfo=timezone.utc)
