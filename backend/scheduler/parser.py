import re
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional, Set

PRESET_INTERVALS = {
    "hourly": 60,
    "every_6_hours": 360,
    "daily": 1440,
    "weekly": 10080
}

MINIMUM_INTERVAL_MINUTES = 60


def parse_interval_preset(preset: str) -> Optional[int]:
    """
    Map interval preset names to minute durations.
    """
    return PRESET_INTERVALS.get(preset.lower())


def validate_interval_minutes(minutes: Optional[int]) -> Tuple[bool, str]:
    """
    Validate that an interval schedule satisfies the minimum safety frequency of 60 minutes.
    """
    if minutes is None:
        return False, "Interval minutes must be specified."
    if minutes < MINIMUM_INTERVAL_MINUTES:
        return False, f"Schedule interval of {minutes} minutes violates safety policy: minimum allowed interval is {MINIMUM_INTERVAL_MINUTES} minutes."
    if minutes > 525600:  # 1 year
        return False, "Schedule interval exceeds maximum allowable duration (1 year)."
    return True, ""


def validate_cron_expression(expr: Optional[str]) -> Tuple[bool, str]:
    """
    Safely validate a standard 5-part cron expression and enforce the 60-minute minimum frequency policy.
    Format: 'minute hour day_of_month month day_of_week'
    
    Safety Policy:
    - Minute field MUST resolve to a single integer (0-59).
    - Wildcard '*', steps '*/N', ranges '0-30', and lists '0,30' in the minute field are REJECTED.
    """
    if not expr or not expr.strip():
        return False, "Cron expression cannot be empty."

    parts = expr.strip().split()
    if len(parts) != 5:
        return False, f"Invalid cron expression '{expr}': expected 5 fields (minute hour dom month dow)."

    min_part, hour_part, dom_part, month_part, dow_part = parts

    # 1. Enforce Minimum 60-Minute Execution Frequency on Minute Field
    # Minute field MUST be a single integer between 0 and 59
    if not re.match(r"^\d{1,2}$", min_part):
        return False, (
            f"Cron expression '{expr}' violates safety policy: minute field '{min_part}' "
            "permits execution more frequent than once per 60 minutes. Only single fixed minutes (e.g. '0', '15', '30') are allowed."
        )

    try:
        min_val = int(min_part)
        if not (0 <= min_val <= 59):
            return False, f"Minute value '{min_val}' is out of range (0-59)."
    except ValueError:
        return False, f"Invalid minute field '{min_part}'."

    # 2. Validate Hour Field
    if not _validate_cron_field(hour_part, 0, 23):
        return False, f"Invalid hour field '{hour_part}' in cron expression."

    # 3. Validate Day of Month Field
    if not _validate_cron_field(dom_part, 1, 31):
        return False, f"Invalid day-of-month field '{dom_part}' in cron expression."

    # 4. Validate Month Field
    if not _validate_cron_field(month_part, 1, 12):
        return False, f"Invalid month field '{month_part}' in cron expression."

    # 5. Validate Day of Week Field
    if not _validate_cron_field(dow_part, 0, 7):
        return False, f"Invalid day-of-week field '{dow_part}' in cron expression."

    return True, ""


def _validate_cron_field(field_str: str, min_val: int, max_val: int) -> bool:
    if field_str == "*":
        return True
    
    # Step syntax: */N or 0-23/N
    step_match = re.match(r"^(\*|\d+-\d+|\d+)/(\d+)$", field_str)
    if step_match:
        step = int(step_match.group(2))
        return step > 0

    # Range syntax: N-M
    range_match = re.match(r"^(\d+)-(\d+)$", field_str)
    if range_match:
        start, end = int(range_match.group(1)), int(range_match.group(2))
        return min_val <= start <= end <= max_val

    # List syntax: N,M,...
    for item in field_str.split(","):
        if not item.isdigit():
            return False
        val = int(item)
        if not (min_val <= val <= max_val):
            return False

    return True


def _match_field_values(field_str: str, min_val: int, max_val: int) -> Set[int]:
    if field_str == "*":
        return set(range(min_val, max_val + 1))
    
    values = set()
    for part in field_str.split(","):
        step_match = re.match(r"^(\*|\d+-\d+|\d+)/(\d+)$", part)
        if step_match:
            base, step_str = step_match.group(1), step_match.group(2)
            step = int(step_str)
            if step <= 0:
                continue
            if base == "*":
                rng = range(min_val, max_val + 1, step)
            elif "-" in base:
                s, e = map(int, base.split("-"))
                rng = range(s, e + 1, step)
            else:
                rng = range(int(base), max_val + 1, step)
            values.update([v for v in rng if min_val <= v <= max_val])
            continue

        range_match = re.match(r"^(\d+)-(\d+)$", part)
        if range_match:
            s, e = int(range_match.group(1)), int(range_match.group(2))
            values.update([v for v in range(s, e + 1) if min_val <= v <= max_val])
            continue

        if part.isdigit():
            v = int(part)
            if min_val <= v <= max_val:
                values.add(v)

    return values


def calculate_next_run_at(
    schedule_type: str,
    interval_minutes: Optional[int] = None,
    cron_expression: Optional[str] = None,
    from_time: Optional[datetime] = None
) -> datetime:
    """
    Calculate the next execution timestamp based on schedule type and configuration.
    """
    base_time = from_time or datetime.now(timezone.utc)
    if base_time.tzinfo is None:
        base_time = base_time.replace(tzinfo=timezone.utc)

    st_type = schedule_type.upper() if schedule_type else "INTERVAL"

    if st_type == "INTERVAL":
        minutes = interval_minutes if interval_minutes is not None else 1440
        safe_minutes = max(MINIMUM_INTERVAL_MINUTES, minutes)
        return base_time + timedelta(minutes=safe_minutes)

    if st_type == "CRON":
        if not cron_expression:
            return base_time + timedelta(minutes=1440)

        parts = cron_expression.strip().split()
        if len(parts) != 5:
            return base_time + timedelta(minutes=1440)

        target_minute = int(parts[0])
        hours = _match_field_values(parts[1], 0, 23)
        doms = _match_field_values(parts[2], 1, 31)
        months = _match_field_values(parts[3], 1, 12)
        dows = _match_field_values(parts[4], 0, 6)
        if 7 in _match_field_values(parts[4], 0, 7):
            dows.add(0)

        curr = base_time.replace(second=0, microsecond=0) + timedelta(minutes=1)

        # Search up to 366 days
        max_steps = 366 * 24
        for _ in range(max_steps):
            if curr.month in months and curr.day in doms:
                dow_python = (curr.weekday() + 1) % 7  # 0=Sunday, 6=Saturday
                if dow_python in dows and curr.hour in hours:
                    next_dt = curr.replace(minute=target_minute)
                    if next_dt > base_time:
                        return next_dt
            curr = (curr + timedelta(hours=1)).replace(minute=0)

        return base_time + timedelta(days=1)

    return base_time + timedelta(minutes=1440)
