import os
from datetime import date, datetime, timedelta

from services.db import select_all
from services.security import int_from_value, text_value

PRIORITY_DEFAULTS = {
    "ALTA": (60, 480),    # respuesta 1h, resolución 8h
    "MEDIA": (240, 960),  # respuesta 4h, resolución 16h
    "BAJA": (480, 2880),  # respuesta 8h, resolución 48h
}

_PRIORITY_MAP = {
    "P1": "ALTA",
    "ALTA": "ALTA",
    "HIGH": "ALTA",
    "P2": "MEDIA",
    "P3": "MEDIA",
    "MEDIA": "MEDIA",
    "MEDIUM": "MEDIA",
    "P4": "BAJA",
    "BAJA": "BAJA",
    "LOW": "BAJA",
}

BUSINESS_START_HOUR = int_from_value(os.getenv("SLA_BUSINESS_START_HOUR"), 7)
BUSINESS_END_HOUR = int_from_value(os.getenv("SLA_BUSINESS_END_HOUR"), 19)
BUSINESS_DAY_MINUTES = max(60, (BUSINESS_END_HOUR - BUSINESS_START_HOUR) * 60)


def normalize_priority(priority_code: str, default: str = "MEDIA") -> str:
    code = (priority_code or "").strip().upper()
    return _PRIORITY_MAP.get(code, default)


def priority_choices():
    return [
        {"key": "ALTA", "label": "Alta", "response_min": 60, "resolution_min": 480},
        {"key": "MEDIA", "label": "Media", "response_min": 240, "resolution_min": 960},
        {"key": "BAJA", "label": "Baja", "response_min": 480, "resolution_min": 2880},
    ]


def get_priority_defaults(priority_code: str):
    code = normalize_priority(priority_code)
    return PRIORITY_DEFAULTS.get(code, PRIORITY_DEFAULTS["MEDIA"])


def _load_holiday_dates() -> set[date]:
    try:
        rows = select_all("SELECT holiday_date FROM dbo.holidays WHERE is_active = 1")
    except Exception:
        return set()

    holidays: set[date] = set()
    for row in rows:
        value = row.get("holiday_date")
        if not value:
            continue
        if isinstance(value, datetime):
            holidays.add(value.date())
        elif isinstance(value, date):
            holidays.add(value)
        else:
            try:
                holidays.add(datetime.fromisoformat(text_value(value)[:10]).date())
            except Exception:
                continue
    return holidays


def _business_bounds(moment: datetime):
    start = moment.replace(hour=BUSINESS_START_HOUR, minute=0, second=0, microsecond=0)
    end = moment.replace(hour=BUSINESS_END_HOUR, minute=0, second=0, microsecond=0)
    return start, end


def _next_business_start(moment: datetime, holidays: set[date]) -> datetime:
    current = moment
    while True:
        start, end = _business_bounds(current)
        if current.date() in holidays:
            current = start + timedelta(days=1)
            continue
        if current < start:
            return start
        if current >= end:
            current = start + timedelta(days=1)
            continue
        return current


def _add_business_minutes(start_at: datetime, minutes: int, holidays: set[date]) -> datetime:
    current = _next_business_start(start_at, holidays)
    remaining = int(minutes or 0)
    if remaining <= 0:
        return current

    while remaining > 0:
        _, day_end = _business_bounds(current)
        available = int((day_end - current).total_seconds() // 60)
        if remaining <= available:
            return current + timedelta(minutes=remaining)
        remaining -= max(0, available)
        current = _next_business_start(day_end + timedelta(seconds=1), holidays)

    return current


def compute_due_dates(created_at: datetime, response_minutes: int, resolution_minutes: int):
    base = created_at or datetime.now()
    holidays = _load_holiday_dates()
    response_due = _add_business_minutes(base, int(response_minutes or 0), holidays)
    resolution_due = _add_business_minutes(base, int(resolution_minutes or 0), holidays)
    return response_due, resolution_due


def humanize_minutes(minutes: int) -> str:
    minutes = int(minutes or 0)
    if minutes >= BUSINESS_DAY_MINUTES and minutes % BUSINESS_DAY_MINUTES == 0:
        days = minutes // BUSINESS_DAY_MINUTES
        return f"{days} día hábil" if days == 1 else f"{days} días hábiles"
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hora" if hours == 1 else f"{hours} horas"
    return f"{minutes} min"
