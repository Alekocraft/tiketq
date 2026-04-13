from __future__ import annotations

from datetime import datetime, timedelta, time

BUSINESS_START_HOUR = 8
BUSINESS_END_HOUR = 18
BUSINESS_MINUTES_PER_DAY = (BUSINESS_END_HOUR - BUSINESS_START_HOUR) * 60

_PRIORITY_DEFAULTS = {
    'P1': (60, 240),
    'P2': (120, 1440),
    'P3': (240, 2880),
    'P4': (480, 4320),
    'ALTA': (60, 240),
    'MEDIA': (240, 2880),
    'BAJA': (480, 4320),
}

_PRIORITY_ALIASES = {
    'CRITICA': 'P1',
    'CRÍTICA': 'P1',
    'URGENTE': 'P1',
    'HIGH': 'ALTA',
    'MEDIUM': 'MEDIA',
    'LOW': 'BAJA',
}


def priority_choices() -> list[dict]:
    ordered = [
        ('P1', 'P1'),
        ('P2', 'P2'),
        ('P3', 'P3'),
        ('P4', 'P4'),
        ('ALTA', 'Alta'),
        ('MEDIA', 'Media'),
        ('BAJA', 'Baja'),
    ]
    return [
        {
            'key': key,
            'label': label,
            'response_min': _PRIORITY_DEFAULTS[key][0],
            'resolution_min': _PRIORITY_DEFAULTS[key][1],
        }
        for key, label in ordered
    ]


def normalize_priority(value: str) -> str:
    raw = (value or '').strip().upper()
    if not raw:
        return 'P3'
    raw = _PRIORITY_ALIASES.get(raw, raw)
    if raw in _PRIORITY_DEFAULTS:
        return raw
    return 'P3'


def get_priority_defaults(priority: str) -> tuple[int, int]:
    return _PRIORITY_DEFAULTS.get(normalize_priority(priority), _PRIORITY_DEFAULTS['P3'])


def humanize_minutes(total_minutes: int) -> str:
    try:
        minutes = int(total_minutes or 0)
    except Exception:
        minutes = 0
    if minutes <= 0:
        return '0 min'
    days, rem = divmod(minutes, BUSINESS_MINUTES_PER_DAY)
    hours, mins = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f'{days} d')
    if hours:
        parts.append(f'{hours} h')
    if mins:
        parts.append(f'{mins} min')
    return ' '.join(parts) if parts else '0 min'


def _business_start(dt: datetime) -> datetime:
    return dt.replace(hour=BUSINESS_START_HOUR, minute=0, second=0, microsecond=0)


def _business_end(dt: datetime) -> datetime:
    return dt.replace(hour=BUSINESS_END_HOUR, minute=0, second=0, microsecond=0)


def _align_to_business_time(dt: datetime) -> datetime:
    start = _business_start(dt)
    end = _business_end(dt)
    if dt < start:
        return start
    if dt >= end:
        next_day = dt + timedelta(days=1)
        return _business_start(next_day)
    return dt.replace(second=0, microsecond=0)


def _add_business_minutes(start_at: datetime, minutes: int) -> datetime:
    remaining = max(int(minutes or 0), 0)
    current = _align_to_business_time(start_at)
    if remaining == 0:
        return current

    while remaining > 0:
        end_of_window = _business_end(current)
        available = int((end_of_window - current).total_seconds() // 60)
        if available <= 0:
            current = _business_start(current + timedelta(days=1))
            continue
        step = min(remaining, available)
        current = current + timedelta(minutes=step)
        remaining -= step
        if remaining > 0:
            current = _business_start(current + timedelta(days=1))
    return current


def compute_due_dates(created_at: datetime, response_minutes: int, resolution_minutes: int) -> tuple[datetime, datetime]:
    base = created_at if isinstance(created_at, datetime) else datetime.now()
    response_due = _add_business_minutes(base, int(response_minutes or 0))
    resolution_due = _add_business_minutes(base, int(resolution_minutes or 0))
    return response_due, resolution_due
