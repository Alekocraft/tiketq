from datetime import datetime, timedelta

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


def compute_due_dates(created_at: datetime, response_minutes: int, resolution_minutes: int):
    return created_at + timedelta(minutes=int(response_minutes)), created_at + timedelta(minutes=int(resolution_minutes))


def humanize_minutes(minutes: int) -> str:
    minutes = int(minutes or 0)
    if minutes % 1440 == 0:
        days = minutes // 1440
        return f"{days} día" if days == 1 else f"{days} días"
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hora" if hours == 1 else f"{hours} horas"
    return f"{minutes} min"
