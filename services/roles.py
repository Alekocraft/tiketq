from __future__ import annotations

from typing import Iterable

ROLE_DEFINITIONS = [
    {"key": "administrador", "label": "Administrador", "queue": False},
    {"key": "gestor_ti", "label": "Gestor TI", "queue": True},
    {"key": "ciberseguridad", "label": "Ciberseguridad", "queue": True},
    {"key": "sugip", "label": "SUGIP", "queue": True},
    {"key": "analista_ti", "label": "Analista TI", "queue": True},
]

SIN_ROL_KEY = "sin_rol"
ROLE_LABELS = {item["key"]: item["label"] for item in ROLE_DEFINITIONS}
OPERATIONAL_ROLES = [item["key"] for item in ROLE_DEFINITIONS if item.get("queue")]
OPERATIONAL_ROLE_SET = set(OPERATIONAL_ROLES)
ADMIN_ROLES = {"administrador"}
RESOLVER_ROLES = set(OPERATIONAL_ROLES) | ADMIN_ROLES
INGEST_ROLES = {"administrador", "gestor_ti"}
GENERAL_CASES_ROLES = {"administrador", "gestor_ti", "sugip"}
BLOCK_GENERAL_CASES_ROLES = {"analista_ti", "ciberseguridad"}
TRIAGE_TARGETS = {
    "administrador": OPERATIONAL_ROLES,
    "gestor_ti": OPERATIONAL_ROLES,
    "sugip": OPERATIONAL_ROLES,
    "ciberseguridad": ["gestor_ti", "sugip"],
    "analista_ti": ["ciberseguridad", "sugip"],
}

ROLE_ALIASES = {
    "admin": "administrador",
    "administrador": "administrador",
    "gestor ti": "gestor_ti",
    "gestor_ti": "gestor_ti",
    "gestor-ti": "gestor_ti",
    "gestor_tic": "gestor_ti",
    "gestor tic": "gestor_ti",
    "ciber": "ciberseguridad",
    "ciberseguridad": "ciberseguridad",
    "suguipq": "sugip",
    "suguip": "sugip",
    "sugip": "sugip",
    "analista ti": "analista_ti",
    "analista_ti": "analista_ti",
    "analista-ti": "analista_ti",
    "sin rol": "sin_rol",
    "sin_rol": "sin_rol",
    "sin-rol": "sin_rol",
}


def normalize_role(value: str | None, default: str = "") -> str:
    raw = str(value or "").strip().lower().replace('-', '_')
    raw = ' '.join(raw.split())
    if not raw:
        return default
    return ROLE_ALIASES.get(raw, raw.replace(' ', '_'))


def normalize_roles(values: Iterable[str] | None) -> list[str]:
    result: list[str] = []
    for value in values or []:
        role = normalize_role(value)
        if role and role not in result:
            result.append(role)
    return result


def role_label(role: str | None) -> str:
    normalized = normalize_role(role)
    if not normalized or normalized == SIN_ROL_KEY:
        return "Sin rol"
    return ROLE_LABELS.get(normalized, normalized.replace('_', ' ').title())


def effective_roles(values: Iterable[str] | None) -> list[str]:
    return [role for role in normalize_roles(values) if role and role != SIN_ROL_KEY]


def has_effective_role(values: Iterable[str] | None) -> bool:
    return bool(effective_roles(values))


def is_roleless(values: Iterable[str] | None) -> bool:
    return not has_effective_role(values)


def role_choices(include_admin: bool = False) -> list[dict]:
    items = ROLE_DEFINITIONS if include_admin else [item for item in ROLE_DEFINITIONS if item.get('queue')]
    return [{"key": item["key"], "label": item["label"]} for item in items]


def is_admin(roles: Iterable[str] | None) -> bool:
    return 'administrador' in set(effective_roles(roles))


def can_resolve(roles: Iterable[str] | None) -> bool:
    return bool(set(effective_roles(roles)) & RESOLVER_ROLES)


def can_ingest(roles: Iterable[str] | None) -> bool:
    return bool(set(effective_roles(roles)) & INGEST_ROLES)


def can_access_general_cases(roles: Iterable[str] | None) -> bool:
    normalized = set(effective_roles(roles))
    if 'administrador' in normalized:
        return True
    if normalized & BLOCK_GENERAL_CASES_ROLES:
        return False
    return bool(normalized & (GENERAL_CASES_ROLES - ADMIN_ROLES))


def triage_targets_for_roles(roles: Iterable[str] | None) -> list[str]:
    normalized = effective_roles(roles)
    ordered: list[str] = []
    for role in normalized:
        for target in TRIAGE_TARGETS.get(role, []):
            if target not in ordered:
                ordered.append(target)
    return ordered


def can_triage(roles: Iterable[str] | None) -> bool:
    return bool(triage_targets_for_roles(roles))


def team_aliases_for_roles(roles: Iterable[str] | None) -> list[str]:
    aliases: list[str] = []
    for role in effective_roles(roles):
        if role in OPERATIONAL_ROLE_SET and role not in aliases:
            aliases.append(role)
    return aliases
