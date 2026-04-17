from __future__ import annotations

from flask_login import UserMixin

from services.roles import can_access_general_cases, can_access_sarlaft, can_ingest, can_triage, has_effective_role, normalize_role, normalize_roles, role_label


class User(UserMixin):
    def __init__(
        self,
        username: str,
        display_name: str = "",
        email: str = "",
        role: str = "",
        *,
        roles=None,
        job_title: str = "",
        department: str = "",
        active: bool = True,
    ):
        self.username = (username or "").strip()
        self.display_name = (display_name or self.username or "").strip()
        self.email = (email or "").strip()
        normalized_roles = normalize_roles(roles or ([role] if role else []))
        primary = normalize_role(role) or (normalized_roles[0] if normalized_roles else "")
        if primary and primary not in normalized_roles:
            normalized_roles.insert(0, primary)
        self.role = primary
        self.roles = normalized_roles
        self.job_title = (job_title or "").strip()
        self.department = (department or "").strip()
        self.active = bool(active)

    @property
    def is_active(self) -> bool:
        return bool(self.active) and has_effective_role(self.roles or ([self.role] if self.role else []))

    @property
    def id(self) -> str:
        return self.username

    def get_id(self) -> str:
        return self.username

    @property
    def primary_role_label(self) -> str:
        return role_label(self.role)

    @property
    def role_labels(self) -> list[str]:
        return [role_label(role) for role in self.roles]

    def has_role(self, role: str) -> bool:
        return normalize_role(role) in self.roles

    def has_any_role(self, *roles: str) -> bool:
        wanted = {normalize_role(role) for role in roles if role}
        return bool(wanted & set(self.roles))

    def can_ingest(self) -> bool:
        return can_ingest(self.roles)

    def can_triage(self) -> bool:
        return can_triage(self.roles)

    def can_access_general_cases(self) -> bool:
        return can_access_general_cases(self.roles)

    def can_access_sarlaft(self) -> bool:
        return can_access_sarlaft(self.roles)
