from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_GENERIC_PUBLIC_ERROR = "Ocurrió un error al procesar la solicitud."
_GENERIC_PUBLIC_MAIL_ERROR = "No fue posible enviar la notificación en este momento."


def text_value(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore").strip()
        except Exception:
            return default
    return f"{value}".strip()


def bool_from_value(value: Any, default: bool = False) -> bool:
    normalized = text_value(value)
    if not normalized:
        return default
    return normalized.lower() in {"1", "true", "yes", "y", "on"}


def int_from_value(value: Any, default: int) -> int:
    try:
        return int(text_value(value) or default)
    except Exception:
        return default


def path_text(value: os.PathLike[str] | str) -> str:
    return os.fspath(value)


def public_error_message(default: str | None = None) -> str:
    return default or _GENERIC_PUBLIC_ERROR


def public_mail_message(status: Any = None) -> str:
    code = text_value(status).upper()
    safe_messages = {
        "SMTP_NOT_CONFIGURED": "El correo saliente no está configurado.",
        "SMTP_HOST_NO_CONFIGURADO": "El correo saliente no está configurado.",
        "DESTINATARIO_VACIO": "No hay un destinatario válido para la notificación.",
        "MAIL_SEND_FAILED": _GENERIC_PUBLIC_MAIL_ERROR,
        "MAIL_SEND_ERROR": _GENERIC_PUBLIC_MAIL_ERROR,
        "DIRECTORY_SERVICE_UNAVAILABLE": "El servicio de directorio no está disponible en este momento.",
        "LDAP_DISABLED": "La autenticación LDAP está deshabilitada.",
    }
    return safe_messages.get(code, _GENERIC_PUBLIC_MAIL_ERROR)


def secure_status_code(status: Any, *, fallback: str = "OPERATION_FAILED") -> str:
    code = text_value(status).upper().replace(" ", "_")
    if not code:
        return fallback
    safe = []
    for ch in code:
        if ch.isalnum() or ch == "_":
            safe.append(ch)
    normalized = "".join(safe).strip("_")
    return normalized[:80] or fallback


def sanitize_log_text(value: Any, default: str = "NA", *, max_length: int = 120) -> str:
    raw = text_value(value, default)
    if not raw:
        return default

    cleaned = []
    for ch in raw:
        if ch in {"\r", "\n", "\t"}:
            cleaned.append(" ")
        elif ch.isprintable() and (ch.isalnum() or ch in {" ", "_", "-", ".", "@", ":", "/", "#"}):
            cleaned.append(ch)
        else:
            cleaned.append("_")

    normalized = " ".join("".join(cleaned).split())
    return normalized[:max_length] or default


# Alias en español para validadores/reglas internas.
sanitar_log_text = sanitize_log_text
sanitizar_log_text = sanitize_log_text


def _adhoc_ssl_available() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except Exception:
        return False


def dev_ssl_context() -> str | tuple[str, str] | None:
    cert_file = text_value(os.getenv("SSL_CERT_FILE"))
    key_file = text_value(os.getenv("SSL_KEY_FILE"))
    if cert_file and key_file and Path(cert_file).exists() and Path(key_file).exists():
        return cert_file, key_file

    if not bool_from_value(os.getenv("USE_HTTPS_DEV"), False):
        return None

    if _adhoc_ssl_available():
        return "adhoc"

    return None
