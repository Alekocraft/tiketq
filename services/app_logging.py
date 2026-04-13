from __future__ import annotations

import json
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from flask import has_app_context

from services.security import sanitize_log_text, text_value

APP_LOGGER_NAME = "solucionati"
LOG_FORMAT = (
    "%(asctime)s | %(levelname)s | %(log_category)s | %(event_name)s | %(source_name)s | "
    "user=%(user_id)s | case=%(case_id)s | status=%(status_code)s | %(message)s"
)
LOG_CATEGORIES = (
    "SYSTEM",
    "SECURITY",
    "NOTIFICATION",
    "EMAIL",
    "CASE",
    "AUDIT",
    "GENERAL",
)
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class _DefaultLogFieldsFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.log_category = getattr(record, "log_category", "GENERAL")
        record.event_name = getattr(record, "event_name", "UNSPECIFIED_EVENT")
        record.source_name = getattr(record, "source_name", "application")
        record.user_id = getattr(record, "user_id", "anonymous")
        record.case_id = getattr(record, "case_id", "NA")
        record.status_code = getattr(record, "status_code", "NA")
        return True


class _CategoryFilter(logging.Filter):
    def __init__(self, category: str):
        super().__init__()
        self.category = category

    def filter(self, record: logging.LogRecord) -> bool:
        return getattr(record, "log_category", "GENERAL") == self.category


_DEFAULT_FILTER = _DefaultLogFieldsFilter()


def _normalize_category(value: Any) -> str:
    normalized = sanitize_log_text(value, default="GENERAL", max_length=32).upper().replace("-", "_").replace(" ", "_")
    if normalized not in LOG_CATEGORIES:
        return "GENERAL"
    return normalized



def _normalize_level(value: Any) -> str:
    normalized = sanitize_log_text(value, default="INFO", max_length=16).upper()
    return normalized if normalized in LOG_LEVELS else "INFO"



def _safe_text(value: Any, default: str = "NA", *, max_length: int = 240) -> str:
    return sanitize_log_text(value, default=default, max_length=max_length)



def _safe_metadata(metadata: Any) -> str | None:
    if not metadata:
        return None
    safe_payload: dict[str, str] = {}
    if isinstance(metadata, dict):
        items = metadata.items()
    else:
        items = [("value", metadata)]

    for raw_key, raw_value in items:
        key = _safe_text(raw_key, default="key", max_length=40).lower()
        if not key:
            continue
        if isinstance(raw_value, bool):
            value = "true" if raw_value else "false"
        elif raw_value is None:
            value = "null"
        else:
            value = _safe_text(raw_value, default="NA", max_length=120)
        safe_payload[key] = value

    if not safe_payload:
        return None
    return json.dumps(safe_payload, ensure_ascii=False, sort_keys=True)



def _log_dir_from_app(app=None) -> Path:
    configured = text_value(os.getenv("APP_LOG_DIR"))
    if configured:
        path = Path(configured)
        if not path.is_absolute() and app is not None:
            path = Path(app.instance_path) / path
        return path

    if app is not None:
        return Path(app.instance_path) / "logs"
    return Path.cwd() / "instance" / "logs"



def configure_logging(app) -> None:
    if app.config.get("CLASSIFIED_LOGGING_READY"):
        return

    log_dir = _log_dir_from_app(app)
    log_dir.mkdir(parents=True, exist_ok=True)

    base_logger = logging.getLogger(APP_LOGGER_NAME)
    base_logger.setLevel(logging.INFO)
    base_logger.propagate = False

    formatter = logging.Formatter(LOG_FORMAT)

    if not any(getattr(handler, "_solucionati_handler", False) for handler in base_logger.handlers):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(_DEFAULT_FILTER)
        console_handler._solucionati_handler = True
        base_logger.addHandler(console_handler)

        combined_handler = RotatingFileHandler(
            log_dir / "application.log",
            maxBytes=1_048_576,
            backupCount=5,
            encoding="utf-8",
        )
        combined_handler.setLevel(logging.INFO)
        combined_handler.setFormatter(formatter)
        combined_handler.addFilter(_DEFAULT_FILTER)
        combined_handler._solucionati_handler = True
        base_logger.addHandler(combined_handler)

        for category in LOG_CATEGORIES:
            category_handler = RotatingFileHandler(
                log_dir / f"{category.lower()}.log",
                maxBytes=524_288,
                backupCount=4,
                encoding="utf-8",
            )
            category_handler.setLevel(logging.INFO)
            category_handler.setFormatter(formatter)
            category_handler.addFilter(_DEFAULT_FILTER)
            category_handler.addFilter(_CategoryFilter(category))
            category_handler._solucionati_handler = True
            base_logger.addHandler(category_handler)

    app.logger.handlers = []
    for handler in base_logger.handlers:
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False
    app.config["CLASSIFIED_LOGGING_READY"] = True



def _resolve_user_id(explicit_user_id: Any = None) -> str:
    if explicit_user_id is not None:
        return _safe_text(explicit_user_id, default="anonymous", max_length=120)

    if not has_app_context():
        return "system"

    try:
        from flask_login import current_user  # noqa: WPS433

        if getattr(current_user, "is_authenticated", False):
            return _safe_text(getattr(current_user, "username", None) or getattr(current_user, "id", None), default="authenticated", max_length=120)
    except Exception:
        return "system"

    return "anonymous"



def _persist_db(
    *,
    category: str,
    level: str,
    event: str,
    detail: str,
    source: str,
    user_id: str,
    case_id: str | None,
    status: str,
    metadata_json: str | None,
) -> None:
    if not has_app_context():
        return
    if not os.getenv("MSSQL_CONN_STR", "").strip():
        return

    try:
        from services.db import commit, execute  # noqa: WPS433

        execute(
            """
            INSERT INTO dbo.app_logs
                (category, level, event_name, detail, source_name, user_id, case_id, status_code, metadata_json, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,SYSDATETIME())
            """,
            (
                category,
                level,
                event,
                detail,
                source,
                user_id,
                case_id,
                status,
                metadata_json,
            ),
        )
        commit()
    except Exception:
        return



def log_event(
    category: Any,
    level: Any,
    event: Any,
    *,
    detail: Any = "",
    source: Any = "application",
    user_id: Any = None,
    case_id: Any = None,
    status: Any = "OK",
    metadata: Any = None,
    persist_db: bool = True,
) -> None:
    normalized_category = _normalize_category(category)
    normalized_level = _normalize_level(level)
    normalized_event = _safe_text(event, default="UNSPECIFIED_EVENT", max_length=80).upper().replace(" ", "_")
    normalized_detail = _safe_text(detail, default=normalized_event, max_length=240)
    normalized_source = _safe_text(source, default="application", max_length=80)
    normalized_user_id = _resolve_user_id(user_id)
    normalized_case_id = _safe_text(case_id, default="NA", max_length=30) if case_id else "NA"
    normalized_status = _safe_text(status, default="OK", max_length=80).upper().replace(" ", "_")
    metadata_json = _safe_metadata(metadata)

    logger = logging.getLogger(APP_LOGGER_NAME)
    logger.log(
        LOG_LEVELS[normalized_level],
        normalized_detail,
        extra={
            "log_category": normalized_category,
            "event_name": normalized_event,
            "source_name": normalized_source,
            "user_id": normalized_user_id,
            "case_id": normalized_case_id,
            "status_code": normalized_status,
        },
    )

    if persist_db:
        _persist_db(
            category=normalized_category,
            level=normalized_level,
            event=normalized_event,
            detail=normalized_detail,
            source=normalized_source,
            user_id=normalized_user_id,
            case_id=None if normalized_case_id == "NA" else normalized_case_id,
            status=normalized_status,
            metadata_json=metadata_json,
        )



def log_exception(
    category: Any,
    event: Any,
    exc: Exception,
    *,
    source: Any = "application",
    user_id: Any = None,
    case_id: Any = None,
    status: Any = "FAILED",
    metadata: Any = None,
) -> None:
    log_event(
        category,
        "ERROR",
        event,
        detail="UNEXPECTED_ERROR",
        source=source,
        user_id=user_id,
        case_id=case_id,
        status=status,
        metadata=metadata,
    )
