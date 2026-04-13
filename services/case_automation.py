from __future__ import annotations

import os
import secrets
import socket
from typing import Any

from flask import current_app, has_app_context, has_request_context, request

from services.db import commit, execute, rollback, select_all, select_one
from services.mail import send_mail
from services.security import secure_status_code, text_value

AUTO_CLOSE_NOTE = (
    "Cierre automático del caso 24 horas después de marcarlo como resuelto. "
    "Se generó una encuesta de satisfacción para el solicitante."
)


def _public_base_url() -> str:
    base = text_value(
        os.getenv("PUBLIC_BASE_URL")
        or os.getenv("APP_BASE_URL")
        or os.getenv("APP_PUBLIC_URL")
    ).rstrip("/")
    if base:
        return base

    preferred_scheme = text_value(os.getenv("PUBLIC_SCHEME") or os.getenv("PREFERRED_URL_SCHEME"), "http") or "http"
    port = text_value(os.getenv("PORT"), "5020") or "5020"

    host = text_value(os.getenv("PUBLIC_HOST") or os.getenv("APP_HOST") or os.getenv("SERVER_NAME")).rstrip("/")
    if host:
        if host.startswith("http://") or host.startswith("https://"):
            return host
        return f"{preferred_scheme}://{host}"

    if has_request_context():
        return request.host_url.rstrip("/")

    if has_app_context():
        server_name = text_value(current_app.config.get("SERVER_NAME")).rstrip("/")
        if server_name:
            scheme = text_value(current_app.config.get("PREFERRED_URL_SCHEME"), preferred_scheme) or preferred_scheme
            return f"{scheme}://{server_name}"

    hostname = text_value(socket.gethostname()).strip().rstrip("/")
    if hostname and hostname.lower() not in {"localhost", "127.0.0.1"}:
        return f"{preferred_scheme}://{hostname}:{port}"

    return f"{preferred_scheme}://localhost:{port}"


def survey_link(token: str) -> str:
    return f"{_public_base_url()}/encuesta/{token}"


def _record_system_update(case_id: str, message: str) -> None:
    execute(
        """
        INSERT INTO dbo.case_updates(case_id, author_id, author_name, author_email, message, is_solution, created_at)
        VALUES (?, NULL, 'Sistema', NULL, ?, 0, SYSDATETIME())
        """,
        (case_id, message),
    )


def _select_survey_by_case_and_resolved(case_id: str, resolved_at_snapshot) -> dict[str, Any] | None:
    return select_one(
        """
        SELECT TOP 1 id, case_id, resolved_at_snapshot, token, recipient_email,
               sent_at, rating, reason, completed_at, delivery_error,
               created_at, updated_at
        FROM dbo.case_surveys
        WHERE case_id = ? AND resolved_at_snapshot = ?
        ORDER BY id DESC
        """,
        (case_id, resolved_at_snapshot),
    )


def _create_survey(case_row: dict[str, Any]) -> dict[str, Any]:
    existing = _select_survey_by_case_and_resolved(case_row["id"], case_row.get("resolved_at"))
    if existing:
        return existing

    token = secrets.token_urlsafe(24)
    cur = execute(
        """
        INSERT INTO dbo.case_surveys(
            case_id, resolved_at_snapshot, token, recipient_email,
            created_at, updated_at
        )
        OUTPUT INSERTED.id, INSERTED.case_id, INSERTED.resolved_at_snapshot,
               INSERTED.token, INSERTED.recipient_email, INSERTED.sent_at,
               INSERTED.rating, INSERTED.reason, INSERTED.completed_at,
               INSERTED.delivery_error, INSERTED.created_at, INSERTED.updated_at
        VALUES (?, ?, ?, ?, SYSDATETIME(), SYSDATETIME())
        """,
        (
            case_row["id"],
            case_row.get("resolved_at"),
            token,
            case_row.get("requester_email") or None,
        ),
    )
    row = cur.fetchone()
    if not row:
        raise RuntimeError("SURVEY_CREATE_FAILED")

    cols = [c[0] for c in cur.description]
    return dict(zip(cols, row))


def _survey_mail_body(case_row: dict[str, Any], survey_row: dict[str, Any]) -> str:
    requester_name = text_value(case_row.get("requester_name"))
    subject = text_value(case_row.get("subject"), "Sin asunto")
    link = survey_link(text_value(survey_row.get("token")))

    greeting = f"Hola {requester_name}," if requester_name else "Hola,"

    return (
        f"{greeting}\n\n"
        f"Tu caso {case_row['id']} fue cerrado automáticamente después de permanecer resuelto por 24 horas.\n"
        f"Asunto: {subject}\n\n"
        "Queremos conocer tu nivel de satisfacción con la atención recibida.\n"
        "Por favor califícanos en una escala de 1 a 5 ingresando en el siguiente enlace:\n\n"
        f"{link}\n\n"
        "Si tu calificación es menor a 3, podrás indicarnos de manera opcional el motivo.\n\n"
        "Gracias,\n"
        "Mesa de ayuda Qualitas"
    )


def _mark_survey_delivery_error(survey_id: int, error_message: str) -> None:
    execute(
        "UPDATE dbo.case_surveys SET delivery_error = ?, updated_at = SYSDATETIME() WHERE id = ?",
        ((error_message or "MAIL_SEND_FAILED")[:100], survey_id),
    )
    commit()


def _attempt_send_survey(case_row: dict[str, Any], survey_row: dict[str, Any]) -> dict[str, int]:
    if survey_row.get("sent_at") or survey_row.get("completed_at"):
        return {"sent": 0, "errors": 0}

    recipient = text_value(survey_row.get("recipient_email") or case_row.get("requester_email"))
    if not recipient:
        _mark_survey_delivery_error(int(survey_row["id"]), "SOLICITANTE_SIN_CORREO")
        return {"sent": 0, "errors": 1}

    try:
        ok, status = send_mail(
            to_addr=recipient,
            subject=f"[{case_row['id']}] Encuesta de satisfacción",
            body=_survey_mail_body(case_row, survey_row),
        )
    except Exception:
        rollback()
        _mark_survey_delivery_error(int(survey_row["id"]), "MAIL_SEND_FAILED")
        return {"sent": 0, "errors": 1}

    if ok:
        execute(
            "UPDATE dbo.case_surveys SET sent_at = COALESCE(sent_at, SYSDATETIME()), delivery_error = NULL, updated_at = SYSDATETIME() WHERE id = ?",
            (survey_row["id"],),
        )
        commit()
        return {"sent": 1, "errors": 0}

    _mark_survey_delivery_error(int(survey_row["id"]), secure_status_code(status, fallback="MAIL_SEND_FAILED"))
    return {"sent": 0, "errors": 1}


def auto_close_resolved_cases() -> dict[str, int]:
    summary = {"closed": 0, "sent": 0, "errors": 0}
    candidates = select_all(
        """
        SELECT id, subject, requester_name, requester_email, priority, resolved_at
        FROM dbo.cases
        WHERE LOWER(ISNULL(status, '')) = 'resuelto'
          AND resolved_at IS NOT NULL
          AND resolved_at <= DATEADD(DAY, -1, SYSDATETIME())
        ORDER BY resolved_at ASC, id ASC
        """
    )

    for case_row in candidates:
        survey_row = None
        try:
            cur = execute(
                """
                UPDATE dbo.cases
                SET status = 'CERRADO',
                    closed_at = COALESCE(closed_at, SYSDATETIME()),
                    updated_at = SYSDATETIME()
                WHERE id = ?
                  AND LOWER(ISNULL(status, '')) = 'resuelto'
                """,
                (case_row["id"],),
            )
            changed = int(getattr(cur, "rowcount", 0) or 0)
            if changed <= 0:
                rollback()
                continue

            _record_system_update(case_row["id"], AUTO_CLOSE_NOTE)
            survey_row = _create_survey(case_row)
            commit()
            summary["closed"] += 1
        except Exception:
            rollback()
            summary["errors"] += 1
            continue

        if survey_row:
            send_result = _attempt_send_survey(case_row, survey_row)
            summary["sent"] += int(send_result.get("sent") or 0)
            summary["errors"] += int(send_result.get("errors") or 0)

    return summary


def retry_pending_surveys(limit: int = 25) -> dict[str, int]:
    summary = {"sent": 0, "errors": 0}
    rows = select_all(
        f"""
        SELECT TOP {int(limit)}
               s.id, s.case_id, s.resolved_at_snapshot, s.token, s.recipient_email,
               s.sent_at, s.rating, s.reason, s.completed_at, s.delivery_error,
               c.subject, c.requester_name, c.requester_email
        FROM dbo.case_surveys s
        INNER JOIN dbo.cases c ON c.id = s.case_id
        WHERE s.sent_at IS NULL
          AND LOWER(ISNULL(c.status, '')) = 'cerrado'
        ORDER BY s.created_at ASC, s.id ASC
        """
    )

    for row in rows:
        send_result = _attempt_send_survey(row, row)
        summary["sent"] += int(send_result.get("sent") or 0)
        summary["errors"] += int(send_result.get("errors") or 0)

    return summary


def run_case_automation() -> dict[str, int]:
    closed_result = auto_close_resolved_cases()
    retry_result = retry_pending_surveys()
    return {
        "closed": int(closed_result.get("closed") or 0),
        "sent": int(closed_result.get("sent") or 0) + int(retry_result.get("sent") or 0),
        "errors": int(closed_result.get("errors") or 0) + int(retry_result.get("errors") or 0),
    }
