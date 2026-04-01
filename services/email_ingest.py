from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from flask import current_app

from services.db import commit, execute, rollback, select_one
from services.case_id import next_case_id
from services.sla import compute_due_dates, get_priority_defaults, normalize_priority
from services.mail import send_mail
from services.security import bool_from_value, path_text, text_value

CASE_ID_RE = re.compile(r"\bQ-\d{4}-\d{5}\b", re.IGNORECASE)
AUTO_REOPEN_STATUSES = {"en espera de usuario", "resuelto", "cerrado"}


def _safe_filename(name: str) -> str:
    name = name or "adjunto"
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name[:180]


def _html_to_text(html: str) -> str:
    if not html:
        return ""
    html = re.sub(r"(?is)<(script|style).*?>.*?</\\1>", " ", html)
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    html = re.sub(r"\s+", " ", html)
    return html.strip()


def _upload_root_for_case(case_id: str) -> Path:
    configured_root = (os.getenv("UPLOAD_ROOT") or "").strip()
    if configured_root:
        base_root = Path(configured_root)
        if not base_root.is_absolute():
            base_root = Path(current_app.root_path) / base_root
    else:
        base_root = Path(current_app.instance_path) / "uploads"
    upload_root = (base_root / case_id).resolve()
    upload_root.mkdir(parents=True, exist_ok=True)
    return upload_root


def _next_available_path(directory: Path, filename: str) -> Path:
    filepath = directory / filename
    counter = 1
    while filepath.exists():
        filepath = directory / f"{filepath.stem}_{counter}{filepath.suffix}"
        counter += 1
    return filepath


def _extract_case_id_from_subject(subject: str) -> str | None:
    match = CASE_ID_RE.search(subject or "")
    return match.group(0).upper() if match else None


def _insert_external_update(case_id: str, author_name: str, author_email: str, message: str) -> int | None:
    cur = execute(
        """
        INSERT INTO dbo.case_updates(case_id, author_id, author_name, author_email, message, is_solution, created_at)
        OUTPUT INSERTED.id
        VALUES (?, NULL, ?, ?, ?, 0, SYSDATETIME())
        """,
        (
            case_id,
            author_name or author_email or "Usuario",
            author_email or None,
            message,
        ),
    )
    row = cur.fetchone()
    if not row:
        return None
    return int(row[0])


def _save_outlook_attachments(case_id: str, attachments, update_id: int | None = None):
    saved = []
    if not attachments or int(getattr(attachments, "Count", 0) or 0) <= 0:
        return saved

    upload_root = _upload_root_for_case(case_id)
    for aidx in range(1, attachments.Count + 1):
        try:
            att = attachments.Item(aidx)
            filename = _safe_filename(getattr(att, "FileName", "") or "adjunto")
            filepath = _next_available_path(upload_root, filename)
            att.SaveAsFile(path_text(filepath))
            size_bytes = int(filepath.stat().st_size) if filepath.exists() else 0
            execute(
                """
                INSERT INTO dbo.case_attachments
                    (case_id, update_id, filename, stored_path, content_type, size_bytes)
                VALUES (?,?,?,?,?,?)
                """,
                (
                    case_id,
                    update_id,
                    filepath.name,
                    path_text(filepath),
                    None,
                    size_bytes,
                ),
            )
            saved.append(filepath.name)
        except Exception:
            continue

    return saved


def _get_root_folder(namespace, mailbox_name: Optional[str]):
    """
    Busca la raíz visible del buzón en el perfil actual de Outlook.
    Si mailbox_name no se especifica o no se encuentra, usa la raíz del perfil principal.
    """
    if mailbox_name:
        wanted = mailbox_name.strip().lower()
        for i in range(1, namespace.Folders.Count + 1):
            root = namespace.Folders.Item(i)
            if (getattr(root, "Name", "") or "").strip().lower() == wanted:
                return root

    inbox = namespace.GetDefaultFolder(6)  # olFolderInbox
    return inbox.Parent


def _get_inbox(namespace, mailbox_name: Optional[str]):
    root = _get_root_folder(namespace, mailbox_name)

    for i in range(1, root.Folders.Count + 1):
        sub = root.Folders.Item(i)
        name = (getattr(sub, "Name", "") or "").strip().lower()
        if name in ("inbox", "bandeja de entrada"):
            return sub

    return namespace.GetDefaultFolder(6)


def _get_sender_email(item) -> str:
    try:
        sender_type = (getattr(item, "SenderEmailType", "") or "").upper()
        if sender_type == "EX":
            sender = getattr(item, "Sender", None)
            if sender:
                exch_user = sender.GetExchangeUser()
                if exch_user and exch_user.PrimarySmtpAddress:
                    return exch_user.PrimarySmtpAddress.strip()
        value = getattr(item, "SenderEmailAddress", "") or ""
        return value.strip()
    except Exception:
        return ""


def _get_transport_headers(item) -> str:
    try:
        return item.PropertyAccessor.GetProperty(
            "http://schemas.microsoft.com/mapi/proptag/0x007D001E"
        ) or ""
    except Exception:
        return ""


def _get_message_id(item) -> str:
    headers = _get_transport_headers(item)
    if headers:
        match = re.search(r"^Message-ID:\s*(.+)$", headers, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip()

    try:
        entry_id = getattr(item, "EntryID", "") or ""
        if entry_id:
            return "OUTLOOK:{0}".format(entry_id)
    except Exception:
        pass

    return ""


def _get_body(item) -> str:
    body = (getattr(item, "Body", "") or "").strip()
    if body:
        return body

    html = (getattr(item, "HTMLBody", "") or "").strip()
    if html:
        return _html_to_text(html)

    return ""


def _format_external_update_message(subject: str, body: str, from_name: str, from_email: str, reopened: bool = False) -> str:
    header_lines = []
    if reopened:
        header_lines.append("[Caso reabierto automáticamente por respuesta del usuario]")
    header_lines.append("Correo asociado por ingesta.")
    header_lines.append(f"Asunto: {subject or '(Sin asunto)'}")
    sender_label = from_name or from_email or "Usuario"
    if from_email:
        header_lines.append(f"Remitente: {sender_label} <{from_email}>")
    else:
        header_lines.append(f"Remitente: {sender_label}")

    text = "\n".join(header_lines).strip()
    if body:
        return f"{text}\n\n{body}"
    return text


def _link_email_to_existing_case(existing_case: dict, subject: str, body: str, from_name: str, from_email: str, msg_id: str, attachments, now: datetime) -> None:
    case_id = existing_case["id"]
    current_status = text_value(existing_case.get("status")).lower()
    reopened = current_status in AUTO_REOPEN_STATUSES

    if reopened:
        response_min, resolution_min = get_priority_defaults(existing_case.get("priority") or "MEDIA")
        response_due, resolution_due = compute_due_dates(now, response_min, resolution_min)
        execute(
            """
            UPDATE dbo.cases
            SET status='REABIERTO',
                resolved_at=NULL,
                closed_at=NULL,
                response_due_at=?,
                resolution_due_at=?,
                updated_at=SYSDATETIME()
            WHERE id = ?
            """,
            (response_due, resolution_due, case_id),
        )
    else:
        execute(
            "UPDATE dbo.cases SET updated_at = SYSDATETIME() WHERE id = ?",
            (case_id,),
        )

    update_id = _insert_external_update(
        case_id,
        from_name,
        from_email,
        _format_external_update_message(subject, body, from_name, from_email, reopened=reopened),
    )
    _save_outlook_attachments(case_id, attachments, update_id=update_id)

    if msg_id:
        execute(
            "INSERT INTO dbo.email_ingest_log(email_message_id, case_id, status) VALUES (?,?,?)",
            (msg_id, case_id, "linked"),
        )


def ingest_unseen():
    """
    Lee correos desde Outlook clásico usando el perfil autenticado del usuario actual.
    """
    try:
        import pythoncom
        import win32com.client
    except Exception as exc:
        raise RuntimeError(
            "Falta pywin32 en el entorno virtual que ejecuta Flask. "
            "Instala con: .\\env1\\Scripts\\python.exe -m pip install pywin32"
        ) from exc

    pythoncom.CoInitialize()
    created = 0
    linked = 0

    mailbox_name = text_value(os.getenv("OUTLOOK_MAILBOX_NAME")) or None
    unread_only = bool_from_value(os.getenv("OUTLOOK_ONLY_UNREAD"), True)
    mark_as_read = bool_from_value(os.getenv("OUTLOOK_MARK_AS_READ"), True)

    try:
        outlook = win32com.client.Dispatch("Outlook.Application")
        namespace = outlook.GetNamespace("MAPI")
        inbox = _get_inbox(namespace, mailbox_name)

        items = inbox.Items
        items.Sort("[ReceivedTime]", True)
        total = items.Count

        for idx in range(1, total + 1):
            try:
                item = items.Item(idx)
            except Exception:
                continue

            if getattr(item, "Class", None) != 43:  # olMail
                continue

            unread = bool(getattr(item, "UnRead", False))
            if unread_only and not unread:
                continue

            subject = (getattr(item, "Subject", "") or "").strip()
            from_name = (getattr(item, "SenderName", "") or "").strip()
            from_email = _get_sender_email(item)
            msg_id = _get_message_id(item)
            body = _get_body(item)
            attachments = getattr(item, "Attachments", None)
            now = datetime.now()

            if msg_id:
                existing = select_one(
                    "SELECT 1 AS x FROM dbo.email_ingest_log WHERE email_message_id = ?",
                    (msg_id,)
                )
                if existing:
                    if mark_as_read and unread:
                        try:
                            item.UnRead = False
                            item.Save()
                        except Exception:
                            pass
                    continue

            referenced_case_id = None
            try:
                referenced_case_id = _extract_case_id_from_subject(subject)
                if referenced_case_id:
                    referenced_case = select_one(
                        "SELECT id, status, priority FROM dbo.cases WHERE id = ?",
                        (referenced_case_id,),
                    )
                else:
                    referenced_case = None

                if referenced_case:
                    _link_email_to_existing_case(
                        referenced_case,
                        subject,
                        body,
                        from_name,
                        from_email,
                        msg_id,
                        attachments,
                        now,
                    )
                    commit()
                    linked += 1
                else:
                    case_id = next_case_id(now=now)
                    prio = normalize_priority("MEDIA")
                    resp_min, res_min = get_priority_defaults(prio)
                    resp_due, res_due = compute_due_dates(now, resp_min, res_min)

                    execute(
                        """
                        INSERT INTO dbo.cases
                            (id, subject, description,
                             requester_name, requester_email,
                             priority, status,
                             assigned_team, assigned_to,
                             sla_response_min, sla_resolution_min,
                             response_due_at, resolution_due_at,
                             created_at, updated_at,
                             first_response_at, resolved_at, closed_at,
                             source_email_message_id, source_email_from)
                        VALUES
                            (?, ?, ?,
                             ?, ?,
                             ?, ?,
                             ?, ?,
                             ?, ?,
                             ?, ?,
                             SYSDATETIME(), SYSDATETIME(),
                             NULL, NULL, NULL,
                             ?, ?)
                        """,
                        (
                            case_id,
                            subject,
                            body,
                            from_name,
                            from_email,
                            prio,
                            "PENDIENTE",
                            "gestor_ti",
                            None,
                            int(resp_min),
                            int(res_min),
                            resp_due,
                            res_due,
                            msg_id or None,
                            from_email or from_name,
                        )
                    )

                    if msg_id:
                        execute(
                            "INSERT INTO dbo.email_ingest_log(email_message_id, case_id, status) VALUES (?,?,?)",
                            (msg_id, case_id, "ok")
                        )

                    _save_outlook_attachments(case_id, attachments, update_id=None)
                    commit()
                    created += 1

                    if from_email:
                        try:
                            send_mail(
                                to_addr=from_email,
                                subject="[{0}] Caso recibido - Soporte TI".format(case_id),
                                body=(
                                    "Hola {0}\n\n"
                                    "Hemos recibido tu solicitud y se creó el caso: {1}\n"
                                    "Asunto: {2}\n\n"
                                    "Te notificaremos cuando sea atendido y al cerrarse con la solución.\n\n"
                                    "Gracias,\nSoporte TI Qualitas"
                                ).format(from_name or "", case_id, subject)
                            )
                        except Exception:
                            pass
            except Exception:
                rollback()
                continue

            if mark_as_read and unread:
                try:
                    item.UnRead = False
                    item.Save()
                except Exception:
                    pass

        return {"ok": True, "created": created, "linked": linked, "source": "outlook"}

    finally:
        pythoncom.CoUninitialize()
