import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from services.db import select_one, execute, commit
from services.case_id import next_case_id
from services.sla import compute_due_dates, get_priority_defaults, normalize_priority
from services.mail import send_mail


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

    mailbox_name = os.getenv("OUTLOOK_MAILBOX_NAME", "").strip() or None
    unread_only = str(os.getenv("OUTLOOK_ONLY_UNREAD", "true")).strip().lower() in (
        "1", "true", "yes", "y", "on"
    )
    mark_as_read = str(os.getenv("OUTLOOK_MARK_AS_READ", "true")).strip().lower() in (
        "1", "true", "yes", "y", "on"
    )

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

            case_id = next_case_id()
            prio = normalize_priority("MEDIA")
            resp_min, res_min = get_priority_defaults(prio)
            now = datetime.now()
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

            attachments = getattr(item, "Attachments", None)
            upload_root = None
            if attachments and int(getattr(attachments, "Count", 0) or 0) > 0:
                configured_root = (os.getenv("UPLOAD_ROOT") or "").strip()
                base_root = Path(configured_root) if configured_root else Path("uploads")
                for aidx in range(1, attachments.Count + 1):
                    try:
                        att = attachments.Item(aidx)
                        if upload_root is None:
                            upload_root = base_root / case_id
                            upload_root.mkdir(parents=True, exist_ok=True)
                        filename = _safe_filename(att.FileName)
                        filepath = upload_root / filename

                        n = 1
                        while filepath.exists():
                            filepath = upload_root / "{0}_{1}{2}".format(filepath.stem, n, filepath.suffix)
                            n += 1

                        att.SaveAsFile(str(filepath))

                        execute(
                            """
                            INSERT INTO dbo.case_attachments
                                (case_id, filename, stored_path, content_type, size_bytes)
                            VALUES (?,?,?,?,?)
                            """,
                            (
                                case_id,
                                filepath.name,
                                str(filepath),
                                None,
                                int(filepath.stat().st_size)
                            )
                        )
                    except Exception:
                        continue

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

            if mark_as_read and unread:
                try:
                    item.UnRead = False
                    item.Save()
                except Exception:
                    pass

        return {"ok": True, "created": created, "source": "outlook"}

    finally:
        pythoncom.CoUninitialize()
