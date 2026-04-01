from __future__ import annotations

import mimetypes
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable

from services.security import bool_from_value, int_from_value, path_text, text_value

DEFAULT_SUPPORT_SENDER = "sistemas@qualitascolombia.com.co"


def _first_env(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = text_value(os.getenv(name))
        if value:
            return value
    return default


def _resolve_sender(explicit_sender: str | None = None) -> str:
    # Requerimiento funcional: todas las notificaciones del sistema deben salir
    # desde la cuenta de soporte TI y no desde valores heredados del .env.
    del explicit_sender
    return DEFAULT_SUPPORT_SENDER


def _smtp_host() -> str:
    return (_first_env("SMTP_HOST", "MAIL_SERVER", "SMTP_SERVER", default="") or "").strip()


def _smtp_port() -> int:
    return int_from_value(_first_env("SMTP_PORT", "MAIL_PORT", default="587"), 587)


def _smtp_username() -> str:
    return _first_env("SMTP_USERNAME", "SMTP_USER", "MAIL_USERNAME", default="") or ""


def _smtp_password() -> str:
    return _first_env("SMTP_PASSWORD", "MAIL_PASSWORD", default="") or ""


def _attachment_content_type(path: Path, declared: str | None = None) -> tuple[str, str]:
    if declared and "/" in declared:
        maintype, subtype = declared.split("/", 1)
        return maintype, subtype
    guessed, _ = mimetypes.guess_type(path_text(path))
    if guessed and "/" in guessed:
        maintype, subtype = guessed.split("/", 1)
        return maintype, subtype
    return "application", "octet-stream"


def _iter_attachment_specs(attachments) -> Iterable[dict]:
    for item in attachments or []:
        if not item:
            continue
        if isinstance(item, (str, os.PathLike)):
            yield {"path": path_text(item)}
            continue
        if isinstance(item, dict):
            yield item


def send_mail(
    to_addr: str,
    subject: str,
    body: str,
    *,
    from_addr: str | None = None,
    html_body: str | None = None,
    attachments=None,
    cc: str | None = None,
    bcc: str | None = None,
) -> tuple[bool, str]:
    recipient = text_value(to_addr)
    if not recipient:
        return False, "DESTINATARIO_VACIO"

    host = _smtp_host()
    if not host:
        return False, "SMTP_HOST_NO_CONFIGURADO"

    sender = _resolve_sender(from_addr)
    port = _smtp_port()
    username = _smtp_username()
    password = _smtp_password()
    use_ssl = bool_from_value(os.getenv("SMTP_USE_SSL"), False) or bool_from_value(os.getenv("MAIL_USE_SSL"), False) or port == 465
    use_tls = bool_from_value(os.getenv("SMTP_USE_TLS"), not use_ssl) or bool_from_value(os.getenv("MAIL_USE_TLS"), not use_ssl)
    timeout = int_from_value(os.getenv("SMTP_TIMEOUT"), 30)

    msg = EmailMessage()
    msg["Subject"] = subject or "(Sin asunto)"
    msg["From"] = sender
    msg["To"] = recipient
    if cc:
        msg["Cc"] = text_value(cc)

    text_body = body or ""
    if html_body:
        msg.set_content(text_body or "Este mensaje contiene una versión HTML.")
        msg.add_alternative(html_body, subtype="html")
    else:
        msg.set_content(text_body)

    for spec in _iter_attachment_specs(attachments):
        raw_path = text_value(spec.get("path") or spec.get("stored_path"))
        if not raw_path:
            continue
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            continue
        filename = text_value(spec.get("filename") or path.name, "adjunto") or "adjunto"
        maintype, subtype = _attachment_content_type(path, spec.get("content_type"))
        with path.open("rb") as fh:
            payload = fh.read()
        msg.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)

    recipients = [addr.strip() for addr in recipient.split(",") if addr.strip()]
    if cc:
        recipients.extend(addr.strip() for addr in text_value(cc).split(",") if addr.strip())
    if bcc:
        recipients.extend(addr.strip() for addr in text_value(bcc).split(",") if addr.strip())

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=timeout) as server:
                if username:
                    server.login(username, password)
                server.send_message(msg, from_addr=sender, to_addrs=recipients)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as server:
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                if username:
                    server.login(username, password)
                server.send_message(msg, from_addr=sender, to_addrs=recipients)
    except Exception:
        return False, "MAIL_SEND_FAILED"

    return True, "OK"
