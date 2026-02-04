import smtplib
from email.message import EmailMessage

def send_email(cfg, to_email: str, subject: str, html_body: str):
    if not cfg.SMTP_SERVER:
        raise RuntimeError("SMTP_SERVER no configurado")

    msg = EmailMessage()
    msg["From"] = cfg.SMTP_FROM_EMAIL or "rrhh@localhost"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content("Este correo requiere un cliente HTML.")
    msg.add_alternative(html_body, subtype="html")

    with smtplib.SMTP(cfg.SMTP_SERVER, cfg.SMTP_PORT, timeout=cfg.SMTP_TIMEOUT) as s:
        if cfg.SMTP_USE_TLS:
            s.starttls()
        s.send_message(msg)
