import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

def _bool(v, default=False):
    if v is None:
        return default
    return str(v).strip().lower() in ("1","true","yes","y","on")

def send_mail(to_addr: str, subject: str, body: str):
    host = os.getenv("SMTP_SERVER", "").strip()
    port = int(os.getenv("SMTP_PORT", "25"))
    timeout = int(os.getenv("SMTP_TIMEOUT", "15"))

    use_tls = _bool(os.getenv("SMTP_USE_TLS"), False)  # STARTTLS
    from_email = os.getenv("SMTP_FROM_EMAIL", "").strip() or os.getenv("SMTP_USERNAME","").strip()
    from_name = os.getenv("SMTP_FROM_NAME", "Soporte TI").strip()

    username = os.getenv("SMTP_USERNAME","").strip()
    password = os.getenv("SMTP_PASSWORD","").strip()

    if not host or not from_email:
        return False, "SMTP_NOT_CONFIGURED"

    msg = EmailMessage()
    msg["From"] = formataddr((from_name, from_email))
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=timeout) as smtp:
        smtp.ehlo()
        if use_tls:
            smtp.starttls()
            smtp.ehlo()

        # Auth opcional
        if username and password:
            smtp.login(username, password)

        smtp.send_message(msg)

    return True, "SENT"
