import os

try:
    from dotenv import load_dotenv
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    load_dotenv(os.path.join(BASE_DIR, ".env"), override=True)
except Exception:
    pass


class Config:
    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev_change_me")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_MB", "20")) * 1024 * 1024
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", os.path.abspath("uploads"))

    # SQL Server
    DATABASE_URL = os.getenv("DATABASE_URL")

    SQLSERVER_HOST = os.getenv("SQLSERVER_HOST")
    SQLSERVER_DB = os.getenv("SQLSERVER_DB", "RRHH")
    SQLSERVER_USER = os.getenv("SQLSERVER_USER")
    SQLSERVER_PASSWORD = os.getenv("SQLSERVER_PASSWORD")
    SQLSERVER_DRIVER = os.getenv("SQLSERVER_DRIVER", "ODBC Driver 18 for SQL Server")
    SQLSERVER_TRUSTED = os.getenv("SQLSERVER_TRUSTED_CONNECTION", "false").lower() == "true"
    SQLSERVER_ENCRYPT = os.getenv("SQLSERVER_ENCRYPT", "true").lower() == "true"
    SQLSERVER_TRUST_CERT = os.getenv("SQLSERVER_TRUST_CERT", "true").lower() == "true"

    # LDAP
    LDAP_SERVER = os.getenv("LDAP_SERVER")
    LDAP_PORT = int(os.getenv("LDAP_PORT", "389"))
    LDAP_DOMAIN = os.getenv("LDAP_DOMAIN")
    LDAP_NETBIOS = os.getenv("QCOLOMBIA")  
    LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE")
    LDAP_SERVICE_USER = os.getenv("LDAP_SERVICE_USER")
    LDAP_SERVICE_PASSWORD = os.getenv("LDAP_SERVICE_PASSWORD")
    LDAP_USE_SSL = os.getenv("LDAP_USE_SSL", "false").lower() == "true"
    LDAP_CONNECT_TIMEOUT = int(os.getenv("LDAP_CONNECT_TIMEOUT", "5"))

    # SMTP
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "false").lower() == "true"
    SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "15"))
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL")
