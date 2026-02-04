import os
from urllib.parse import quote_plus

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine


def _sanitize_url(url: str) -> str:
    pwd = os.getenv("SQLSERVER_PASSWORD")
    if pwd:
        url = url.replace(pwd, "***")
    return url


def _build_odbc_connect(cfg) -> str:
    driver = getattr(cfg, "SQLSERVER_DRIVER", "ODBC Driver 18 for SQL Server")
    host = getattr(cfg, "SQLSERVER_HOST", None)
    db = getattr(cfg, "SQLSERVER_DB", "RRHH")

    if not host:
        raise RuntimeError("Falta SQLSERVER_HOST o DATABASE_URL en .env")

    trusted = str(getattr(cfg, "SQLSERVER_TRUSTED", False)).lower() == "true"
    encrypt = str(getattr(cfg, "SQLSERVER_ENCRYPT", False)).lower() == "true"
    trust_cert = str(getattr(cfg, "SQLSERVER_TRUST_CERT", True)).lower() == "true"

    odbc = (
        f"DRIVER={{{driver}}};"
        f"SERVER={host};"
        f"DATABASE={db};"
    )

    if trusted or not getattr(cfg, "SQLSERVER_USER", None):
        odbc += "Trusted_Connection=yes;"
    else:
        odbc += f"UID={cfg.SQLSERVER_USER};PWD={cfg.SQLSERVER_PASSWORD};"

    odbc += f"Encrypt={'yes' if encrypt else 'no'};"
    odbc += f"TrustServerCertificate={'yes' if trust_cert else 'no'};"

    return "mssql+pyodbc:///?odbc_connect=" + quote_plus(odbc)


def get_engine(cfg) -> Engine:
    url = getattr(cfg, "DATABASE_URL", None) or os.getenv("DATABASE_URL")
    if url and str(url).strip():
        return create_engine(str(url).strip(), pool_pre_ping=True, future=True)

    return create_engine(_build_odbc_connect(cfg), pool_pre_ping=True, future=True)


def db_config_info(cfg) -> dict:
    url = getattr(cfg, "DATABASE_URL", None) or os.getenv("DATABASE_URL")
    if url and str(url).strip():
        return {"using": "DATABASE_URL", "database_url": _sanitize_url(str(url))}
    return {
        "using": "SQLSERVER_*",
        "host": getattr(cfg, "SQLSERVER_HOST", None),
        "db": getattr(cfg, "SQLSERVER_DB", None),
        "driver": getattr(cfg, "SQLSERVER_DRIVER", None),
        "trusted": getattr(cfg, "SQLSERVER_TRUSTED", None),
        "encrypt": getattr(cfg, "SQLSERVER_ENCRYPT", None),
        "trust_cert": getattr(cfg, "SQLSERVER_TRUST_CERT", None),
    }


def db_healthcheck(engine: Engine) -> tuple[bool, str | None]:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, None
    except Exception as ex:
        return False, str(ex)
