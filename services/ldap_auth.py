import logging
import ssl

from ldap3 import ALL, SUBTREE, Connection, Server, Tls

from config.ldap_config import (
    LDAP_CONNECTION_TIMEOUT,
    LDAP_DOMAIN,
    LDAP_ENABLED,
    LDAP_PORT,
    LDAP_SEARCH_BASE,
    LDAP_SERVER,
    LDAP_SERVICE_PASSWORD,
    LDAP_SERVICE_USER,
    LDAP_USE_SSL,
)

logger = logging.getLogger(__name__)


def _clean_attr(value) -> str:
    if value is None:
        return ""
    value = str(value).strip()
    if value.lower() in {"none", "null"}:
        return ""
    return value


def _pick_display_name(*candidates: str) -> str:
    cleaned = []
    for raw in candidates:
        value = _clean_attr(raw)
        if not value:
            continue
        if value.isdigit() and len(value) <= 3:
            continue
        cleaned.append(value)
    return cleaned[0] if cleaned else ""


def _as_upn(user: str) -> str:
    if not user:
        return ""
    user = user.strip()
    if "@" in user or "\\" in user:
        return user
    return f"{user}@{LDAP_DOMAIN}" if LDAP_DOMAIN else user


def _host_only(server: str) -> str:
    s = (server or "").strip()
    if s.startswith("ldap://"):
        return s[len("ldap://") :]
    if s.startswith("ldaps://"):
        return s[len("ldaps://") :]
    return s


def _server() -> Server:
    tls = None
    if LDAP_USE_SSL:
        tls = Tls(validate=ssl.CERT_NONE)

    return Server(
        _host_only(LDAP_SERVER),
        port=LDAP_PORT,
        use_ssl=LDAP_USE_SSL,
        tls=tls,
        get_info=ALL,
        connect_timeout=LDAP_CONNECTION_TIMEOUT,
    )


def _entry_to_user(entry, fallback_username: str = "") -> dict:
    display_name = _clean_attr(entry.displayName) if "displayName" in entry else ""
    given_name = _clean_attr(entry.givenName) if "givenName" in entry else ""
    last_name = _clean_attr(entry.sn) if "sn" in entry else ""
    cn = _clean_attr(entry.cn) if "cn" in entry else ""
    name_attr = _clean_attr(entry.name) if "name" in entry else ""
    mail = _clean_attr(entry.mail) if "mail" in entry else ""
    sam = _clean_attr(entry.sAMAccountName) if "sAMAccountName" in entry else fallback_username
    title = _clean_attr(entry.title) if "title" in entry else ""
    department = _clean_attr(entry.department) if "department" in entry else ""
    full_name = " ".join([part for part in [given_name, last_name] if part]).strip()
    display_name = _pick_display_name(display_name, full_name, cn, name_attr, sam)
    return {
        "username": sam,
        "display_name": display_name or sam,
        "email": mail,
        "job_title": title,
        "department": department,
        "dn": entry.entry_dn,
    }


def _service_bind() -> Connection:
    server = _server()
    svc_user = _as_upn(LDAP_SERVICE_USER)
    return Connection(server, user=svc_user, password=LDAP_SERVICE_PASSWORD, auto_bind=True)


def test_connection():
    if not LDAP_ENABLED:
        return False, "LDAP_DISABLED"
    try:
        conn = _service_bind()
        conn.unbind()
        return True, "OK"
    except Exception as e:
        logger.exception("LDAP test_connection falló")
        return False, str(e)


def search_user(username: str):
    if not LDAP_ENABLED:
        return False, {"error": "LDAP_DISABLED"}
    username = (username or "").strip()
    if not username:
        return False, {"error": "EMPTY_USERNAME"}
    if not LDAP_SEARCH_BASE:
        return False, {"error": "LDAP_SEARCH_BASE_EMPTY"}
    if not LDAP_SERVICE_USER or not LDAP_SERVICE_PASSWORD:
        return False, {"error": "LDAP_SERVICE_ACCOUNT_EMPTY"}

    try:
        conn = _service_bind()
        upn = _as_upn(username)
        attrs = [
            "displayName",
            "mail",
            "userPrincipalName",
            "sAMAccountName",
            "givenName",
            "sn",
            "cn",
            "name",
            "title",
            "department",
        ]
        search_filter = (
            f"(|(sAMAccountName={username})(userPrincipalName={username})"
            f"(userPrincipalName={upn})(mail={username}))"
        )
        ok = conn.search(
            search_base=LDAP_SEARCH_BASE,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attrs,
            size_limit=1,
        )
        if not ok or not conn.entries:
            conn.unbind()
            return False, {"error": "USER_NOT_FOUND"}
        result = _entry_to_user(conn.entries[0], fallback_username=username)
        conn.unbind()
        return True, result
    except Exception as e:
        logger.exception("LDAP search_user falló")
        return False, {"error": "LDAP_ERROR", "detail": str(e)}


def authenticate(username: str, password: str):
    if not LDAP_ENABLED:
        return False, {"error": "LDAP_DISABLED"}
    username = (username or "").strip()
    password = password or ""
    if not username or not password:
        return False, {"error": "EMPTY_CREDENTIALS"}

    ok, user_info = search_user(username)
    if not ok:
        return False, user_info

    try:
        server = _server()
        user_conn = Connection(server, user=user_info["dn"], password=password, auto_bind=True)
        user_conn.unbind()
        return True, user_info
    except Exception as e:
        logger.exception("LDAP authenticate falló")
        return False, {"error": "LDAP_ERROR", "detail": str(e)}
