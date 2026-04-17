import logging
import re
import ssl
from typing import Iterable, List, Optional, Set, Tuple

from ldap3 import ALL, NTLM, SUBTREE, Connection, Server, Tls

try:
    from ldap3.utils.conv import escape_filter_chars
except Exception:
    def escape_filter_chars(value):
        raw = f"{value or ''}"
        return (
            raw.replace('\\', r'\5c')
            .replace('*', r'\2a')
            .replace('(', r'\28')
            .replace(')', r'\29')
            .replace('\x00', r'\00')
        )

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
from services.app_logging import log_event
from services.security import sanitizar_log_text, text_value

logger = logging.getLogger(__name__)

LDAP_PUBLIC_ERROR = {"error": "DIRECTORY_SERVICE_UNAVAILABLE"}


def _unwrap_attr_value(value):
    raw = getattr(value, "value", value)
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            normalized = _unwrap_attr_value(item)
            if normalized not in {None, ""}:
                return normalized
        return ""
    return raw


def _clean_attr(value) -> str:
    normalized = text_value(_unwrap_attr_value(value))
    if normalized.lower() in {"none", "null", "[]", "()", "{}"}:
        return ""
    return normalized


def _secret_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return f"{value}"


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


def _looks_like_code(value: str) -> bool:
    normalized = _clean_attr(value)
    if not normalized:
        return False
    compact = normalized.replace('-', '').replace('_', '').replace(' ', '')
    has_letters = any(ch.isalpha() for ch in compact)
    has_digits = any(ch.isdigit() for ch in compact)
    if has_letters and has_digits and len(compact) >= 6 and compact.upper() == compact:
        return True
    return False


def _extract_bracketed_text(*values: str) -> str:
    for raw in values:
        normalized = _clean_attr(raw)
        if not normalized:
            continue
        matches = re.findall(r'\[([^\]]+)\]', normalized)
        for match in matches:
            candidate = _clean_attr(match)
            if candidate and not _looks_like_code(candidate):
                return candidate
    return ""


def _clean_name_text(value: str) -> str:
    normalized = _clean_attr(value)
    if not normalized:
        return ""
    cleaned = re.sub(r'\s*\[[^\]]+\]', '', normalized).strip(' -')
    return cleaned.strip()


def _pick_job_title(*candidates: str) -> str:
    for raw in candidates:
        value = _clean_attr(raw)
        if not value or _looks_like_code(value):
            continue
        return value
    for raw in candidates:
        value = _clean_attr(raw)
        if value:
            return value
    return ""


def _as_upn(user: str) -> str:
    normalized = text_value(user)
    if not normalized:
        return ""
    if "@" in normalized or "\\" in normalized:
        return normalized
    return f"{normalized}@{LDAP_DOMAIN}" if LDAP_DOMAIN else normalized


def _as_netbios_user(user: str) -> str:
    normalized = text_value(user)
    if not normalized or "\\" in normalized:
        return normalized
    domain = text_value(LDAP_DOMAIN)
    if not domain:
        return normalized
    short_domain = domain.split(".", 1)[0].upper()
    return f"{short_domain}\\{normalized}"


def _host_only(server: str) -> str:
    normalized = text_value(server)
    if normalized.startswith("ldap://"):
        return normalized[len("ldap://") :]
    if normalized.startswith("ldaps://"):
        return normalized[len("ldaps://") :]
    return normalized


def _account_name(value: str) -> str:
    normalized = text_value(value)
    if not normalized:
        return ""
    if "\\" in normalized:
        normalized = normalized.rsplit("\\", 1)[-1]
    if "@" in normalized:
        normalized = normalized.split("@", 1)[0]
    return normalized.strip()


def _search_candidates(username: str) -> List[str]:
    raw = text_value(username)
    account = _account_name(raw)
    candidates = []

    def add(value: str) -> None:
        normalized = text_value(value)
        if not normalized:
            return
        if normalized not in candidates:
            candidates.append(normalized)

    add(raw)
    add(account)
    add(_as_upn(raw))
    add(_as_upn(account))

    return candidates


def _search_terms(username: str) -> List[str]:
    terms = []

    def add(value: str) -> None:
        normalized = text_value(value)
        if not normalized:
            return
        if normalized not in terms:
            terms.append(normalized)

    for candidate in _search_candidates(username):
        add(candidate)
        if "@" in candidate:
            add(candidate.split("@", 1)[0])
        if "\\" in candidate:
            add(candidate.rsplit("\\", 1)[-1])
        for token in re.split(r"[\s,;:_\-]+", candidate):
            token = token.strip()
            if len(token) >= 3:
                add(token)

    return terms


def _or_filter(clauses: List[str]) -> str:
    unique = []
    seen: Set[str] = set()
    for clause in clauses:
        if clause and clause not in seen:
            seen.add(clause)
            unique.append(clause)
    if not unique:
        return "(objectClass=user)"
    return "(&(objectClass=user)(|" + "".join(unique) + "))"


def _build_exact_search_filter(username: str) -> str:
    clauses = []
    for candidate in _search_candidates(username):
        safe = escape_filter_chars(candidate)
        clauses.extend(
            [
                f"(sAMAccountName={safe})",
                f"(userPrincipalName={safe})",
                f"(mail={safe})",
                f"(displayName={safe})",
                f"(cn={safe})",
                f"(name={safe})",
                f"(givenName={safe})",
                f"(sn={safe})",
                f"(title={safe})",
                f"(department={safe})",
                f"(description={safe})",
            ]
        )
    return _or_filter(clauses)


def _build_contains_search_filter(username: str) -> str:
    clauses = []
    for term in _search_terms(username):
        safe = escape_filter_chars(term)
        wildcard = f"*{safe}*"
        clauses.extend(
            [
                f"(displayName={wildcard})",
                f"(cn={wildcard})",
                f"(name={wildcard})",
                f"(givenName={wildcard})",
                f"(sn={wildcard})",
                f"(title={wildcard})",
                f"(department={wildcard})",
                f"(description={wildcard})",
                f"(mail={wildcard})",
                f"(sAMAccountName={wildcard})",
            ]
        )
    return _or_filter(clauses)


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


def _entry_values(entry) -> dict:
    return {
        "display_name": _clean_attr(entry.displayName) if "displayName" in entry else "",
        "given_name": _clean_attr(entry.givenName) if "givenName" in entry else "",
        "last_name": _clean_attr(entry.sn) if "sn" in entry else "",
        "cn": _clean_attr(entry.cn) if "cn" in entry else "",
        "name_attr": _clean_attr(entry.name) if "name" in entry else "",
        "mail": _clean_attr(entry.mail) if "mail" in entry else "",
        "sam": _clean_attr(entry.sAMAccountName) if "sAMAccountName" in entry else "",
        "upn": _clean_attr(entry.userPrincipalName) if "userPrincipalName" in entry else "",
        "title": _clean_attr(entry.title) if "title" in entry else "",
        "department": _clean_attr(entry.department) if "department" in entry else "",
        "description": _clean_attr(entry.description) if "description" in entry else "",
        "employee_type": _clean_attr(entry.employeeType) if "employeeType" in entry else "",
        "personal_title": _clean_attr(entry.personalTitle) if "personalTitle" in entry else "",
        "ext1": _clean_attr(entry.extensionAttribute1) if "extensionAttribute1" in entry else "",
        "ext2": _clean_attr(entry.extensionAttribute2) if "extensionAttribute2" in entry else "",
        "ext3": _clean_attr(entry.extensionAttribute3) if "extensionAttribute3" in entry else "",
    }


def _score_entry(entry, query: str) -> int:
    q = text_value(query).strip().lower()
    if not q:
        return 0

    values = _entry_values(entry)
    score = 0

    exact_major = [values["sam"], values["upn"], values["mail"]]
    exact_minor = [
        values["display_name"],
        values["cn"],
        values["name_attr"],
        values["given_name"],
        values["last_name"],
        values["title"],
        values["department"],
        values["description"],
    ]

    if any(text_value(value).lower() == q for value in exact_major if value):
        score += 100
    if any(text_value(value).lower() == q for value in exact_minor if value):
        score += 70

    for value in exact_major:
        normalized = text_value(value).lower()
        if normalized.startswith(q):
            score += 35
        elif q in normalized:
            score += 20

    for value in exact_minor:
        normalized = text_value(value).lower()
        if normalized.startswith(q):
            score += 20
        elif q in normalized:
            score += 10

    tokens = [token for token in re.split(r"\s+", q) if token]
    searchable = " ".join([text_value(v).lower() for v in exact_major + exact_minor if v])
    for token in tokens:
        if token in searchable:
            score += 5

    return score


def _pick_best_entry(entries, query: str):
    if not entries:
        return None
    ranked = sorted(entries, key=lambda item: _score_entry(item, query), reverse=True)
    return ranked[0]


def _run_search(conn: Connection, search_filter: str, attrs: List[str], size_limit: int = 10):
    ok = conn.search(
        search_base=LDAP_SEARCH_BASE,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=attrs,
        size_limit=size_limit,
    )
    if not ok or not conn.entries:
        return None
    return _pick_best_entry(conn.entries, query="")


def _search_with_ranking(conn: Connection, username: str, search_filter: str, attrs: List[str], size_limit: int = 10):
    ok = conn.search(
        search_base=LDAP_SEARCH_BASE,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=attrs,
        size_limit=size_limit,
    )
    if not ok or not conn.entries:
        return None
    return _pick_best_entry(conn.entries, query=username)


def _entry_to_user(entry, fallback_username: str = "") -> dict:
    values = _entry_values(entry)
    full_name = " ".join([part for part in [values["given_name"], values["last_name"]] if part]).strip()
    bracketed_title = _extract_bracketed_text(values["display_name"], values["cn"], values["name_attr"])
    display_name = _pick_display_name(
        _clean_name_text(values["display_name"]),
        full_name,
        _clean_name_text(values["cn"]),
        _clean_name_text(values["name_attr"]),
        values["sam"],
        fallback_username,
    )
    job_title = _pick_job_title(
        bracketed_title,
        values["title"],
        values["description"],
        values["employee_type"],
        values["personal_title"],
        values["ext1"],
        values["ext2"],
        values["ext3"],
    )
    return {
        "username": values["sam"] or fallback_username,
        "display_name": display_name or values["sam"] or fallback_username,
        "email": values["mail"],
        "job_title": job_title,
        "department": values["department"],
        "dn": entry.entry_dn,
        "upn": values["upn"],
    }


def _service_bind() -> Connection:
    server = _server()
    svc_user = _as_upn(LDAP_SERVICE_USER)
    return Connection(server, user=svc_user, password=LDAP_SERVICE_PASSWORD, auto_bind=True)


def _log_directory_service_error(operation: str, detail: str = "") -> None:
    sanitized_op = sanitizar_log_text(operation, default="unknown_operation")
    sanitized_detail = sanitizar_log_text(detail, default="")
    event_detail = sanitized_op if not sanitized_detail else f"{sanitized_op}:{sanitized_detail}"
    log_event(
        "SECURITY",
        "ERROR",
        "DIRECTORY_SERVICE_ERROR",
        detail=event_detail,
        source="services.ldap_auth",
        status="DIRECTORY_SERVICE_UNAVAILABLE",
        persist_db=False,
    )


def _bind_candidates(username: str, user_info: dict) -> Iterable[Tuple[str, Optional[str]]]:
    dn = text_value(user_info.get("dn"))
    upn = text_value(user_info.get("upn"))
    sam = text_value(user_info.get("username")) or _account_name(username)
    requested = text_value(username)

    seen: Set[Tuple[str, Optional[str]]] = set()

    def add(user_value: str, auth_mode: Optional[str] = None):
        normalized = text_value(user_value)
        if not normalized:
            return
        key = (normalized, auth_mode)
        if key in seen:
            return
        seen.add(key)
        yield key

    for item in add(dn, None):
        yield item
    for item in add(upn, None):
        yield item
    for item in add(_as_upn(sam), None):
        yield item
    for item in add(_as_upn(requested), None):
        yield item
    for item in add(_as_netbios_user(sam), NTLM):
        yield item
    for item in add(_as_netbios_user(requested), NTLM):
        yield item


def _try_user_bind(server: Server, bind_user: str, password: str, auth_mode: Optional[str] = None) -> bool:
    kwargs = {"user": bind_user, "password": password, "auto_bind": True}
    if auth_mode:
        kwargs["authentication"] = auth_mode
    conn = Connection(server, **kwargs)
    conn.unbind()
    return True


def test_connection():
    if not LDAP_ENABLED:
        return False, "LDAP_DISABLED"
    try:
        conn = _service_bind()
        conn.unbind()
        return True, "OK"
    except Exception as exc:
        _log_directory_service_error("test_connection", detail=type(exc).__name__)
        return False, "DIRECTORY_SERVICE_UNAVAILABLE"


def search_user(username: str):
    if not LDAP_ENABLED:
        return False, {"error": "LDAP_DISABLED"}
    username = text_value(username)
    if not username:
        return False, {"error": "EMPTY_USERNAME"}
    if not LDAP_SEARCH_BASE:
        return False, {"error": "LDAP_SEARCH_BASE_EMPTY"}
    if not LDAP_SERVICE_USER or not LDAP_SERVICE_PASSWORD:
        return False, {"error": "LDAP_SERVICE_ACCOUNT_EMPTY"}

    try:
        conn = _service_bind()
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
            "description",
            "employeeType",
            "personalTitle",
            "extensionAttribute1",
            "extensionAttribute2",
            "extensionAttribute3",
        ]

        entry = _search_with_ranking(conn, username, _build_exact_search_filter(username), attrs, size_limit=10)
        if entry is None:
            entry = _search_with_ranking(conn, username, _build_contains_search_filter(username), attrs, size_limit=20)
        if entry is None:
            conn.unbind()
            return False, {"error": "USER_NOT_FOUND"}

        result = _entry_to_user(entry, fallback_username=_account_name(username) or username)
        conn.unbind()
        return True, result
    except Exception as exc:
        _log_directory_service_error("search_user", detail=type(exc).__name__)
        return False, LDAP_PUBLIC_ERROR.copy()


def authenticate(username: str, password: str):
    if not LDAP_ENABLED:
        return False, {"error": "LDAP_DISABLED"}
    username = text_value(username)
    password = _secret_value(password)
    if not username or not password:
        return False, {"error": "EMPTY_CREDENTIALS"}

    ok, user_info = search_user(username)
    if not ok:
        return False, user_info

    server = _server()
    for bind_user, auth_mode in _bind_candidates(username, user_info):
        try:
            _try_user_bind(server, bind_user, password, auth_mode=auth_mode)
            return True, user_info
        except Exception:
            continue

    _log_directory_service_error("authenticate")
    return False, LDAP_PUBLIC_ERROR.copy()
