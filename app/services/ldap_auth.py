from dataclasses import dataclass
import socket

from ldap3 import Server, Connection, NONE, NTLM
from ldap3.core.exceptions import LDAPException


@dataclass
class LdapResult:
    ok: bool
    username: str | None = None
    display_name: str | None = None
    email: str | None = None
    error: str | None = None


def _tcp_check(host: str, port: int, timeout: int) -> tuple[bool, str | None]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, None
    except Exception as ex:
        return False, str(ex)


def _norm_sam(username: str) -> str:
    u = (username or "").strip()
    if "\\" in u:
        return u.split("\\", 1)[1]
    if "@" in u:
        return u.split("@", 1)[0]
    return u


def _try_bind(server: Server, bind_user: str, password: str, timeout: int, use_ntlm: bool) -> tuple[bool, str | None]:
    try:
        if use_ntlm:
            conn = Connection(
                server,
                user=bind_user,
                password=password,
                authentication=NTLM,
                auto_bind=True,
                receive_timeout=timeout,
            )
        else:
            conn = Connection(
                server,
                user=bind_user,
                password=password,
                auto_bind=True,
                receive_timeout=timeout,
            )
        conn.unbind()
        return True, None
    except Exception as ex:
        return False, str(ex)


def _service_bind_and_lookup(cfg, server: Server, sam: str, timeout: int) -> tuple[dict, str | None]:
    """
    Se conecta con cuenta de servicio y busca DN/UPN/mail/displayName del usuario.
    Retorna: (attrs_dict, error)
    """
    svc_user = (cfg.LDAP_SERVICE_USER or "").strip()
    svc_pwd = (cfg.LDAP_SERVICE_PASSWORD or "")
    if not svc_user or not svc_pwd:
        return {}, "No hay cuenta de servicio configurada"

    # Intentar con varios formatos para la cuenta de servicio
    candidates: list[tuple[str, bool]] = []
    # 1) Si ya viene con \ o @, úsalo como está (simple)
    candidates.append((svc_user, False))

    # 2) Si hay NETBIOS y no trae \, intentar NTLM
    if "\\" not in svc_user and getattr(cfg, "LDAP_NETBIOS", None):
        candidates.append((f"{cfg.LDAP_NETBIOS}\\{svc_user}", True))

    # 3) Si hay dominio y no trae @, intentar UPN
    if "@" not in svc_user and getattr(cfg, "LDAP_DOMAIN", None):
        candidates.append((f"{svc_user}@{cfg.LDAP_DOMAIN}", False))

    last_err = None
    bound_conn = None

    for u, is_ntlm in candidates:
        try:
            if is_ntlm:
                bound_conn = Connection(server, user=u, password=svc_pwd, authentication=NTLM, auto_bind=True, receive_timeout=timeout)
            else:
                bound_conn = Connection(server, user=u, password=svc_pwd, auto_bind=True, receive_timeout=timeout)
            break
        except Exception as ex:
            last_err = str(ex)

    if not bound_conn:
        return {}, f"Service bind falló: {last_err}"

    try:
        bound_conn.search(
            search_base=cfg.LDAP_SEARCH_BASE,
            search_filter=f"(sAMAccountName={sam})",
            attributes=["distinguishedName", "userPrincipalName", "displayName", "mail", "sAMAccountName"],
        )
        attrs = {}
        if bound_conn.entries:
            e = bound_conn.entries[0]
            attrs["dn"] = str(e.distinguishedName) if "distinguishedName" in e else None
            attrs["upn"] = str(e.userPrincipalName) if "userPrincipalName" in e else None
            attrs["display_name"] = str(e.displayName) if "displayName" in e else None
            attrs["email"] = str(e.mail) if "mail" in e else None
        bound_conn.unbind()
        return attrs, None
    except Exception as ex:
        try:
            bound_conn.unbind()
        except Exception:
            pass
        return {}, f"Service search falló: {ex}"


def authenticate(cfg, username: str, password: str) -> LdapResult:
    if not cfg.LDAP_SERVER or not cfg.LDAP_SEARCH_BASE:
        return LdapResult(False, error="LDAP no configurado (LDAP_SERVER/LDAP_SEARCH_BASE).")

    host = cfg.LDAP_SERVER
    port = int(cfg.LDAP_PORT or 389)
    timeout = int(getattr(cfg, "LDAP_CONNECT_TIMEOUT", 5) or 5)
    use_ssl = bool(getattr(cfg, "LDAP_USE_SSL", False)) or port == 636

    tcp_ok, tcp_err = _tcp_check(host, port, timeout)
    if not tcp_ok:
        return LdapResult(False, error=f"TCP LDAP no accesible a {host}:{port} -> {tcp_err}")

    sam = _norm_sam(username)

    server = Server(
        host,
        port=port,
        use_ssl=use_ssl,
        get_info=NONE,
        connect_timeout=timeout,
    )

    # 1) Buscar DN/UPN reales con cuenta de servicio (si está)
    attrs, svc_err = _service_bind_and_lookup(cfg, server, sam, timeout)

    dn = attrs.get("dn")
    upn = attrs.get("upn")
    display_name = attrs.get("display_name")
    email = attrs.get("email")

    # 2) Preparar intentos de bind del usuario (orden: DN -> UPN -> NETBIOS\sam (NTLM) -> sam@domain)
    attempts: list[tuple[str, bool]] = []

    if dn:
        attempts.append((dn, False))  # simple bind con DN
    if upn:
        attempts.append((upn, False))  # simple bind con UPN real
    if getattr(cfg, "LDAP_NETBIOS", None):
        attempts.append((f"{cfg.LDAP_NETBIOS}\\{sam}", True))  # NTLM
    if getattr(cfg, "LDAP_DOMAIN", None):
        attempts.append((f"{sam}@{cfg.LDAP_DOMAIN}", False))  # UPN genérico (fallback)

    # si el usuario escribió algo como DOMINIO\user o user@algo, probarlo primero también:
    typed = (username or "").strip()
    if typed and typed not in [a[0] for a in attempts]:
        attempts.insert(0, (typed, ("\\" in typed and "@" not in typed)))  # si es DOM\user, intentar NTLM

    last_err = None
    for bind_user, is_ntlm in attempts:
        ok, err = _try_bind(server, bind_user, password, timeout, use_ntlm=is_ntlm)
        if ok:
            # si no se pudo consultar display/email (porque service bind falló), al menos devolvemos sam
            return LdapResult(True, username=sam, display_name=display_name or sam, email=email)

        last_err = err

    # Info útil si service bind estaba mal
    extra = f" | {svc_err}" if svc_err else ""
    return LdapResult(False, error=f"{last_err}{extra}")


def ldap_healthcheck(cfg) -> dict:
    host = cfg.LDAP_SERVER
    port = int(cfg.LDAP_PORT or 389)
    timeout = int(getattr(cfg, "LDAP_CONNECT_TIMEOUT", 5) or 5)
    use_ssl = bool(getattr(cfg, "LDAP_USE_SSL", False)) or port == 636

    tcp_ok, tcp_err = (False, "LDAP_SERVER vacío")
    if host:
        tcp_ok, tcp_err = _tcp_check(host, port, timeout)

    return {
        "server": host,
        "port": port,
        "use_ssl": use_ssl,
        "timeout": timeout,
        "tcp_ok": tcp_ok,
        "tcp_error": tcp_err,
        "search_base": getattr(cfg, "LDAP_SEARCH_BASE", None),
        "domain": getattr(cfg, "LDAP_DOMAIN", None),
        "netbios": getattr(cfg, "LDAP_NETBIOS", None),
        "service_user_configured": bool(getattr(cfg, "LDAP_SERVICE_USER", None)),
    }
