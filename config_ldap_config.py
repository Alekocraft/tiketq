import os

def _bool(env_value, default=False) -> bool:
    if env_value is None:
        return default
    return str(env_value).strip().lower() in ("1", "true", "yes", "y", "on")

LDAP_ENABLED = _bool(os.getenv("LDAP_ENABLED"), True)

# Servidor LDAP: "ldap://host" o "ldaps://host"
LDAP_SERVER = os.getenv("LDAP_SERVER", "ldap://localhost")
LDAP_PORT = int(os.getenv("LDAP_PORT", "389"))
LDAP_USE_SSL = _bool(os.getenv("LDAP_USE_SSL"), False)
LDAP_CONNECTION_TIMEOUT = int(os.getenv("LDAP_CONNECTION_TIMEOUT", "8"))

LDAP_DOMAIN = os.getenv("LDAP_DOMAIN", "")
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE", "")

# Cuenta de servicio
LDAP_SERVICE_USER = os.getenv("LDAP_SERVICE_USER", "")
LDAP_SERVICE_PASSWORD = os.getenv("LDAP_SERVICE_PASSWORD", "")
