import os

from services.security import bool_from_value, int_from_value, text_value

LDAP_ENABLED = bool_from_value(os.getenv("LDAP_ENABLED"), True)

LDAP_SERVER = text_value(os.getenv("LDAP_SERVER"), "localhost")
LDAP_PORT = int_from_value(os.getenv("LDAP_PORT"), 389)
LDAP_USE_SSL = bool_from_value(os.getenv("LDAP_USE_SSL"), False)
LDAP_CONNECTION_TIMEOUT = int_from_value(os.getenv("LDAP_CONNECTION_TIMEOUT"), 8)

LDAP_DOMAIN = text_value(os.getenv("LDAP_DOMAIN"))
LDAP_SEARCH_BASE = text_value(os.getenv("LDAP_SEARCH_BASE"))

LDAP_SERVICE_USER = text_value(os.getenv("LDAP_SERVICE_USER"))
LDAP_SERVICE_PASSWORD = text_value(os.getenv("LDAP_SERVICE_PASSWORD"))
