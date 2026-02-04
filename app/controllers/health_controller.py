from flask import Blueprint, jsonify, current_app
from app.db import get_engine, db_healthcheck, db_config_info
from app.services.ldap_auth import ldap_healthcheck

health_bp = Blueprint("health", __name__, url_prefix="/health")


@health_bp.get("/db")
def db():
    cfg = current_app.config["APP_CONFIG"]
    engine = get_engine(cfg)
    ok, err = db_healthcheck(engine)
    return jsonify({"ok": ok, "error": err, "config": db_config_info(cfg)})


@health_bp.get("/ldap")
def ldap():
    cfg = current_app.config["APP_CONFIG"]
    return jsonify(ldap_healthcheck(cfg))


@health_bp.get("/ping")
def ping():
    return jsonify({"ok": True})
