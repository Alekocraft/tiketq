from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from sqlalchemy.exc import OperationalError

from app.services.ldap_auth import authenticate
from app.db import get_engine
from app.repositories.usuarios_repo import get_or_create_usuario, get_roles_usuario

auth_bp = Blueprint("auth", __name__, url_prefix="")


@auth_bp.get("/login")
def login():
    return render_template("auth/login.html", next=request.args.get("next", "/"))


@auth_bp.post("/login")
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    next_url = request.form.get("next") or "/"

    if not username or not password:
        flash("Usuario y contraseña son obligatorios.", "warning")
        return redirect(url_for("auth.login", next=next_url))

    cfg = current_app.config["APP_CONFIG"]

    # 1) LDAP
    ldap_res = authenticate(cfg, username, password)
    if not ldap_res.ok:
        flash(f"No fue posible autenticar: {ldap_res.error}", "danger")
        return redirect(url_for("auth.login", next=next_url))

    # 2) BD (si falla, NO 500)
    try:
        engine = get_engine(cfg)
        usuario = get_or_create_usuario(engine, ldap_res.username, ldap_res.email)
        roles = get_roles_usuario(engine, usuario["id_usuario"])
    except OperationalError as ex:
        flash(f"No fue posible conectar a la base de datos: {ex}", "danger")
        return redirect(url_for("auth.login", next=next_url))
    except Exception as ex:
        flash(f"Error interno al crear/consultar usuario en BD: {ex}", "danger")
        return redirect(url_for("auth.login", next=next_url))

    session["user"] = {
        "id_usuario": usuario["id_usuario"],
        "usuario_ldap": usuario["usuario_ldap"],
        "correo": usuario.get("correo"),
        "roles": roles,
        "display_name": ldap_res.display_name or ldap_res.username
    }

    flash(f"Bienvenido, {session['user']['display_name']}", "success")
    return redirect(next_url)


@auth_bp.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
