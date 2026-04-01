from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_user, logout_user

from models.user import User
from services.db import commit, execute, select_all, select_one
from services.ldap_auth import authenticate, test_connection
from services.roles import has_effective_role, normalize_role, normalize_roles


auth_bp = Blueprint("auth", __name__, url_prefix="")


def _load_roles(user_id: str) -> list[str]:
    rows = select_all("SELECT role FROM dbo.user_roles WHERE user_id = ? ORDER BY role", (user_id,))
    return normalize_roles([r.get("role") for r in rows if r.get("role")])


def _replace_roles(user_id: str, roles) -> list[str]:
    normalized = normalize_roles(roles)
    execute("DELETE FROM dbo.user_roles WHERE user_id = ?", (user_id,))
    for role in normalized:
        execute(
            "INSERT INTO dbo.user_roles(user_id, role, created_at, updated_at) VALUES (?, ?, SYSDATETIME(), SYSDATETIME())",
            (user_id, role),
        )
    return normalized


def _upsert_user(user: User):
    row = select_one("SELECT role, is_active FROM dbo.users WHERE id = ?", (user.username,))
    stored_primary = normalize_role((row or {}).get("role") or "")
    current_roles = _load_roles(user.username)
    primary_role = current_roles[0] if current_roles else stored_primary
    effective_active = bool((row or {}).get("is_active", 1)) and has_effective_role(current_roles or ([primary_role] if primary_role else []))

    execute(
        """
        MERGE dbo.users AS target
        USING (SELECT ? AS id, ? AS display_name, ? AS email, ? AS job_title, ? AS department, ? AS role, ? AS is_active) AS src
        ON target.id = src.id
        WHEN MATCHED THEN
            UPDATE SET
                display_name = src.display_name,
                email = src.email,
                job_title = src.job_title,
                department = src.department,
                role = src.role,
                is_active = src.is_active,
                updated_at = SYSDATETIME()
        WHEN NOT MATCHED THEN
            INSERT (id, display_name, email, job_title, department, role, is_active, created_at, updated_at)
            VALUES (src.id, src.display_name, src.email, src.job_title, src.department, src.role, src.is_active, SYSDATETIME(), SYSDATETIME());
        """,
        (
            user.username,
            user.display_name,
            user.email,
            user.job_title,
            user.department,
            primary_role or "sin_rol",
            1 if effective_active else 0,
        ),
    )
    commit()

    latest_roles = _load_roles(user.username)
    user.roles = latest_roles
    user.role = latest_roles[0] if latest_roles else (primary_role or "sin_rol")
    user.active = effective_active


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("cases.dashboard"))

    if request.method == "POST":
        usuario = (request.form.get("usuario") or "").strip()
        contrasena = request.form.get("contrasena") or ""

        ok, info = authenticate(usuario, contrasena)
        if ok:
            user = User(
                info.get("username", usuario),
                info.get("display_name", ""),
                info.get("email", ""),
                job_title=info.get("job_title", ""),
                department=info.get("department", ""),
            )
            existing = select_one("SELECT id, is_active FROM dbo.users WHERE id = ?", (user.username,))
            counts = select_one("SELECT COUNT(*) AS total_users FROM dbo.users") or {}
            total_users = int(counts.get("total_users") or 0)

            if not existing and total_users == 0:
                user.roles = ["administrador"]
                user.role = "administrador"
                execute(
                    """
                    INSERT INTO dbo.users(id, display_name, email, role, is_active, created_at, updated_at, job_title, department)
                    VALUES (?, ?, ?, 'administrador', 1, SYSDATETIME(), SYSDATETIME(), ?, ?)
                    """,
                    (user.username, user.display_name, user.email, user.job_title, user.department),
                )
                _replace_roles(user.username, ["administrador"])
                commit()
                flash("Primer administrador inicializado correctamente.", "success")
            elif not existing:
                flash("Tu usuario no está autorizado en el sistema. Solicita alta al administrador.", "error")
                return render_template("auth/login.html")
            elif not bool(existing.get("is_active", 0)):
                flash("Tu usuario está inactivo. Contacta al administrador.", "error")
                return render_template("auth/login.html")
            else:
                _upsert_user(user)
                if not user.is_active or not has_effective_role(user.roles or ([user.role] if user.role else [])):
                    execute("UPDATE dbo.users SET role = 'sin_rol', is_active = 0, updated_at = SYSDATETIME() WHERE id = ?", (user.username,))
                    commit()
                    flash("Tu usuario no tiene roles asignados y quedó inactivo. Contacta al administrador.", "error")
                    return render_template("auth/login.html")

            login_user(user)
            session["user_display_name"] = info.get("display_name") or user.display_name
            session["user_job_title"] = (info.get("job_title") or "").strip()
            session["user_department"] = (info.get("department") or "").strip()
            next_url = request.args.get("next")
            return redirect(next_url or url_for("cases.dashboard"))

        flash("Credenciales inválidas o usuario no encontrado en directorio.", "error")
        return render_template("auth/login.html")

    return render_template("auth/login.html")


@auth_bp.route("/logout")
def logout():
    logout_user()
    for key in ("user_display_name", "user_job_title", "user_department"):
        session.pop(key, None)
    return redirect(url_for("auth.login"))


@auth_bp.route("/test-ldap")
def test_ldap():
    ok, msg = test_connection()
    if ok:
        flash("Conexión LDAP OK.", "success")
    else:
        flash(f"Conexión LDAP falló: {msg}", "error")
    return redirect(url_for("auth.login"))
