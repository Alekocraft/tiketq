from __future__ import annotations

from functools import wraps

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from services.db import commit, execute, rollback, select_all, select_one
from services.ldap_auth import search_user
from services.roles import has_effective_role, is_admin, normalize_role, normalize_roles, role_choices, role_label

users_bp = Blueprint("users", __name__, url_prefix="")


TRUTHY = {"1", "true", "yes", "on", "si", "sí"}


def _current_roles() -> list[str]:
    return normalize_roles(
        getattr(current_user, "roles", [])
        or ([getattr(current_user, "role", "")] if getattr(current_user, "role", "") else [])
    )


def _is_admin() -> bool:
    return is_admin(_current_roles())


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not _is_admin():
            flash("Solo el administrador puede gestionar usuarios.", "error")
            return redirect(url_for("cases.dashboard"))
        return view(*args, **kwargs)

    return wrapped


def _is_truthy(value) -> bool:
    return str(value or "").strip().lower() in TRUTHY


def _available_role_choices() -> list[dict]:
    return role_choices(include_admin=True)


def _user_stats() -> dict:
    row = select_one(
        """
        SELECT
            COUNT(*) AS total_users,
            SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active_users,
            SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) AS inactive_users,
            SUM(CASE WHEN LOWER(ISNULL(role, '')) = 'administrador' THEN 1 ELSE 0 END) AS admin_users
        FROM dbo.users
        """
    ) or {}
    return {
        "total_users": int(row.get("total_users") or 0),
        "active_users": int(row.get("active_users") or 0),
        "inactive_users": int(row.get("inactive_users") or 0),
        "admin_users": int(row.get("admin_users") or 0),
    }


def _roles_by_user() -> dict[str, list[str]]:
    rows = select_all("SELECT user_id, role FROM dbo.user_roles ORDER BY user_id, role")
    result: dict[str, list[str]] = {}
    for row in rows:
        result.setdefault(row["user_id"], []).append(row["role"])
    return {user_id: normalize_roles(roles) for user_id, roles in result.items()}


def _decorate_user_rows(users: list[dict]) -> list[dict]:
    roles_map = _roles_by_user()
    decorated: list[dict] = []
    for user in users:
        roles = roles_map.get(user["id"], [])
        if not roles:
            primary = normalize_role(user.get("role") or "")
            roles = [primary] if primary else []
        user["roles"] = roles
        user["role_labels"] = [role_label(role) for role in roles]
        user["primary_role"] = roles[0] if roles else normalize_role(user.get("role") or "")
        user["primary_role_label"] = role_label(user["primary_role"])
        decorated.append(user)
    return decorated


def _load_users(q: str = "", role: str = "", state: str = "") -> list[dict]:
    where = []
    params = []

    if q:
        where.append(
            "(u.id LIKE ? OR u.display_name LIKE ? OR u.email LIKE ? OR u.job_title LIKE ? OR u.department LIKE ?)"
        )
        params.extend([f"%{q}%"] * 5)

    if state == "active":
        where.append("u.is_active = 1")
    elif state == "inactive":
        where.append("u.is_active = 0")

    sql = """
        SELECT
            u.id, u.display_name, u.email, u.role, u.is_active,
            u.job_title, u.department, u.created_at, u.updated_at
        FROM dbo.users u
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY u.display_name, u.id"

    users = _decorate_user_rows(select_all(sql, tuple(params)))
    if role:
        users = [user for user in users if role in user.get("roles", [])]
    return users


def _load_user(user_id: str) -> dict | None:
    row = select_one(
        """
        SELECT
            u.id, u.display_name, u.email, u.role, u.is_active,
            u.job_title, u.department, u.created_at, u.updated_at
        FROM dbo.users u
        WHERE u.id = ?
        """,
        (user_id,),
    )
    if not row:
        return None
    return _decorate_user_rows([row])[0]


def _save_roles(user_id: str, roles: list[str]) -> None:
    execute("DELETE FROM dbo.user_roles WHERE user_id = ?", (user_id,))
    for role in roles:
        execute(
            "INSERT INTO dbo.user_roles(user_id, role, created_at, updated_at) VALUES (?, ?, SYSDATETIME(), SYSDATETIME())",
            (user_id, role),
        )


def _sync_or_create_user(user_id: str, payload: dict, roles: list[str], active: bool) -> None:
    primary_role = roles[0] if roles else "sin_rol"
    effective_active = bool(active) and has_effective_role(roles or ([primary_role] if primary_role else []))
    execute(
        """
        MERGE dbo.users AS target
        USING (
            SELECT
                ? AS id,
                ? AS display_name,
                ? AS email,
                ? AS job_title,
                ? AS department,
                ? AS role,
                ? AS is_active
        ) AS src
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
            user_id,
            payload.get("display_name") or user_id,
            payload.get("email") or "",
            payload.get("job_title") or "",
            payload.get("department") or "",
            primary_role,
            1 if effective_active else 0,
        ),
    )
    _save_roles(user_id, roles)


def _manual_payload_from_form(user_id: str) -> dict:
    return {
        "username": user_id,
        "display_name": (request.form.get("display_name") or user_id).strip(),
        "email": (request.form.get("email") or "").strip(),
        "job_title": (request.form.get("job_title") or "").strip(),
        "department": (request.form.get("department") or "").strip(),
    }


@users_bp.route("/admin/users")
@admin_required
def list_users():
    q = (request.args.get("q") or "").strip()
    role = normalize_role(request.args.get("role") or "")
    state = (request.args.get("state") or "").strip().lower()

    users = _load_users(q=q, role=role, state=state)
    return render_template(
        "admin/users_list.html",
        title="Usuarios",
        users=users,
        stats=_user_stats(),
        q=q,
        role=role,
        state=state,
        role_choices=_available_role_choices(),
    )


@users_bp.route("/admin/users/new", methods=["GET", "POST"])
@admin_required
def create_user():
    preview_user = None
    username_value = (request.values.get("username") or "").strip()
    selected_roles = normalize_roles(request.values.getlist("roles"))
    form_data = {
        "display_name": (request.values.get("display_name") or "").strip(),
        "email": (request.values.get("email") or "").strip(),
        "job_title": (request.values.get("job_title") or "").strip(),
        "department": (request.values.get("department") or "").strip(),
        "is_active": _is_truthy(request.values.get("is_active", "1")),
    }

    if request.method == "POST":
        action = (request.form.get("action") or "lookup").strip().lower()
        if not username_value:
            flash("Debes indicar el usuario LDAP.", "error")
        else:
            ok, info = search_user(username_value)
            if not ok:
                flash("No fue posible consultar ese usuario en LDAP.", "error")
            else:
                preview_user = info
                form_data = {
                    "display_name": (request.form.get("display_name") or info.get("display_name") or username_value).strip(),
                    "email": (request.form.get("email") or info.get("email") or "").strip(),
                    "job_title": (request.form.get("job_title") or info.get("job_title") or "").strip(),
                    "department": (request.form.get("department") or info.get("department") or "").strip(),
                    "is_active": _is_truthy(request.form.get("is_active", "1")),
                }

                if action == "save":
                    try:
                        _sync_or_create_user(info.get("username") or username_value, form_data, selected_roles, form_data["is_active"])
                        commit()
                        if has_effective_role(selected_roles):
                            flash("Usuario creado y autorizado correctamente.", "success")
                        else:
                            flash("Usuario creado sin roles. Quedó inactivo hasta que se le asigne al menos un rol.", "success")
                        return redirect(url_for("users.edit_user", user_id=info.get("username") or username_value))
                    except Exception as exc:
                        rollback()
                        flash(f"No fue posible crear el usuario: {exc}", "error")

    return render_template(
        "admin/users_create.html",
        title="Crear usuario",
        preview_user=preview_user,
        username_value=username_value,
        selected_roles=selected_roles,
        role_choices=_available_role_choices(),
        form_data=form_data,
    )


@users_bp.route("/admin/users/<user_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_user(user_id: str):
    user = _load_user(user_id)
    if not user:
        abort(404)

    if request.method == "POST":
        action = (request.form.get("action") or "save").strip().lower()

        if action == "sync_ldap":
            ok, info = search_user(user_id)
            if not ok:
                flash("No fue posible refrescar los datos desde LDAP.", "error")
            else:
                try:
                    payload = {
                        "display_name": info.get("display_name") or user_id,
                        "email": info.get("email") or "",
                        "job_title": info.get("job_title") or "",
                        "department": info.get("department") or "",
                    }
                    _sync_or_create_user(user_id, payload, user.get("roles", []), bool(user.get("is_active")))
                    commit()
                    flash("Datos del usuario sincronizados desde LDAP.", "success")
                    return redirect(url_for("users.edit_user", user_id=user_id))
                except Exception as exc:
                    rollback()
                    flash(f"No fue posible sincronizar el usuario: {exc}", "error")
        else:
            roles = normalize_roles(request.form.getlist("roles"))
            active = _is_truthy(request.form.get("is_active"))
            effective_active = bool(active) and has_effective_role(roles)
            if user_id == current_user.username and not effective_active:
                flash("No puedes dejar tu propio usuario sin roles o inactivo mientras estás autenticado.", "error")
            else:
                try:
                    payload = _manual_payload_from_form(user_id)
                    _sync_or_create_user(user_id, payload, roles, active)
                    commit()
                    if has_effective_role(roles):
                        flash("Usuario actualizado correctamente.", "success")
                    else:
                        flash("Usuario actualizado sin roles. Quedó inactivo hasta que se le asigne al menos un rol.", "success")
                    return redirect(url_for("users.edit_user", user_id=user_id))
                except Exception as exc:
                    rollback()
                    flash(f"No fue posible actualizar el usuario: {exc}", "error")

        user = _load_user(user_id)

    return render_template(
        "admin/users_edit.html",
        title="Editar usuario",
        user=user,
        role_choices=_available_role_choices(),
    )


@users_bp.route("/admin/users/<user_id>/deactivate", methods=["POST"])
@admin_required
def deactivate_user(user_id: str):
    if user_id == current_user.username:
        flash("No puedes desactivar tu propio usuario.", "error")
        return redirect(url_for("users.list_users"))

    execute("UPDATE dbo.users SET is_active = 0, updated_at = SYSDATETIME() WHERE id = ?", (user_id,))
    commit()
    flash("Usuario desactivado.", "success")
    return redirect(request.referrer or url_for("users.list_users"))


@users_bp.route("/admin/users/<user_id>/reactivate", methods=["POST"])
@admin_required
def reactivate_user(user_id: str):
    user = _load_user(user_id)
    if not user:
        flash("El usuario no existe.", "error")
        return redirect(request.referrer or url_for("users.list_users"))
    if not has_effective_role(user.get("roles", [])):
        flash("No se puede reactivar un usuario sin roles. Asígnale al menos un rol primero.", "error")
        return redirect(request.referrer or url_for("users.edit_user", user_id=user_id))
    execute("UPDATE dbo.users SET is_active = 1, updated_at = SYSDATETIME() WHERE id = ?", (user_id,))
    commit()
    flash("Usuario reactivado.", "success")
    return redirect(request.referrer or url_for("users.list_users"))


@users_bp.route("/admin/users/<user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id: str):
    if user_id == current_user.username:
        flash("No puedes eliminar tu propio usuario.", "error")
        return redirect(url_for("users.list_users"))

    user = _load_user(user_id)
    if not user:
        flash("El usuario ya no existe.", "error")
        return redirect(url_for("users.list_users"))

    if bool(user.get("is_active")):
        flash("Primero debes desactivar el usuario antes de eliminarlo.", "error")
        return redirect(url_for("users.list_users"))

    refs = select_one(
        """
        SELECT
            (SELECT COUNT(*) FROM dbo.case_updates WHERE author_id = ?) AS updates_count,
            (SELECT COUNT(*) FROM dbo.notifications WHERE user_id = ?) AS notifications_count,
            (SELECT COUNT(*) FROM dbo.cases WHERE LOWER(ISNULL(assigned_to, '')) = LOWER(?)) AS assigned_cases_count
        """,
        (user_id, user_id, user_id),
    ) or {}

    if any(int(refs.get(key) or 0) > 0 for key in ("updates_count", "notifications_count", "assigned_cases_count")):
        flash(
            "No se puede eliminar porque el usuario tiene trazabilidad en casos, notificaciones o actualizaciones. Déjalo inactivo.",
            "error",
        )
        return redirect(url_for("users.list_users"))

    try:
        execute("DELETE FROM dbo.user_roles WHERE user_id = ?", (user_id,))
        execute("DELETE FROM dbo.users WHERE id = ?", (user_id,))
        commit()
        flash("Usuario eliminado definitivamente.", "success")
    except Exception as exc:
        rollback()
        flash(f"No fue posible eliminar el usuario: {exc}", "error")

    return redirect(url_for("users.list_users"))
