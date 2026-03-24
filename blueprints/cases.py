from __future__ import annotations

import csv
import io
import os
from datetime import datetime
from typing import Optional

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required

from services.db import commit, execute, get_db, rollback, select_all, select_one
from services.ldap_auth import search_user
from services.roles import can_ingest, can_resolve, can_triage, is_admin, normalize_role, normalize_roles, role_choices, role_label, team_aliases_for_roles, triage_targets_for_roles
from services.sla import compute_due_dates, get_priority_defaults, humanize_minutes, normalize_priority, priority_choices

cases_bp = Blueprint("cases", __name__, url_prefix="")

OPEN_STATUSES = {"pendiente", "asignado", "reabierto"}
RESOLVED_STATUSES = {"resuelto"}
HIDDEN_STATUSES = {"cerrado"}
FINAL_STATUSES = RESOLVED_STATUSES | HIDDEN_STATUSES
PRIORITY_CHOICES = [choice["key"] for choice in priority_choices()]


def _fetchall_dict(cur):
    rows = cur.fetchall()
    if not rows:
        return []
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in rows]


def _fetchone_dict(cur):
    row = cur.fetchone()
    if not row:
        return None
    cols = [c[0] for c in cur.description]
    return dict(zip(cols, row))


def _current_roles() -> list[str]:
    return normalize_roles(
        getattr(current_user, "roles", [])
        or ([getattr(current_user, "role", "")] if getattr(current_user, "role", "") else [])
    )


def _is_admin() -> bool:
    return is_admin(_current_roles())


def _is_manager() -> bool:
    return _is_admin()


def _can_triage() -> bool:
    return can_triage(_current_roles())


def _can_ingest() -> bool:
    return can_ingest(_current_roles())


def _can_resolve() -> bool:
    return can_resolve(_current_roles())


def _dedupe(items):
    result = []
    for item in items:
        if item and item not in result:
            result.append(item)
    return result


def _triage_team_choices() -> list[dict]:
    targets = triage_targets_for_roles(_current_roles())
    return [choice for choice in role_choices() if choice["key"] in targets]


def _priority_choices() -> list[dict]:
    return priority_choices()


def _fmt_dt(value):
    if not value:
        return "-"
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M")
    return str(value)


def _decorate_case(row: Optional[dict]):
    if not row:
        return row
    priority = normalize_priority(row.get("priority") or "MEDIA")
    response_min, resolution_min = get_priority_defaults(priority)
    response_min = int(row.get("sla_response_min") or response_min)
    resolution_min = int(row.get("sla_resolution_min") or resolution_min)
    created_at = row.get("created_at") or datetime.now()
    response_due = row.get("response_due_at")
    resolution_due = row.get("resolution_due_at")
    if not response_due or not resolution_due:
        response_due, resolution_due = compute_due_dates(created_at, response_min, resolution_min)
    row["priority"] = priority
    row["priority_label"] = priority.title()
    row["priority_css"] = priority.lower()
    row["sla_response_min"] = response_min
    row["sla_resolution_min"] = resolution_min
    row["sla_response_text"] = humanize_minutes(response_min)
    row["sla_resolution_text"] = humanize_minutes(resolution_min)
    row["response_due_at"] = response_due
    row["resolution_due_at"] = resolution_due
    row["response_due_at_display"] = _fmt_dt(response_due)
    row["resolution_due_at_display"] = _fmt_dt(resolution_due)
    row["sla_window_text"] = f"{row['sla_response_text']} / {row['sla_resolution_text']}"
    row["assigned_team"] = normalize_role(row.get("assigned_team") or "")
    row["assigned_team_label"] = role_label(row.get("assigned_team") or "") if row.get("assigned_team") else "-"
    return row


def _work_queue_aliases() -> list[str]:
    return _dedupe(team_aliases_for_roles(_current_roles()))


def _visibility_condition(alias: str = "c", scope: str = "all"):
    if _is_admin():
        if scope == "mine":
            return f"LOWER(ISNULL({alias}.assigned_to, '')) = LOWER(?)", [current_user.username]
        return "", []

    team_aliases = _work_queue_aliases()
    user_clause = f"LOWER(ISNULL({alias}.assigned_to, '')) = LOWER(?)"
    if not team_aliases:
        return user_clause, [current_user.username]

    expr = f"LOWER(REPLACE(REPLACE(ISNULL({alias}.assigned_team, ''), ' ', '_'), '-', '_'))"
    placeholders = ", ".join(["?"] * len(team_aliases))
    team_clause = f"{expr} IN ({placeholders})"
    return f"({team_clause} OR {user_clause})", [*team_aliases, current_user.username]


def _notif_count() -> int:
    row = select_one(
        "SELECT COUNT(*) AS c FROM dbo.notifications WHERE user_id=? AND is_read=0",
        (current_user.username,),
    )
    return int(row["c"]) if row and row.get("c") is not None else 0


def _role_scope_labels() -> list[str]:
    roles = _current_roles()
    if _is_admin():
        return ["Administrador"]
    return [role_label(r) for r in roles] or ["Sin rol asignado"]


def _dashboard_stats():
    db = get_db()
    visibility_sql, visibility_params = _visibility_condition("c", scope="all")
    mine_sql, mine_params = _visibility_condition("c", scope="mine")

    filters = ["LOWER(ISNULL(c.status, '')) <> 'cerrado'"]
    params = list(visibility_params)
    if visibility_sql:
        filters.insert(0, visibility_sql)
    where_clause = "WHERE " + " AND ".join(filters)
    cur = db.cursor()
    cur.execute(
        f"""
        SELECT
            COUNT(*) AS total_cases,
            SUM(CASE WHEN LOWER(c.status) IN ('pendiente', 'asignado', 'reabierto') THEN 1 ELSE 0 END) AS open_cases,
            SUM(CASE WHEN LOWER(c.status) = 'resuelto' THEN 1 ELSE 0 END) AS resolved_cases,
            SUM(CASE WHEN LOWER(c.status) = 'reabierto' THEN 1 ELSE 0 END) AS reopened_cases,
            SUM(CASE WHEN UPPER(c.priority) IN ('ALTA', 'P1') THEN 1 ELSE 0 END) AS high_priority
        FROM dbo.cases c
        {where_clause}
        """,
        params,
    )
    stats = _fetchone_dict(cur) or {}

    mine_filters = ["LOWER(ISNULL(c.status, '')) <> 'cerrado'"]
    mine_bindings = []
    if mine_sql:
        mine_filters.insert(0, mine_sql)
        mine_bindings.extend(mine_params)
    else:
        mine_filters.insert(0, "LOWER(ISNULL(c.assigned_to, '')) = LOWER(?)")
        mine_bindings.append(current_user.username)
    mine_where = "WHERE " + " AND ".join(mine_filters)
    mine_row = select_one(
        f"SELECT COUNT(*) AS total_cases FROM dbo.cases c {mine_where}",
        tuple(mine_bindings),
    ) or {}

    cur_recent = db.cursor()
    cur_recent.execute(
        f"""
        SELECT TOP 8
            c.id, c.subject, c.status, c.priority, c.assigned_team,
            c.assigned_to, c.requester_email, c.created_at, c.updated_at
        FROM dbo.cases c
        {where_clause}
        ORDER BY c.created_at DESC
        """,
        params,
    )
    recent_cases = _fetchall_dict(cur_recent)

    cur_ingest = db.cursor()
    cur_ingest.execute(
        """
        SELECT TOP 1 processed_at, status, case_id, email_message_id
        FROM dbo.email_ingest_log
        ORDER BY processed_at DESC
        """
    )
    last_ingest = _fetchone_dict(cur_ingest)

    return {
        "total_cases": int(stats.get("total_cases") or 0),
        "open_cases": int(stats.get("open_cases") or 0),
        "resolved_cases": int(stats.get("resolved_cases") or 0),
        "reopened_cases": int(stats.get("reopened_cases") or 0),
        "high_priority": int(stats.get("high_priority") or 0),
        "my_cases": int(mine_row.get("total_cases") or 0),
        "recent_cases": recent_cases,
        "last_ingest": last_ingest,
        "notif_count": _notif_count(),
        "scope_labels": _role_scope_labels(),
    }


def _list_cases(scope: str = "all"):
    db = get_db()
    status = (request.args.get("status") or "").strip()
    q = (request.args.get("q") or "").strip()
    assigned_team = normalize_role(request.args.get("assigned_team") or "")

    try:
        limit = int(request.args.get("limit", 50))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))

    where = []
    params = []

    visibility_sql, visibility_params = _visibility_condition("c", scope="mine" if scope == "mine" else "all")
    where.append("LOWER(ISNULL(c.status, '')) <> 'cerrado'")

    if visibility_sql:
        where.append(visibility_sql)
        params.extend(visibility_params)

    if status and status.strip().lower() != "cerrado":
        where.append("LOWER(c.status) = LOWER(?)")
        params.append(status)

    if q:
        where.append("(c.id LIKE ? OR c.subject LIKE ? OR c.requester_email LIKE ?)")
        params.extend([f"%{q}%"] * 3)

    if assigned_team and _is_admin() and scope != "mine":
        where.append("LOWER(REPLACE(REPLACE(ISNULL(c.assigned_team, ''), ' ', '_'), '-', '_')) = ?")
        params.append(assigned_team)

    sql = """
        SELECT
            c.id, c.subject, c.description, c.status, c.priority, c.category, c.subcategory,
            c.assigned_team, c.assigned_to,
            u.display_name AS assigned_user_name,
            c.requester_name, c.requester_email,
            c.sla_response_min, c.sla_resolution_min, c.response_due_at, c.resolution_due_at,
            c.created_at, c.updated_at, c.first_response_at, c.resolved_at, c.closed_at
        FROM dbo.cases c
        LEFT JOIN dbo.users u ON u.id = c.assigned_to
    """

    if where:
        sql += " WHERE " + " AND ".join(where)

    sql += " ORDER BY c.created_at DESC OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY"
    params_with_limit = params + [limit]

    cur = db.cursor()
    cur.execute(sql, params_with_limit)
    cases = [_decorate_case(row) for row in _fetchall_dict(cur)]

    summary_clause = " WHERE " + " AND ".join(where) if where else ""
    cur_summary = db.cursor()
    cur_summary.execute(
        f"""
        SELECT
            COUNT(*) AS total_cases,
            SUM(CASE WHEN LOWER(c.status) IN ('pendiente', 'asignado', 'reabierto') THEN 1 ELSE 0 END) AS open_cases,
            SUM(CASE WHEN LOWER(c.status) = 'resuelto' THEN 1 ELSE 0 END) AS resolved_cases,
            SUM(CASE WHEN LOWER(c.status) = 'reabierto' THEN 1 ELSE 0 END) AS reopened_cases
        FROM dbo.cases c
        {summary_clause}
        """,
        params,
    )
    summary = _fetchone_dict(cur_summary) or {}

    return render_template(
        "cases/list.html",
        title="Mis tickets" if scope == "mine" else "Casos",
        cases=cases,
        notif_count=_notif_count(),
        status=status,
        q=q,
        limit=limit,
        summary=summary,
        scope=scope,
        assigned_team=assigned_team,
        role_choices=role_choices(),
        scope_labels=_role_scope_labels(),
        can_triage=_can_triage(),
    )


def _get_case(case_id: str):
    visibility_sql, visibility_params = _visibility_condition("c", scope="all")
    sql = """
        SELECT
            c.id, c.subject, c.description, c.status, c.priority, c.category, c.subcategory,
            c.assigned_team, c.assigned_to, c.requester_name, c.requester_email,
            c.sla_response_min, c.sla_resolution_min, c.response_due_at, c.resolution_due_at,
            c.created_at, c.updated_at, c.first_response_at, c.resolved_at, c.closed_at,
            u.display_name AS assigned_user_name
        FROM dbo.cases c
        LEFT JOIN dbo.users u ON u.id = c.assigned_to
        WHERE c.id = ?
    """
    params = [case_id]
    if visibility_sql:
        sql += f" AND {visibility_sql}"
        params.extend(visibility_params)
    return _decorate_case(select_one(sql, tuple(params)))


def _record_case_update(case_id: str, message: str, is_solution: bool = False):
    execute(
        """
        INSERT INTO dbo.case_updates(case_id, author_id, author_name, author_email, message, is_solution, created_at)
        VALUES (?, ?, ?, ?, ?, ?, SYSDATETIME())
        """,
        (
            case_id,
            current_user.username,
            current_user.display_name,
            current_user.email,
            message,
            1 if is_solution else 0,
        ),
    )


@cases_bp.route("/dashboard")
@login_required
def dashboard():
    data = _dashboard_stats()
    data["summary"] = {
        "total_cases": data.get("total_cases", 0),
        "open_cases": data.get("open_cases", 0),
        "resolved_cases": data.get("resolved_cases", 0),
        "reopened_cases": data.get("reopened_cases", 0),
        "high_priority": data.get("high_priority", 0),
        "my_cases": data.get("my_cases", 0),
    }
    data["latest_ingest"] = data.get("last_ingest")
    data["active_roles"] = _role_scope_labels()
    return render_template("dashboard.html", title="Inicio", **data)


@cases_bp.route("/cases")
@login_required
def list_cases():
    return _list_cases("all")


@cases_bp.route("/mis-tickets")
@login_required
def my_tickets():
    return _list_cases("mine")


@cases_bp.route("/cases/categorizados")
@login_required
def categorized_cases():
    return redirect(url_for("cases.my_tickets"))

@cases_bp.route("/cases/<case_id>")
@login_required
def case_detail(case_id):
    case_row = _get_case(case_id)
    if not case_row:
        abort(404)

    attachments = select_all(
        "SELECT filename, stored_path, size_bytes FROM dbo.case_attachments WHERE case_id = ? ORDER BY id DESC",
        (case_id,),
    )
    updates = select_all(
        """
        SELECT author_name, author_email, message, is_solution, created_at
        FROM dbo.case_updates
        WHERE case_id = ?
        ORDER BY created_at DESC
        """,
        (case_id,),
    )
    return render_template(
        "cases/detail.html",
        title=f"Caso {case_id}",
        c=case_row,
        atts=attachments,
        updates=updates,
        notif_count=_notif_count(),
        can_reopen=(_can_resolve() and str(case_row.get("status") or "").strip().lower() in FINAL_STATUSES),
        can_resolve=(_can_resolve() and str(case_row.get("status") or "").strip().lower() not in FINAL_STATUSES),
        can_close=(_can_resolve() and str(case_row.get("status") or "").strip().lower() in RESOLVED_STATUSES),
        can_triage=_can_triage(),
        triage_teams=_triage_team_choices(),
        priority_choices=_priority_choices(),
    )


@cases_bp.route("/cases/<case_id>/attachments/<path:filename>")
@login_required
def download_attachment(case_id, filename):
    case_row = _get_case(case_id)
    if not case_row:
        abort(404)
    row = select_one(
        "SELECT TOP 1 filename, stored_path FROM dbo.case_attachments WHERE case_id = ? AND filename = ?",
        (case_id, filename),
    )
    if not row:
        abort(404)
    stored_path = row.get("stored_path") or ""
    if not stored_path or not os.path.exists(stored_path):
        abort(404)
    return send_file(stored_path, as_attachment=True, download_name=row.get("filename") or filename)


@cases_bp.route("/cases/<case_id>/status", methods=["POST"])
@login_required
def change_case_status(case_id):
    case_row = _get_case(case_id)
    if not case_row:
        abort(404)
    if not _can_resolve():
        flash("No tienes permisos para actualizar el estado de este caso.", "error")
        return redirect(url_for("cases.case_detail", case_id=case_id))

    action = (request.form.get("action") or "").strip().lower()
    note = (request.form.get("note") or "").strip()

    if action not in {"resolve", "reopen", "close"}:
        flash("Acción no reconocida.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case_id))

    if not note:
        flash("La nota es obligatoria para actualizar el estado del caso.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case_id))

    try:
        if action == "resolve":
            execute(
                "UPDATE dbo.cases SET status='RESUELTO', resolved_at=SYSDATETIME(), updated_at=SYSDATETIME() WHERE id = ?",
                (case_id,),
            )
            _record_case_update(case_id, note, is_solution=True)
            flash(f"El caso {case_id} quedó en estado RESUELTO.", "success")
        elif action == "close":
            execute(
                "UPDATE dbo.cases SET status='CERRADO', closed_at=SYSDATETIME(), updated_at=SYSDATETIME() WHERE id = ?",
                (case_id,),
            )
            _record_case_update(case_id, note)
            flash(f"El caso {case_id} quedó en estado CERRADO.", "success")
        else:
            response_min, resolution_min = get_priority_defaults(case_row.get("priority") or "MEDIA")
            response_due, resolution_due = compute_due_dates(datetime.now(), response_min, resolution_min)
            execute(
                "UPDATE dbo.cases SET status='REABIERTO', resolved_at=NULL, closed_at=NULL, response_due_at=?, resolution_due_at=?, updated_at=SYSDATETIME() WHERE id = ?",
                (response_due, resolution_due, case_id),
            )
            _record_case_update(case_id, note)
            flash(f"El caso {case_id} fue reabierto.", "success")
        commit()
    except Exception as exc:
        rollback()
        flash(f"No fue posible actualizar el caso: {exc}", "error")

    return redirect(url_for("cases.case_detail", case_id=case_id))


@cases_bp.route("/cases/<case_id>/triage", methods=["POST"])
@login_required
def triage_case(case_id):
    if not _can_triage():
        flash("No tienes permisos para categorizar casos.", "error")
        return redirect(url_for("cases.case_detail", case_id=case_id))

    case_row = _get_case(case_id)
    if not case_row:
        abort(404)

    assigned_team = normalize_role(request.form.get("assigned_team") or "")
    priority = normalize_priority(request.form.get("priority") or "")
    note = (request.form.get("note") or "").strip()

    allowed_targets = triage_targets_for_roles(_current_roles())
    if assigned_team not in allowed_targets:
        flash("Debes seleccionar un destino permitido para tu rol.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case_id))
    if priority not in PRIORITY_CHOICES:
        flash("Debes seleccionar una prioridad válida.", "warning")
        return redirect(url_for("cases.case_detail", case_id=case_id))

    try:
        response_min, resolution_min = get_priority_defaults(priority)
        response_due, resolution_due = compute_due_dates(datetime.now(), response_min, resolution_min)
        execute(
            """
            UPDATE dbo.cases
            SET assigned_team=?,
                assigned_to=?,
                priority=?,
                category=?,
                sla_response_min=?,
                sla_resolution_min=?,
                response_due_at=?,
                resolution_due_at=?,
                status=CASE WHEN LOWER(status)='resuelto' THEN status ELSE 'ASIGNADO' END,
                updated_at=SYSDATETIME()
            WHERE id=?
            """,
            (assigned_team, None, priority, assigned_team, int(response_min), int(resolution_min), response_due, resolution_due, case_id),
        )
        message = f"Caso asignado a la cola de {role_label(assigned_team)} con prioridad {priority}."
        if note:
            message += f" Nota: {note}"
        _record_case_update(case_id, message)
        commit()
        flash("Caso asignado correctamente.", "success")
    except Exception as exc:
        rollback()
        flash(f"No fue posible asignar el caso: {exc}", "error")

    return redirect(url_for("cases.case_detail", case_id=case_id))


@cases_bp.route("/actions/ingest-emails", methods=["POST"])
@login_required
def ingest_emails_action():
    if not _can_ingest():
        message = "Solo Administrador y Gestor TI pueden ejecutar la ingesta de correos."
        flash(message, "error")
        wants_json = (
            request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or "application/json" in (request.headers.get("Accept") or "")
        )
        if wants_json:
            return jsonify(ok=False, error=message), 403
        return redirect(request.referrer or url_for("cases.dashboard"))

    wants_json = (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in (request.headers.get("Accept") or "")
    )

    try:
        from services.email_ingest import ingest_unseen
        result = ingest_unseen()
        created = int((result or {}).get("created") or 0)
        if created > 0:
            flash(f"Ingesta completada. Se crearon {created} caso(s) desde Outlook.", "success")
        else:
            flash("Ingesta completada. No se encontraron correos nuevos para procesar.", "info")
        if wants_json:
            return jsonify(ok=True, result=result)
    except Exception as exc:
        rollback()
        message = f"La ingesta falló: {exc}"
        flash(message, "error")
        if wants_json:
            return jsonify(ok=False, error=str(exc)), 500

    return redirect(request.referrer or url_for("cases.dashboard"))


@cases_bp.route("/notifications")
@login_required
def notifications():
    try:
        limit = int(request.args.get("limit", 50))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))

    notifications_rows = select_all(
        """
        SELECT id, type, title, body, case_id, is_read, created_at
        FROM dbo.notifications
        WHERE user_id=?
        ORDER BY created_at DESC
        OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY
        """,
        (current_user.username, limit),
    )

    return render_template(
        "cases/notifications.html",
        title="Notificaciones",
        notifications=notifications_rows,
        notif_count=_notif_count(),
        limit=limit,
    )


@cases_bp.route("/notifications/mark-read", methods=["POST"])
@login_required
def notifications_mark_read():
    execute(
        "UPDATE dbo.notifications SET is_read=1, read_at=SYSDATETIME() WHERE user_id=? AND is_read=0",
        (current_user.username,),
    )
    commit()
    return jsonify(ok=True)


@cases_bp.route("/admin/users", methods=["GET", "POST"])
@login_required
def admin_users():
    if not _is_admin():
        flash("Solo el perfil administrador puede gestionar usuarios.", "error")
        return redirect(url_for("cases.dashboard"))

    preview_user = None
    username_value = ""
    selected_roles = []

    edit_username = (request.args.get("edit") or "").strip()
    if edit_username:
        username_value = edit_username
        ok, info = search_user(edit_username)
        if ok:
            preview_user = info
        else:
            preview_user = select_one(
                "SELECT id, display_name, email, job_title, department FROM dbo.users WHERE id = ?",
                (edit_username,),
            )
            if preview_user:
                preview_user = {
                    "username": preview_user.get("id") or edit_username,
                    "display_name": preview_user.get("display_name") or edit_username,
                    "email": preview_user.get("email") or "",
                    "job_title": preview_user.get("job_title") or "",
                    "department": preview_user.get("department") or "",
                }
        role_rows = select_all("SELECT role FROM dbo.user_roles WHERE user_id = ? ORDER BY role", (edit_username,))
        selected_roles = normalize_roles([row.get("role") for row in role_rows])

    if request.method == "POST":
        action = (request.form.get("action") or "save").strip().lower()
        username = (request.form.get("username") or request.form.get("user_id") or "").strip()
        username_value = username
        selected_roles = normalize_roles(request.form.getlist("roles"))

        if not username:
            flash("Debes indicar el usuario de red.", "error")
            return redirect(url_for("cases.admin_users"))

        ok, info = search_user(username)
        if not ok:
            flash("No fue posible consultar ese usuario en LDAP.", "error")
            return redirect(url_for("cases.admin_users"))

        preview_user = info

        if action == "lookup":
            pass
        else:
            try:
                primary_role = selected_roles[0] if selected_roles else "sin_rol"
                execute(
                    """
                    MERGE dbo.users AS target
                    USING (SELECT ? AS id, ? AS display_name, ? AS email, ? AS job_title, ? AS department) AS src
                    ON target.id = src.id
                    WHEN MATCHED THEN
                        UPDATE SET
                            display_name = src.display_name,
                            email = src.email,
                            job_title = src.job_title,
                            department = src.department,
                            role = ?,
                            updated_at = SYSDATETIME()
                    WHEN NOT MATCHED THEN
                        INSERT (id, display_name, email, job_title, department, role, is_active, created_at, updated_at)
                        VALUES (src.id, src.display_name, src.email, src.job_title, src.department, ?, 1, SYSDATETIME(), SYSDATETIME());
                    """,
                    (
                        info.get("username") or username,
                        info.get("display_name") or username,
                        info.get("email") or "",
                        info.get("job_title") or "",
                        info.get("department") or "",
                        primary_role,
                        primary_role,
                    ),
                )
                execute("DELETE FROM dbo.user_roles WHERE user_id = ?", (info.get("username") or username,))
                for role in selected_roles:
                    execute(
                        "INSERT INTO dbo.user_roles(user_id, role, created_at, updated_at) VALUES (?, ?, SYSDATETIME(), SYSDATETIME())",
                        (info.get("username") or username, role),
                    )
                commit()
                flash("Usuario sincronizado desde LDAP y roles guardados.", "success")
                return redirect(url_for("cases.admin_users", edit=info.get("username") or username))
            except Exception as exc:
                rollback()
                flash(f"No fue posible guardar el usuario: {exc}", "error")

    users = select_all(
        """
        SELECT id, display_name, email, job_title, department, role, is_active, updated_at
        FROM dbo.users
        ORDER BY display_name, id
        """
    )
    role_rows = select_all("SELECT user_id, role FROM dbo.user_roles ORDER BY user_id, role")
    roles_by_user = {}
    for row in role_rows:
        roles_by_user.setdefault(row["user_id"], []).append(row["role"])

    for user in users:
        user["roles"] = roles_by_user.get(user["id"], [])
        user["role_labels"] = [role_label(r) for r in user["roles"]]

    return render_template(
        "admin/users.html",
        title="Usuarios",
        users=users,
        role_choices=role_choices(include_admin=True),
        notif_count=_notif_count(),
        preview_user=preview_user,
        username_value=username_value,
        selected_roles=selected_roles,
    )


@cases_bp.route("/reports")
@login_required
def reports():
    visibility_sql, visibility_params = _visibility_condition("c")
    where_clause = f"WHERE {visibility_sql}" if visibility_sql else ""

    totals = select_one(
        f"""
        SELECT
            COUNT(*) AS total_cases,
            SUM(CASE WHEN LOWER(c.status) IN ('pendiente', 'asignado', 'reabierto') THEN 1 ELSE 0 END) AS open_cases,
            SUM(CASE WHEN LOWER(c.status) = 'resuelto' THEN 1 ELSE 0 END) AS resolved_cases,
            SUM(CASE WHEN LOWER(c.status) = 'reabierto' THEN 1 ELSE 0 END) AS reopened_cases,
            SUM(CASE WHEN LOWER(c.status) = 'cerrado' THEN 1 ELSE 0 END) AS closed_cases,
            SUM(CASE WHEN UPPER(c.priority) IN ('ALTA', 'P1') THEN 1 ELSE 0 END) AS high_priority
        FROM dbo.cases c
        {where_clause}
        """,
        tuple(visibility_params),
    ) or {}

    by_team = select_all(
        f"""
        SELECT c.assigned_team, COUNT(*) AS total_cases,
               SUM(CASE WHEN LOWER(c.status) IN ('pendiente', 'asignado', 'reabierto') THEN 1 ELSE 0 END) AS open_cases,
               SUM(CASE WHEN LOWER(c.status) = 'resuelto' THEN 1 ELSE 0 END) AS resolved_cases,
               SUM(CASE WHEN LOWER(c.status) = 'cerrado' THEN 1 ELSE 0 END) AS closed_cases
        FROM dbo.cases c
        {where_clause}
        GROUP BY c.assigned_team
        ORDER BY total_cases DESC, c.assigned_team
        """,
        tuple(visibility_params),
    )

    by_priority = select_all(
        f"""
        SELECT c.priority, COUNT(*) AS total_cases
        FROM dbo.cases c
        {where_clause}
        GROUP BY c.priority
        ORDER BY CASE UPPER(c.priority)
            WHEN 'ALTA' THEN 1
            WHEN 'MEDIA' THEN 2
            WHEN 'BAJA' THEN 3
            WHEN 'P1' THEN 1
            WHEN 'P2' THEN 2
            WHEN 'P3' THEN 2
            WHEN 'P4' THEN 3
            ELSE 99 END, c.priority
        """,
        tuple(visibility_params),
    )

    by_status = select_all(
        f"""
        SELECT c.status, COUNT(*) AS total_cases
        FROM dbo.cases c
        {where_clause}
        GROUP BY c.status
        ORDER BY CASE LOWER(c.status)
            WHEN 'pendiente' THEN 1
            WHEN 'asignado' THEN 2
            WHEN 'resuelto' THEN 3
            WHEN 'reabierto' THEN 4
            WHEN 'cerrado' THEN 5
            ELSE 99 END, c.status
        """,
        tuple(visibility_params),
    )

    top_owners = select_all(
        f"""
        SELECT TOP 10 ISNULL(u.display_name, c.assigned_to) AS owner_name, COUNT(*) AS total_cases
        FROM dbo.cases c
        LEFT JOIN dbo.users u ON u.id = c.assigned_to
        {where_clause}
        GROUP BY ISNULL(u.display_name, c.assigned_to)
        ORDER BY total_cases DESC, owner_name
        """,
        tuple(visibility_params),
    )

    closed_case_id = (request.args.get("closed_case_id") or "").strip()
    closed_cases = []
    if closed_case_id:
        closed_where = []
        closed_params = []
        if visibility_sql:
            closed_where.append(visibility_sql)
            closed_params.extend(visibility_params)
        closed_where.append("LOWER(c.status) = 'cerrado'")
        closed_where.append("c.id LIKE ?")
        closed_params.append(f"%{closed_case_id}%")
        closed_cases = select_all(
            f"""
            SELECT c.id, c.status, c.priority, c.assigned_team,
                   ISNULL(u.display_name, c.assigned_to) AS assigned_to_name,
                   c.requester_name, c.requester_email, c.subject, c.created_at, c.closed_at
            FROM dbo.cases c
            LEFT JOIN dbo.users u ON u.id = c.assigned_to
            WHERE {' AND '.join(closed_where)}
            ORDER BY c.closed_at DESC, c.created_at DESC
            """,
            tuple(closed_params),
        )

    return render_template(
        "reports/index.html",
        title="Reportes",
        totals=totals,
        by_team=by_team,
        by_status=by_status,
        top_owners=top_owners,
        by_priority=by_priority,
        closed_case_id=closed_case_id,
        closed_cases=closed_cases,
        notif_count=_notif_count(),
        scope_labels=_role_scope_labels(),
    )


@cases_bp.route("/reports/export")
@login_required
def reports_export():
    kind = (request.args.get("kind") or "cases").strip().lower()
    closed_case_id = (request.args.get("closed_case_id") or "").strip()
    visibility_sql, visibility_params = _visibility_condition("c")
    where_clause = f"WHERE {visibility_sql}" if visibility_sql else ""

    output = io.StringIO()
    writer = csv.writer(output)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if kind == "summary":
        writer.writerow(["seccion", "dimension", "valor_1", "valor_2", "valor_3"])

        totals = select_one(
            f"""
            SELECT
                COUNT(*) AS total_cases,
                SUM(CASE WHEN LOWER(c.status) IN ('pendiente', 'asignado', 'reabierto') THEN 1 ELSE 0 END) AS open_cases,
                SUM(CASE WHEN LOWER(c.status) = 'resuelto' THEN 1 ELSE 0 END) AS resolved_cases,
                SUM(CASE WHEN LOWER(c.status) = 'reabierto' THEN 1 ELSE 0 END) AS reopened_cases,
                SUM(CASE WHEN LOWER(c.status) = 'cerrado' THEN 1 ELSE 0 END) AS closed_cases,
                SUM(CASE WHEN UPPER(c.priority) IN ('ALTA', 'P1') THEN 1 ELSE 0 END) AS high_priority
            FROM dbo.cases c
            {where_clause}
            """,
            tuple(visibility_params),
        ) or {}
        writer.writerow(["totales", "casos", totals.get("total_cases", 0) or 0, totals.get("open_cases", 0) or 0, totals.get("resolved_cases", 0) or 0])
        writer.writerow(["totales", "reabiertos_cerrados_y_prioridad_alta", totals.get("reopened_cases", 0) or 0, totals.get("closed_cases", 0) or 0, totals.get("high_priority", 0) or 0])

        by_team = select_all(
            f"""
            SELECT c.assigned_team, COUNT(*) AS total_cases,
                   SUM(CASE WHEN LOWER(c.status) IN ('pendiente', 'asignado', 'reabierto') THEN 1 ELSE 0 END) AS open_cases,
                   SUM(CASE WHEN LOWER(c.status) = 'resuelto' THEN 1 ELSE 0 END) AS resolved_cases,
                   SUM(CASE WHEN LOWER(c.status) = 'cerrado' THEN 1 ELSE 0 END) AS closed_cases
            FROM dbo.cases c
            {where_clause}
            GROUP BY c.assigned_team
            ORDER BY total_cases DESC, c.assigned_team
            """,
            tuple(visibility_params),
        )
        for row in by_team:
            writer.writerow(["equipo", row.get("assigned_team") or "-", row.get("total_cases") or 0, row.get("open_cases") or 0, row.get("resolved_cases") or 0])
            writer.writerow(["equipo_cerrado", row.get("assigned_team") or "-", row.get("closed_cases") or 0, "", ""])

        by_status = select_all(
            f"""
            SELECT c.status, COUNT(*) AS total_cases
            FROM dbo.cases c
            {where_clause}
            GROUP BY c.status
            ORDER BY total_cases DESC, c.status
            """,
            tuple(visibility_params),
        )
        for row in by_status:
            writer.writerow(["estado", row.get("status") or "-", row.get("total_cases") or 0, "", ""])

        by_priority = select_all(
            f"""
            SELECT c.priority, COUNT(*) AS total_cases
            FROM dbo.cases c
            {where_clause}
            GROUP BY c.priority
            ORDER BY total_cases DESC, c.priority
            """,
            tuple(visibility_params),
        )
        for row in by_priority:
            writer.writerow(["prioridad", normalize_priority(row.get("priority") or "MEDIA"), row.get("total_cases") or 0, "", ""])

        filename = f"reporte_resumen_{stamp}.csv"
    elif kind == "closed":
        writer.writerow(["id", "estado", "prioridad", "equipo", "asignado_a", "solicitante", "correo", "cerrado", "asunto"])
        closed_where = []
        closed_params = []
        if visibility_sql:
            closed_where.append(visibility_sql)
            closed_params.extend(visibility_params)
        closed_where.append("LOWER(c.status) = 'cerrado'")
        if closed_case_id:
            closed_where.append("c.id LIKE ?")
            closed_params.append(f"%{closed_case_id}%")
        rows = select_all(
            f"""
            SELECT c.id, c.status, c.priority, c.assigned_team,
                   ISNULL(u.display_name, c.assigned_to) AS assigned_to_name,
                   c.requester_name, c.requester_email, c.closed_at, c.subject
            FROM dbo.cases c
            LEFT JOIN dbo.users u ON u.id = c.assigned_to
            WHERE {' AND '.join(closed_where)}
            ORDER BY c.closed_at DESC, c.created_at DESC
            """,
            tuple(closed_params),
        )
        for row in rows:
            writer.writerow([
                row.get("id") or "",
                row.get("status") or "",
                row.get("priority") or "",
                role_label(row.get("assigned_team") or "") if row.get("assigned_team") else "",
                row.get("assigned_to_name") or "",
                row.get("requester_name") or "",
                row.get("requester_email") or "",
                row.get("closed_at") or "",
                row.get("subject") or "",
            ])
        filename = f"reporte_cerrados_{stamp}.csv"
    else:
        writer.writerow(["id", "estado", "prioridad", "ans_respuesta", "ans_resolucion", "vence_respuesta", "vence_resolucion", "equipo", "asignado_a", "solicitante", "correo", "creado", "actualizado", "asunto"])
        rows = select_all(
            f"""
            SELECT c.id, c.status, c.priority, c.assigned_team,
                   ISNULL(u.display_name, c.assigned_to) AS assigned_to_name,
                   c.requester_name, c.requester_email, c.created_at, c.updated_at, c.subject,
                   c.sla_response_min, c.sla_resolution_min, c.response_due_at, c.resolution_due_at
            FROM dbo.cases c
            LEFT JOIN dbo.users u ON u.id = c.assigned_to
            {where_clause}
            ORDER BY c.created_at DESC
            """,
            tuple(visibility_params),
        )
        for row in rows:
            row = _decorate_case(row)
            writer.writerow([
                row.get("id") or "",
                row.get("status") or "",
                row.get("priority") or "",
                row.get("sla_response_text") or "",
                row.get("sla_resolution_text") or "",
                row.get("response_due_at_display") or "",
                row.get("resolution_due_at_display") or "",
                row.get("assigned_team") or "",
                row.get("assigned_to_name") or "",
                row.get("requester_name") or "",
                row.get("requester_email") or "",
                row.get("created_at") or "",
                row.get("updated_at") or "",
                row.get("subject") or "",
            ])
        filename = f"reporte_casos_{stamp}.csv"

    content = "﻿" + output.getvalue()
    return Response(
        content,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
