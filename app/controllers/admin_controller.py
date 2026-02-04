from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from sqlalchemy import text
from app.services.authz import login_required, require_roles
from app.db import get_engine

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.get("/empleados")
@login_required
@require_roles("ADMIN","RRHH")
def empleados():
    q = (request.args.get("q") or "").strip()
    cfg = current_app.config["APP_CONFIG"]
    engine = get_engine(cfg)

    sql = text("""
        SELECT TOP 200 e.id_empleado, e.identificacion, e.nombres, e.apellidos, e.correo,
               e.activo, e.grupo, a.nombre AS area, c.nombre AS cargo
        FROM rrhh.empleados e
        LEFT JOIN rrhh.areas a ON a.id_area = e.id_area
        LEFT JOIN rrhh.cargos c ON c.id_cargo = e.id_cargo
        WHERE (:q='' OR e.identificacion LIKE :q2 OR (e.nombres + ' ' + e.apellidos) LIKE :q2)
        ORDER BY e.apellidos, e.nombres
    """)
    with engine.connect() as conn:
        rows = conn.execute(sql, {"q": q, "q2": f"%{q}%"}).mappings().all()

    return render_template("admin/empleados.html", rows=rows, q=q)

@admin_bp.get("/empleados/nuevo")
@login_required
@require_roles("ADMIN","RRHH")
def empleados_nuevo():
    cfg = current_app.config["APP_CONFIG"]
    engine = get_engine(cfg)
    with engine.connect() as conn:
        areas = conn.execute(text("SELECT id_area, nombre FROM rrhh.areas WHERE activo=1 ORDER BY nombre")).mappings().all()
        cargos = conn.execute(text("SELECT id_cargo, nombre FROM rrhh.cargos WHERE activo=1 ORDER BY nombre")).mappings().all()
    return render_template("admin/empleado_form.html", mode="new", areas=areas, cargos=cargos, emp=None)

@admin_bp.post("/empleados/nuevo")
@login_required
@require_roles("ADMIN","RRHH")
def empleados_nuevo_post():
    cfg = current_app.config["APP_CONFIG"]
    engine = get_engine(cfg)

    data = {
        "identificacion": (request.form.get("identificacion") or "").strip(),
        "nombres": (request.form.get("nombres") or "").strip(),
        "apellidos": (request.form.get("apellidos") or "").strip(),
        "correo": (request.form.get("correo") or "").strip() or None,
        "id_area": request.form.get("id_area") or None,
        "id_cargo": request.form.get("id_cargo") or None,
        "grupo": request.form.get("grupo") or "ADMIN",
        "activo": 1 if request.form.get("activo") == "1" else 0,
        "habilitado_ttc_jefe": 1 if request.form.get("habilitado_ttc_jefe") == "1" else 0,
        "habilitado_ttc_rrhh": 1 if request.form.get("habilitado_ttc_rrhh") == "1" else 0,
    }
    if not data["identificacion"] or not data["nombres"] or not data["apellidos"]:
        flash("Identificación, nombres y apellidos son obligatorios.", "warning")
        return redirect(url_for("admin.empleados_nuevo"))

    sql = text("""
        INSERT INTO rrhh.empleados
        (identificacion, nombres, apellidos, correo, id_area, id_cargo, activo, grupo, habilitado_ttc_jefe, habilitado_ttc_rrhh)
        VALUES
        (:identificacion, :nombres, :apellidos, :correo, :id_area, :id_cargo, :activo, :grupo, :habilitado_ttc_jefe, :habilitado_ttc_rrhh)
    """)
    try:
        with engine.begin() as conn:
            conn.execute(sql, data)
        flash("Empleado creado.", "success")
        return redirect(url_for("admin.empleados"))
    except Exception as ex:
        flash(f"Error creando empleado: {ex}", "danger")
        return redirect(url_for("admin.empleados_nuevo"))
