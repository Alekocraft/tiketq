from sqlalchemy import text
from sqlalchemy.engine import Engine

def get_or_create_usuario(engine: Engine, usuario_ldap: str, correo: str | None):
    sql_find = text("SELECT id_usuario, usuario_ldap, correo, activo FROM rrhh.usuarios WHERE usuario_ldap=:u")
    sql_ins = text("INSERT INTO rrhh.usuarios(usuario_ldap, correo, activo) VALUES(:u, :c, 1)")
    with engine.begin() as conn:
        row = conn.execute(sql_find, {"u": usuario_ldap}).mappings().first()
        if row:
            # actualizar correo si llega nuevo
            if correo and (row.get("correo") is None or row.get("correo") == ""):
                conn.execute(text("UPDATE rrhh.usuarios SET correo=:c WHERE id_usuario=:id"), {"c": correo, "id": row["id_usuario"]})
                row = conn.execute(sql_find, {"u": usuario_ldap}).mappings().first()
            return row
        conn.execute(sql_ins, {"u": usuario_ldap, "c": correo})
        return conn.execute(sql_find, {"u": usuario_ldap}).mappings().first()

def get_roles_usuario(engine: Engine, id_usuario: int) -> list[str]:
    sql = text("""
        SELECT r.nombre
        FROM rrhh.usuario_roles ur
        JOIN rrhh.roles r ON r.id_rol = ur.id_rol
        WHERE ur.id_usuario = :id
    """)
    with engine.connect() as conn:
        return [r[0] for r in conn.execute(sql, {"id": id_usuario}).all()]
