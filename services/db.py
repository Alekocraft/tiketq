import os
from flask import g
from dotenv import load_dotenv

load_dotenv()

# SQL Server only (pyodbc)
def get_db():
    """
    Devuelve una conexión pyodbc a SQL Server usando MSSQL_CONN_STR.
    """
    if "db" in g:
        return g.db

    conn_str = os.getenv("MSSQL_CONN_STR", "").strip()
    if not conn_str:
        raise RuntimeError("MSSQL_CONN_STR no está configurado en .env")

    import pyodbc
    conn = pyodbc.connect(conn_str)
    # usamos transacciones explícitas (commit/rollback)
    conn.autocommit = False
    g.db = conn
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass

def _dicts_from_cursor(cur):
    cols = [c[0] for c in cur.description] if cur.description else []
    return [dict(zip(cols, row)) for row in cur.fetchall()] if cols else []

def select_one(sql: str, params=()):
    db = get_db()
    cur = db.cursor()
    cur.execute(sql, params)
    row = cur.fetchone()
    if not row:
        return None
    cols = [c[0] for c in cur.description]
    return dict(zip(cols, row))

def select_all(sql: str, params=()):
    db = get_db()
    cur = db.cursor()
    cur.execute(sql, params)
    return _dicts_from_cursor(cur)

def execute(sql: str, params=()):
    """
    Ejecuta INSERT/UPDATE/DELETE. Retorna cursor para leer outputs si aplica.
    """
    db = get_db()
    cur = db.cursor()
    cur.execute(sql, params)
    return cur

def commit():
    db = get_db()
    db.commit()

def rollback():
    db = get_db()
    db.rollback()
