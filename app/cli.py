import hashlib
from datetime import datetime
import pandas as pd
from sqlalchemy import text

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def register_cli(app):
    @app.cli.command("import-jefes-directos")
    def import_jefes_directos():
        """Importa áreas, cargos y empleados desde un Excel tipo 'JEFES DIRECTOS.xlsx'."""
        cfg = app.config["APP_CONFIG"]
        engine = app.config["ENGINE"]
        path = cfg.IMPORT_JEFES_PATH or "JEFES DIRECTOS.xlsx"
        df = pd.read_excel(path)

        required = {"C.C", "NOMBRES", "APELLIDOS", "AREA", "CARGO"}
        missing = required - set(df.columns)
        if missing:
            raise SystemExit(f"Faltan columnas en {path}: {missing}")

        # Normalizar
        df["C.C"] = df["C.C"].astype(str).str.strip()
        df["AREA"] = df["AREA"].astype(str).str.strip()
        df["CARGO"] = df["CARGO"].astype(str).str.strip()
        df["NOMBRES"] = df["NOMBRES"].astype(str).str.strip()
        df["APELLIDOS"] = df["APELLIDOS"].astype(str).str.strip()
        df["correo"] = None

        file_hash = _sha256_file(path)

        with engine.begin() as conn:
            # Registrar import
            conn.execute(text("""
                IF NOT EXISTS (SELECT 1 FROM rrhh.importaciones WHERE modulo='MAESTRO' AND hash_sha256=:h)
                INSERT INTO rrhh.importaciones(modulo, nombre_archivo, hash_sha256, importado_en)
                VALUES('TURNOS', :n, :h, SYSDATETIME())
            """), {"n": path, "h": file_hash})

            # Áreas
            areas = sorted(set(df["AREA"].dropna().tolist()))
            for a in areas:
                conn.execute(text("""
                    IF NOT EXISTS (SELECT 1 FROM rrhh.areas WHERE nombre=:n)
                    INSERT INTO rrhh.areas(nombre, activo) VALUES(:n, 1)
                """), {"n": a})

            # Cargos
            cargos = sorted(set(df["CARGO"].dropna().tolist()))
            for c in cargos:
                conn.execute(text("""
                    IF NOT EXISTS (SELECT 1 FROM rrhh.cargos WHERE nombre=:n)
                    INSERT INTO rrhh.cargos(nombre, activo) VALUES(:n, 1)
                """), {"n": c})

            # Empleados (por C.C)
            for _, r in df.iterrows():
                area_id = conn.execute(text("SELECT id_area FROM rrhh.areas WHERE nombre=:n"), {"n": r["AREA"]}).scalar()
                cargo_id = conn.execute(text("SELECT id_cargo FROM rrhh.cargos WHERE nombre=:n"), {"n": r["CARGO"]}).scalar()

                conn.execute(text("""
                    IF NOT EXISTS (SELECT 1 FROM rrhh.empleados WHERE identificacion=:cc)
                    INSERT INTO rrhh.empleados(identificacion, nombres, apellidos, correo, id_area, id_cargo, activo, grupo)
                    VALUES(:cc, :n, :a, :correo, :id_area, :id_cargo, 1, 'ADMIN')
                """), {
                    "cc": r["C.C"],
                    "n": r["NOMBRES"],
                    "a": r["APELLIDOS"],
                    "correo": None,
                    "id_area": area_id,
                    "id_cargo": cargo_id
                })

        print("✅ Import empleados/áreas/cargos terminado.")

    @app.cli.command("import-turnos-cabina")
    def import_turnos_cabina():
        """Importa la tabla de definición de turnos (hora inicio/fin/código) desde el excel de cabina/ajustadores."""
        cfg = app.config["APP_CONFIG"]
        engine = app.config["ENGINE"]
        path = cfg.IMPORT_CABINA_PATH or "turnos (cabina y ajustadores).xlsx"

        raw = pd.read_excel(path, sheet_name=0, header=None)

        # Buscar fila donde col0 == 'Hora inicio'
        idx = None
        for i in range(min(200, len(raw))):
            if str(raw.iloc[i,0]).strip().lower() == "hora inicio":
                idx = i
                break
        if idx is None:
            raise SystemExit("No encontré la sección 'Hora inicio' en el archivo.")

        # Datos desde idx+2 hasta que aparezca una fila vacía en las 3 primeras columnas
        rows = []
        for i in range(idx+2, min(idx+80, len(raw))):
            h_ini = raw.iloc[i,0]
            h_fin = raw.iloc[i,1]
            codigo = raw.iloc[i,2]
            nombre = raw.iloc[i,3]
            if (pd.isna(h_ini) and pd.isna(h_fin) and pd.isna(codigo)):
                break
            if pd.isna(codigo) or pd.isna(h_ini) or pd.isna(h_fin):
                continue
            rows.append((str(codigo).strip(), str(nombre).strip() if not pd.isna(nombre) else f"Turno {codigo}", h_ini, h_fin))

        if not rows:
            raise SystemExit("No encontré filas de turnos (código, hora inicio, hora fin).")

        # Insert/Upsert
        with engine.begin() as conn:
            for codigo, nombre, h_ini, h_fin in rows:
                # duracion aproximada
                try:
                    dur = (pd.to_datetime(h_fin) - pd.to_datetime(h_ini)).total_seconds()/3600.0
                    if dur <= 0:
                        dur += 24
                except Exception:
                    dur = 0

                conn.execute(text("""
                    IF NOT EXISTS (SELECT 1 FROM rrhh.turnos WHERE codigo=:cod)
                    INSERT INTO rrhh.turnos(codigo, nombre, grupo, hora_inicio, hora_fin, duracion_horas, activo)
                    VALUES(:cod, :nom, 'CABINA', :hi, :hf, :dur, 1)
                """), {"cod": f"CAB_{codigo}", "nom": f"CABINA - {nombre}", "hi": h_ini, "hf": h_fin, "dur": dur})

        print(f"✅ Turnos cabina importados: {len(rows)}")
