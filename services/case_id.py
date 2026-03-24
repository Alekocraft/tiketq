import re
from datetime import datetime
from services.db import get_db, select_one, execute, commit

_CASE_ID_RE = re.compile(r"^Q-(\d{4})-(\d{5})$")


def _is_expected_case_id(value: str, year: int) -> bool:
    match = _CASE_ID_RE.match((value or "").strip())
    return bool(match and int(match.group(1)) == year)


def next_case_id(now=None) -> str:
    """
    Genera IDs con formato fijo: Q-YYYY-00001.

    Si existe una SP previa pero devuelve otro formato, se ignora y se usa
    el consecutivo controlado en dbo.case_sequences para mantener el estándar.
    """
    now = now or datetime.now()
    year = int(now.strftime("%Y"))
    padding = 5

    db = get_db()

    try:
        cur = db.cursor()
        out = cur.execute(
            "DECLARE @id NVARCHAR(30); "
            "EXEC dbo.sp_next_case_id @CaseId=@id OUTPUT; "
            "SELECT @id AS case_id;"
        )
        row = out.fetchone()
        if row and row[0]:
            candidate = str(row[0]).strip()
            if _is_expected_case_id(candidate, year):
                db.commit()
                return candidate
            db.rollback()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    execute(
        "IF NOT EXISTS (SELECT 1 FROM sys.objects "
        "WHERE object_id = OBJECT_ID(N'dbo.case_sequences') AND type in (N'U')) "
        "BEGIN "
        "CREATE TABLE dbo.case_sequences(" 
        "[year] INT NOT NULL PRIMARY KEY, "
        "last_seq INT NOT NULL DEFAULT(0), "
        "updated_at DATETIME2 NOT NULL DEFAULT(SYSDATETIME())" 
        "); "
        "END"
    )

    row = select_one(
        "SELECT last_seq FROM dbo.case_sequences WITH (UPDLOCK, HOLDLOCK) WHERE [year]=?",
        (year,),
    )
    if row:
        seq = int(row["last_seq"]) + 1
        execute(
            "UPDATE dbo.case_sequences SET last_seq=?, updated_at=SYSDATETIME() WHERE [year]=?",
            (seq, year),
        )
    else:
        seq = 1
        execute(
            "INSERT INTO dbo.case_sequences([year], last_seq) VALUES (?, ?)",
            (year, seq),
        )

    case_id = f"Q-{year}-{seq:0{padding}d}"
    commit()
    return case_id
