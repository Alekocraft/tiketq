from pathlib import Path
import os, sqlite3
from dotenv import load_dotenv

load_dotenv()

def main():
    db_path = os.getenv("DB_PATH","db/tikets.sqlite3")
    Path(os.path.dirname(db_path)).mkdir(parents=True, exist_ok=True)
    schema_path = Path(__file__).resolve().parents[1] / "db" / "schema.sql"
    conn = sqlite3.connect(db_path)
    conn.executescript(schema_path.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()
    print(f"DB listo: {db_path}")

if __name__ == "__main__":
    main()
