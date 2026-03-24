from dotenv import load_dotenv

load_dotenv()

from app import create_app
from services.email_ingest import ingest_unseen


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        result = ingest_unseen()
        print(result)
