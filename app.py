import os
import threading
import time

from dotenv import load_dotenv
from flask import Flask, redirect, url_for
from flask_login import LoginManager, current_user

load_dotenv()


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY", os.urandom(32))

    from services.db import close_db, select_all, select_one
    app.teardown_appcontext(close_db)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    from models.user import User

    @login_manager.user_loader
    def load_user(user_id: str):
        if not user_id:
            return None
        row = select_one(
            "SELECT id, display_name, email, role, is_active, job_title, department FROM dbo.users WHERE id = ?",
            (user_id,),
        )
        if not row or not bool(row.get('is_active', 1)):
            return None
        role_rows = select_all(
            "SELECT role FROM dbo.user_roles WHERE user_id = ? ORDER BY role",
            (user_id,),
        )
        roles = [r.get("role") for r in role_rows if r.get("role")]
        return User(
            row["id"],
            (row.get("display_name") or row["id"]),
            (row.get("email") or ""),
            (row.get("role") or ""),
            roles=roles,
            job_title=(row.get("job_title") or ""),
            department=(row.get("department") or ""),
            active=bool(row.get("is_active", 1)),
        )

    @app.context_processor
    def inject_header_notifications():
        if not current_user.is_authenticated:
            return {"notif_count": 0, "header_notifications": []}
        notifications = select_all(
            """
            SELECT TOP 6 id, type, title, body, case_id, is_read, created_at
            FROM dbo.notifications
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (current_user.username,),
        )
        unread_row = select_one(
            "SELECT COUNT(*) AS unread_count FROM dbo.notifications WHERE user_id = ? AND is_read = 0",
            (current_user.username,),
        ) or {}
        return {
            "notif_count": int(unread_row.get("unread_count") or 0),
            "header_notifications": notifications,
        }

    from blueprints.auth import auth_bp
    from blueprints.cases import cases_bp
    from blueprints.users import users_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(users_bp)

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("cases.dashboard"))
        return redirect(url_for("auth.login"))

    with app.app_context():
        from services.bootstrap import ensure_schema

        ensure_schema()

    def _bg_ingest_loop():
        from services.email_ingest import ingest_unseen

        interval = int(os.getenv("EMAIL_INGEST_INTERVAL_SECONDS", "60"))
        while True:
            try:
                with app.app_context():
                    ingest_unseen()
            except Exception:
                pass
            time.sleep(max(10, interval))

    if str(os.getenv("EMAIL_INGEST_BACKGROUND", "false")).lower() in ("1", "true", "yes", "y", "on"):
        t = threading.Thread(target=_bg_ingest_loop, daemon=True)
        t.start()

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("PORT", "5020"))
    debug = os.getenv("DEBUG", "true").lower() in ("1", "true", "yes", "y")
    app.run(host="0.0.0.0", port=port, debug=debug)
