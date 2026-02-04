from flask import Flask
from app.config import Config
from app.db import get_engine
from app.cli import register_cli

def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    cfg = Config()
    app.secret_key = cfg.SECRET_KEY

    # Guardar config "real" (objeto) para usarlo en servicios
    app.config["APP_CONFIG"] = cfg
    app.config["ENGINE"] = get_engine(cfg)

    # Blueprints
    from app.controllers.auth_controller import auth_bp
    from app.controllers.home_controller import home_bp
    from app.controllers.health_controller import health_bp
    from app.controllers.admin_controller import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(home_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(admin_bp)

    # CLI
    register_cli(app)

    return app
