from flask import Blueprint, render_template, session
from app.services.authz import login_required

home_bp = Blueprint("home", __name__, url_prefix="")

@home_bp.get("/")
@login_required
def dashboard():
    return render_template("home/dashboard.html", user=session.get("user"))
