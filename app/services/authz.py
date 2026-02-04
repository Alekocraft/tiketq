from functools import wraps
from flask import session, redirect, url_for, flash, request

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def require_roles(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = session.get("user")
            if not user:
                return redirect(url_for("auth.login", next=request.path))
            user_roles = set(user.get("roles", []))
            if not user_roles.intersection(set(roles)):
                flash("No tienes permisos para acceder a esta opción.", "danger")
                return redirect(url_for("home.dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator
