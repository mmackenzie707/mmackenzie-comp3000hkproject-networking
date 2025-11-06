import os
from flask import Flask, redirect, url_for, request, send_from_directory
from flask_login import LoginManager, current_user
from smartfw import build_app as build_core_app
from login import bp as auth_bp, login_manager, init_db


def build_app(firewall, model):
    #bare sensor
    app = build_core_app(firewall, model)

    #login
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or "change-me"
    login_manager.init_app(app)
    init_db()
    app.register_blueprint(auth_bp)

    #page level protection
    @app.before_request
    def require_login():
        if request.endpoint in {"auth.login", "static"}:
            return
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login", next=request.path))
        
    #serve the HUD page
    @app.route("/hud")
    @require_login
    def hud():
        return send_from_directory("dist", "index.html")

    #redirect to hud after login
    @app.route("/")
    @require_login
    def root():
        return redirect(url_for("hud"))
    
    return app