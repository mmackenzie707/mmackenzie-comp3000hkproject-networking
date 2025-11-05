import os
from __future__ import annotations
import logging
from flask import Flask, request, jsonify, redirect, url_for
from flask_login import LoginManager, current_user
from .firewall import Firewall
from .model import AnomalyModel
from .config import THRESHOLD, CUT_OFF
from ui.login import bp as auth_bp, login_manager, init_db


#Flask REST Endpoint

log = logging.getLogger(__name__)


def build_app(firewall: Firewall, model: AnomalyModel) -> Flask:
    app = Flask("smartfw")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or "change-me"

    #Login code
    login_manager.init_app(app)
    init_db()
    app.register_blueprint(auth_bp)

    #Protection script that needs to be applied to every confidential page
    @app.before_request
    def require_login():
        if request.endpoint in {"auth.login", "static"}:
            return
        if not current_user.is_authenticated"
            return redirect(url_for("auth.login", next=request.path))

    @app.route("/")
    def index():
        return jsonify({"threshold": THRESHOLD,"cut_off": CUT_OFF, "blocked": list(firewall._blocked.keys())})
    
    @app.post("/whitelist")
    def whitelist():
        ip = request.get_json(silent=True).get("ip")
        if not ip:
            return jsonify(error="ip required"), 400
        from .config import WHITELIST
        WHITELIST.add(ip)
        return jsonify(whitelist=ip)
    
    @app.post("/threshold")
    def threshold():
        global THRESHOLD
        val = request.get_json(silent=True).get("value")
        if val is None:
            return jsonify(error="value required"), 400
        THRESHOLD = float(val)
        return jsonify(threshold=THRESHOLD)
    
    @app.post("/cut-off")
    def set_cut_off():
        global CUT_OFF
        CUT_OFF = float(request.json["value"])
        return jsonify(cut_off=CUT_OFF)
     
    return app