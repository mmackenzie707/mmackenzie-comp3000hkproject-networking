from __future__ import annotations
import os
import logging
from flask import Flask, request, jsonify, redirect, url_for
from .firewall import Firewall
from .model import AnomalyModel
from .config import THRESHOLD, CUT_OFF


#Flask REST Endpoint

log = logging.getLogger(__name__)


def build_app(firewall: Firewall, model: AnomalyModel) -> Flask:
    app = Flask("smartfw")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or "change-me"

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