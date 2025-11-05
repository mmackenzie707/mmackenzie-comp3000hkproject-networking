from __future__ import annotations
import logging
from flask import Flask, request, jsonify
from .firewall import Firewall
from .model import AnomalyModel
from .config import THRESHOLD


#Flask REST Endpoint

log = logging.getLogger(__name__)


def build_app(firewall: Firewall, model: AnomalyModel) -> Flask:
    app = Flask("smartfw")

    @app.route("/")
    def index():
        return jsonify({"threshold": THRESHOLD, "blocked": list(firewall._blocked.keys())})
    
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
        val = request.get_json(silent=True).get("Value")
        if val is None:
            return jsonify(error="value required"), 400
        THRESHOLD = float(val)
        return jsonify(threshold=THRESHOLD)
    
    return app