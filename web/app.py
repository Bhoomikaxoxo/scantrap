"""
web/app.py
----------
Flask + Flask-SocketIO dashboard.
Emits real-time stats and alerts over WebSocket via the 'update' event.
"""

import logging
import threading
import time

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

import config
from core.analyzer import get_stats
from database.logger import get_recent_alerts, get_alert_counts

log = logging.getLogger("scantrap.web")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "scantrap-secret-key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ─────────────────────────────────────────────────────────────────────────────
# Background push loop (pushes stats every second via SocketIO)
# ─────────────────────────────────────────────────────────────────────────────

def _push_loop():
    """Continuously push live stats to all connected clients."""
    while True:
        time.sleep(1)
        payload = {
            "stats": get_stats(),
            "counts": get_alert_counts(),
        }
        socketio.emit("update", payload)


def start_push_loop():
    t = threading.Thread(target=_push_loop, daemon=True, name="scantrap-push")
    t.start()


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    alerts = get_recent_alerts(limit=200)
    return jsonify(alerts)


@app.route("/api/stats")
def api_stats():
    return jsonify({"stats": get_stats(), "counts": get_alert_counts()})


# ─────────────────────────────────────────────────────────────────────────────
# SocketIO events
# ─────────────────────────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    log.debug("Client connected")
    # Send immediate snapshot on connect
    socketio.emit("update", {
        "stats": get_stats(),
        "counts": get_alert_counts(),
    })


def run_server():
    start_push_loop()
    socketio.run(
        app,
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
