# =============================================================================
# api/routes.py — Flask REST API
# =============================================================================
# Exposes all monitoring data via clean JSON endpoints.
# Also serves the web dashboard via Flask-Login authenticated sessions.
#
# Endpoints:
#   GET  /                         → Dashboard (login required)
#   GET  /login  POST /login       → Auth
#   GET  /logout                   → Logout
#   GET  /api/stats/realtime       → Latest computed metrics
#   GET  /api/stats/history        → Historical traffic (query params: minutes, limit)
#   GET  /api/alerts               → Alert list (query params: severity, minutes, limit)
#   GET  /api/top-talkers          → Top IP addresses by traffic
#   GET  /api/protocols            → Protocol distribution
#   GET  /api/connections          → Active connections
#   GET  /api/export/csv           → Download packet history as CSV
#   GET  /api/export/json          → Download stats as JSON
#   GET  /api/status               → System health / uptime info

import io
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Blueprint, Flask, Response, jsonify, redirect,
    render_template, request, session, url_for,
)
from flask_cors import CORS
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user,
)

import config
from utils.exporter import records_to_csv_string, export_json
from utils.logger import get_logger

logger = get_logger(__name__)

# ─── Flask App Factory ────────────────────────────────────────────────────────

def create_app(analyzer=None, db=None, alerter=None) -> Flask:
    """
    Flask application factory.

    Args:
        analyzer: TrafficAnalyzer instance (provides real-time stats).
        db:       DatabaseHandler instance (provides historical queries).
        alerter:  AnomalyDetector instance (provides recent alerts).
    """
    app = Flask(
        __name__,
        template_folder="../frontend/templates",
        static_folder="../frontend/static",
    )
    app.secret_key = config.SECRET_KEY
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # ── Flask-Login Setup ─────────────────────────────────────────────────────
    login_manager = LoginManager(app)
    login_manager.login_view = "auth.login"  # redirect here if @login_required fails

    class _User(UserMixin):
        id = "admin"

    @login_manager.user_loader
    def load_user(user_id):
        if user_id == "admin":
            return _User()
        return None

    # ── Store module references in app context ────────────────────────────────
    app.analyzer = analyzer
    app.db       = db
    app.alerter  = alerter
    app.start_time = datetime.now(timezone.utc)

    # ── Register blueprints ───────────────────────────────────────────────────
    from api.routes import auth_bp, api_bp, dashboard_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)

    return app


# ─── Blueprints ───────────────────────────────────────────────────────────────

auth_bp      = Blueprint("auth",      __name__)
api_bp       = Blueprint("api",       __name__, url_prefix="/api")
dashboard_bp = Blueprint("dashboard", __name__)


# ══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    from flask_login import UserMixin

    class _User(UserMixin):
        id = "admin"

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if username == config.DASHBOARD_USERNAME and password == config.DASHBOARD_PASSWORD:
            login_user(_User(), remember=False)
            logger.info("Dashboard login: %s", username)
            return redirect(url_for("dashboard.index"))
        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html", error=None)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

@dashboard_bp.route("/")
@login_required
def index():
    return render_template("dashboard.html")


# ══════════════════════════════════════════════════════════════════════════════
# API ROUTES
# ══════════════════════════════════════════════════════════════════════════════

def _analyzer():
    from flask import current_app
    return current_app.analyzer

def _db():
    from flask import current_app
    return current_app.db

def _alerter():
    from flask import current_app
    return current_app.alerter


# ── /api/status ───────────────────────────────────────────────────────────────

@api_bp.route("/status")
def status():
    """System health check — no login required (for monitoring tools)."""
    from flask import current_app
    uptime = (datetime.now(timezone.utc) - current_app.start_time).total_seconds()
    return jsonify({
        "status":    "running",
        "uptime_s":  round(uptime, 1),
        "db_connected": _db().is_connected if _db() else False,
        "capture_running": True,   # simplification; can be wired to engine
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ── /api/stats/realtime ───────────────────────────────────────────────────────

@api_bp.route("/stats/realtime")
@login_required
def realtime_stats():
    """Return the most recent computed traffic metrics."""
    if not _analyzer():
        return jsonify({"error": "Analyzer not running"}), 503

    stats = _analyzer().get_realtime_stats()
    return jsonify(stats)


# ── /api/stats/history ────────────────────────────────────────────────────────

@api_bp.route("/stats/history")
@login_required
def traffic_history():
    """
    Historical traffic metrics.
    Query params:
      ?minutes=60   — lookback window (default 60)
      ?limit=200    — max records (default 200)
    """
    minutes = _int_param("minutes", 60, min_val=1, max_val=1440)
    limit   = _int_param("limit",   200, min_val=1, max_val=1000)

    if not _db():
        return jsonify({"error": "Database not connected", "data": []}), 503

    data = _db().get_traffic_history(minutes=minutes, limit=limit)
    return jsonify({"data": data, "count": len(data)})


# ── /api/alerts ───────────────────────────────────────────────────────────────

@api_bp.route("/alerts")
@login_required
def get_alerts():
    """
    Fetch alert records.
    Query params:
      ?limit=100     — max alerts (default 100)
      ?severity=HIGH — filter by severity
      ?minutes=60    — lookback window
      ?source=db     — "db" for MongoDB, "memory" for in-memory buffer (default: memory)
    """
    limit    = _int_param("limit",   100, min_val=1,  max_val=500)
    severity = request.args.get("severity")
    minutes  = request.args.get("minutes", type=int)
    source   = request.args.get("source", "memory")

    if source == "db" and _db():
        alerts = _db().get_alerts(limit=limit, severity=severity, minutes=minutes)
    elif _alerter():
        alerts = _alerter().get_recent_alerts(limit=limit)
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity.upper()]
    else:
        alerts = []

    return jsonify({"alerts": alerts, "count": len(alerts)})


# ── /api/top-talkers ─────────────────────────────────────────────────────────

@api_bp.route("/top-talkers")
@login_required
def top_talkers():
    """Return the top IP addresses by traffic volume."""
    if not _analyzer():
        return jsonify({"top_talkers": []}), 503
    stats = _analyzer().get_realtime_stats()
    return jsonify({"top_talkers": stats.get("top_talkers", [])})


# ── /api/protocols ────────────────────────────────────────────────────────────

@api_bp.route("/protocols")
@login_required
def protocol_distribution():
    """Return current protocol distribution percentages."""
    if not _analyzer():
        return jsonify({"protocols": {}}), 503
    stats = _analyzer().get_realtime_stats()
    return jsonify({"protocols": stats.get("protocol_dist", {})})


# ── /api/connections ──────────────────────────────────────────────────────────

@api_bp.route("/connections")
@login_required
def active_connections():
    """Return active network connections."""
    limit = _int_param("limit", 50, min_val=1, max_val=200)

    if _db() and _db().is_connected:
        conns = _db().get_connections(limit=limit)
    elif _analyzer():
        stats = _analyzer().get_realtime_stats()
        conns = []  # real-time stats no longer carry full connections
    else:
        conns = []

    return jsonify({"connections": conns, "count": len(conns)})


# ── /api/export/csv ───────────────────────────────────────────────────────────

@api_bp.route("/export/csv")
@login_required
def export_csv():
    """Stream the last 500 traffic stat records as a CSV download."""
    if not _db() or not _db().is_connected:
        return jsonify({"error": "Database not connected"}), 503

    records = _db().get_recent_packets(limit=500)
    csv_str = records_to_csv_string(records)

    filename = f"netmon_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── /api/export/json ──────────────────────────────────────────────────────────

@api_bp.route("/export/json")
@login_required
def export_json_endpoint():
    """Return the last 200 traffic stats as a JSON download."""
    if not _db() or not _db().is_connected:
        return jsonify({"error": "Database not connected"}), 503

    data = _db().get_traffic_history(minutes=240, limit=200)
    filename = f"netmon_stats_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        __import__("json").dumps({"data": data}, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _int_param(name: str, default: int, min_val: int = 1, max_val: int = 10_000) -> int:
    """Parse an integer query parameter with bounds checking."""
    try:
        val = int(request.args.get(name, default))
        return max(min_val, min(max_val, val))
    except (TypeError, ValueError):
        return default
