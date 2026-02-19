#Web dashboard routes for viewing scan results, compliance status,
#and generating reports. Serves HTML pages to end users.

import logging

from flask import Blueprint, render_template

from backend import db
from backend.models import Scan

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    #display the main dashboard with a list of recent security scans
    try:
        scans = (
            Scan.query
            .order_by(Scan.scan_timestamp.desc())
            .limit(20)
            .all()
        )
    except Exception as e:
        logger.error("Failed to load scans for dashboard: %s", e)
        scans = []

    return render_template("dashboard.html", scans=scans)


@dashboard_bp.route("/scan/<scan_id>")
def view_scan(scan_id: str):
    #display detailed results for a single scan
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return render_template("404.html", message="Scan not found"), 404
    return render_template("scan_detail.html", scan=scan)


# Register this blueprint in backend/__init__.py:
#   from backend.routes.dashboard import dashboard_bp
#   app.register_blueprint(dashboard_bp)
