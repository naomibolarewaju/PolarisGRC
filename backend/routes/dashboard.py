#Web dashboard routes for viewing scan results, compliance status,
#and generating reports. Serves HTML pages to end users.

import logging

from collections import defaultdict

from flask import Blueprint, flash, redirect, render_template, url_for

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
    #display detailed results for a single scan, findings grouped by category
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        flash("Scan not found.", "error")
        return redirect(url_for("dashboard.index"))

    # Group findings by category, preserving insertion order
    categories: dict[str, list] = defaultdict(list)
    for finding in scan.findings:
        key = finding.category or "Uncategorised"
        categories[key].append(finding)

    # Status counts derived from actual findings (source of truth)
    status_counts = {"PASS": 0, "FAIL": 0, "SKIPPED": 0, "ERROR": 0}
    for finding in scan.findings:
        status_counts[finding.status] = status_counts.get(finding.status, 0) + 1

    return render_template(
        "scan_detail.html",
        scan=scan,
        categories=categories,
        status_counts=status_counts,
    )


# Register this blueprint in backend/__init__.py:
#   from backend.routes.dashboard import dashboard_bp
#   app.register_blueprint(dashboard_bp)
