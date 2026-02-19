#REST API endpoints for receiving scan data from the audit agent
#and serving results to the dashboard.

import logging
from datetime import datetime

from flask import Blueprint, current_app, jsonify, request

from backend import db
from backend.models import Finding, Scan

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/health", methods=["GET"])
def health():
    #return service health status
    return jsonify({"status": "healthy", "version": "1.0.0"})


@api_bp.route("/scan-results", methods=["POST"])
def submit_scan_results():
    #accept scan results from the audit agent and persist to the database
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Request body must be JSON"}), 400

    required_fields = ["hostname", "scan_timestamp", "checks", "summary"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        return jsonify({
            "status": "error",
            "message": f"Missing required fields: {', '.join(missing)}",
        }), 400

    try:
        os_info = data.get("os_info", {})
        summary = data["summary"]

        scan = Scan(
            hostname=data["hostname"],
            agent_version=data.get("agent_version"),
            os_name=os_info.get("name"),
            os_version=os_info.get("version"),
            scan_timestamp=datetime.fromisoformat(data["scan_timestamp"]),
            privileged_mode=data.get("privileged_mode", False),
            total_checks=summary.get("total", 0),
            passed_checks=summary.get("passed", 0),
            failed_checks=summary.get("failed", 0),
            skipped_checks=summary.get("skipped", 0),
            error_checks=summary.get("errors", 0),
        )

        for check in data["checks"]:
            finding = Finding(
                scan=scan,
                check_id=check.get("check_id", "unknown"),
                name=check.get("name", "Unknown Check"),
                category=check.get("category"),
                status=check.get("status", "ERROR"),
                severity=check.get("severity"),
                finding=check.get("finding"),
                remediation=check.get("remediation"),
                requires_privilege=check.get("requires_privilege", False),
                privilege_level=check.get("privilege_level"),
                skip_reason=check.get("skip_reason"),
                cis_reference=check.get("cis_reference"),
                compliance_mappings=check.get("compliance_mappings"),
            )
            db.session.add(finding)

        db.session.add(scan)
        db.session.commit()

        return jsonify({
            "scan_id": scan.id,
            "status": "success",
            "message": "Scan results saved successfully",
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error("Failed to save scan results: %s", e)
        return jsonify({
            "status": "error",
            "message": "Internal server error while saving scan results",
        }), 500


@api_bp.route("/scans", methods=["GET"])
def get_scans():
    #retrieve a paginated list of all scans, most recent first
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)

        pagination = Scan.query.order_by(
            Scan.scan_timestamp.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)

        scans = []
        for scan in pagination.items:
            scans.append({
                "scan_id": scan.id,
                "hostname": scan.hostname,
                "timestamp": scan.scan_timestamp.isoformat(),
                "summary": {
                    "total": scan.total_checks,
                    "passed": scan.passed_checks,
                    "failed": scan.failed_checks,
                    "skipped": scan.skipped_checks,
                    "errors": scan.error_checks,
                },
                "risk_score": scan.risk_score,
            })

        return jsonify({"scans": scans})

    except Exception as e:
        logger.error("Failed to retrieve scans: %s", e)
        return jsonify({
            "status": "error",
            "message": "Internal server error while retrieving scans",
        }), 500


@api_bp.route("/scans/<scan_id>", methods=["GET"])
def get_scan_detail(scan_id: str):
    #retrieve detailed results for a single scan including all findings
    try:
        scan = db.session.get(Scan, scan_id)
        if scan is None:
            return jsonify({
                "status": "error",
                "message": f"Scan {scan_id} not found",
            }), 404

        findings = []
        for f in scan.findings:
            findings.append({
                "check_id": f.check_id,
                "name": f.name,
                "category": f.category,
                "status": f.status,
                "severity": f.severity,
                "finding": f.finding,
                "remediation": f.remediation,
                "requires_privilege": f.requires_privilege,
                "privilege_level": f.privilege_level,
                "skip_reason": f.skip_reason,
                "cis_reference": f.cis_reference,
                "compliance_mappings": f.compliance_mappings,
            })

        return jsonify({
            "scan_id": scan.id,
            "hostname": scan.hostname,
            "os_info": {
                "name": scan.os_name,
                "version": scan.os_version,
            },
            "scan_timestamp": scan.scan_timestamp.isoformat(),
            "privileged_mode": scan.privileged_mode,
            "summary": {
                "total": scan.total_checks,
                "passed": scan.passed_checks,
                "failed": scan.failed_checks,
                "skipped": scan.skipped_checks,
                "errors": scan.error_checks,
            },
            "findings": findings,
            "risk_score": scan.risk_score,
        })

    except Exception as e:
        logger.error("Failed to retrieve scan %s: %s", scan_id, e)
        return jsonify({
            "status": "error",
            "message": "Internal server error while retrieving scan details",
        }), 500
