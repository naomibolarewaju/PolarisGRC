#REST API endpoints for receiving scan data from the audit agent
#and serving results to the dashboard.

import logging
from datetime import datetime

from io import BytesIO

from flask import Blueprint, Response, current_app, jsonify, request, send_file

from backend import db
from backend.models import Finding, Scan
from backend.services.compliance_service import ComplianceService
from backend.services.export_service import ExportService
from backend.services.risk_service import RiskService

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/health", methods=["GET"])
def health():
    #return service health status
    return jsonify({"status": "healthy", "version": "1.0.0"})


@api_bp.route("/scan-results", methods=["POST"])
def submit_scan_results():
    """Accept scan results from the audit agent and persist to the database.

    Automatically calculates a baseline risk score using default organisational
    context (medium-sized, medium-sensitivity organisation). Users can run the
    Risk Assessment Wizard for a context-specific score that accounts for
    industry, data types, and organisation size.

    Returns 201 with ``scan_id`` on success, 400 for invalid input, 500 on error.
    """
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

        # Calculate baseline risk score with default organizational context.
        # Users can perform detailed risk assessment for context-specific scoring.
        try:
            svc = RiskService()
            checks = data.get("checks", [])
            scan.risk_score = svc.calculate_risk_score(checks, svc.get_default_context())
        except Exception as risk_exc:
            logger.warning("Risk score calculation failed, storing None: %s", risk_exc)
            scan.risk_score = None

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
    """Retrieve detailed results for a single scan including all findings.

    Response JSON includes:

    * **findings** — list of individual check results.
    * **compliance_summary** — per-framework control coverage derived from
      the findings, with the following structure for each framework
      (``iso27001``, ``gdpr``, ``nist_csf``)::

          {
            "total_controls":  int,   # controls defined in reference data
            "satisfied":       int,   # controls with >= 1 PASS finding
            "failed":          int,   # controls with FAIL (and no PASS)
            "not_assessed":    int,   # controls with no findings or SKIP/ERROR only
            "coverage_percent": float # satisfied / total * 100, 1 d.p.
          }

    If the compliance service is unavailable ``compliance_summary`` will be
    an empty dict ``{}``.
    """
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

        compliance_summary = _build_compliance_summary(scan.findings)

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
            "compliance_summary": compliance_summary,
            "risk_score": scan.risk_score,
        })

    except Exception as e:
        logger.error("Failed to retrieve scan %s: %s", scan_id, e)
        return jsonify({
            "status": "error",
            "message": "Internal server error while retrieving scan details",
        }), 500


@api_bp.route("/scans/<scan_id>/export/csv", methods=["GET"])
def export_scan_csv(scan_id: str):
    """Download all findings for a scan as a CSV file.

    Returns a UTF-8 CSV attachment with 11 columns (check metadata, compliance
    mappings). Suitable for analysis in Excel or Google Sheets.

    Filename format: ``polaris_scan_<hostname>_<YYYYMMDD>.csv``
    """
    try:
        scan = db.session.get(Scan, scan_id)
        if scan is None:
            return jsonify({"status": "error", "message": f"Scan {scan_id} not found"}), 404

        csv_str = ExportService().export_scan_to_csv(scan, scan.findings)
        buf = BytesIO(csv_str.encode("utf-8"))
        buf.seek(0)

        filename = (
            f"polaris_scan_{scan.hostname}_{scan.scan_timestamp.strftime('%Y%m%d')}.csv"
        )
        return send_file(buf, mimetype="text/csv", as_attachment=True, download_name=filename)

    except Exception as e:
        logger.error("Failed to export scan %s as CSV: %s", scan_id, e)
        return jsonify({
            "status": "error",
            "message": "Internal server error while exporting scan",
        }), 500


def _build_compliance_summary(findings: list) -> dict:
    """Calculate per-framework compliance coverage from a list of Finding rows.

    For each framework control defined in the reference data:

    * **satisfied** — at least one finding mapping to this control has PASS status.
    * **failed** — at least one finding has FAIL status and none have PASS.
    * **not_assessed** — no findings map to this control, or all are SKIPPED/ERROR.

    Args:
        findings: SQLAlchemy Finding model instances (must have ``status`` and
                  ``compliance_mappings`` attributes).

    Returns:
        Dict keyed by framework name, or an empty dict if the service fails.
    """
    try:
        service = ComplianceService()
        summary: dict = {}

        for framework in ("iso27001", "gdpr", "nist_csf"):
            controls = service.get_all_controls_for_framework(framework)
            satisfied = 0
            failed = 0
            not_assessed = 0

            for control_id in controls:
                # Collect statuses from all findings that reference this control
                statuses = [
                    f.status
                    for f in findings
                    if control_id in (f.compliance_mappings or {}).get(framework, [])
                ]

                if not statuses or all(s in ("SKIPPED", "ERROR") for s in statuses):
                    not_assessed += 1
                elif "PASS" in statuses:
                    satisfied += 1
                else:  # FAIL present, no PASS
                    failed += 1

            total = len(controls)
            summary[framework] = {
                "total_controls": total,
                "satisfied": satisfied,
                "failed": failed,
                "not_assessed": not_assessed,
                "coverage_percent": round(satisfied / total * 100, 1) if total else 0.0,
            }

        return summary

    except Exception as exc:
        logger.error("Failed to calculate compliance summary: %s", exc)
        return {}
