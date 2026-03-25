#REST API endpoints for receiving scan data from the audit agent
#and serving results to the dashboard.

import logging
from datetime import datetime

from io import BytesIO

from flask import Blueprint, Response, current_app, jsonify, request, send_file
from flask_login import current_user, login_required
from flask_wtf.csrf import generate_csrf

from backend import csrf, db
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


@api_bp.route("/csrf-token", methods=["GET"])
def get_csrf_token():
    """Return a fresh CSRF token for programmatic clients.

    Programmatic clients (e.g. the audit agent, scripts, or single-page
    apps that do not use WTForms) must include this token in the
    ``X-CSRFToken`` request header on every state-changing request
    (POST, PUT, PATCH, DELETE) unless the endpoint is ``@csrf.exempt``.

    Usage example::

        # 1. Fetch a token (requires an active session / login first)
        token_resp = requests.get("http://localhost:5000/api/csrf-token")
        token = token_resp.json()["csrf_token"]

        # 2. Include it in subsequent requests
        requests.post(
            "http://localhost:5000/api/scan-results",
            json=payload,
            headers={"X-CSRFToken": token},
        )

    Returns:
        JSON ``{"csrf_token": "<token>"}`` with HTTP 200.
    """
    return jsonify({"csrf_token": generate_csrf()})


@api_bp.route("/scan-results", methods=["POST"])
@csrf.exempt
@login_required
def submit_scan_results():
    """Accept scan results from the audit agent and persist to the database.

    This endpoint is ``@csrf.exempt`` because it is designed for programmatic
    access by the PolarisGRC audit agent, which sends JSON with an active
    session cookie (obtained by logging in via ``/login``) rather than a
    browser form.  CSRF forgery is not a practical threat here because:

    * The request body must be ``application/json`` — browsers cannot set
      this Content-Type in a cross-origin form POST.
    * The ``@login_required`` decorator still enforces authentication.

    Programmatic clients that *do* need to call other non-exempt endpoints
    should first call ``GET /api/csrf-token`` to obtain a token and then
    include it as an ``X-CSRFToken`` header.

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
            user_id=current_user.id,
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
@login_required
def get_scans():
    #retrieve a paginated list of all scans, most recent first
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)

        pagination = (
            Scan.query
            .filter_by(user_id=current_user.id)
            .order_by(Scan.scan_timestamp.desc())
            .paginate(page=page, per_page=per_page, error_out=False)
        )

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
@login_required
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
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
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
@login_required
def export_scan_csv(scan_id: str):
    """Download all findings for a scan as a CSV file.

    Returns a UTF-8 CSV attachment with 11 columns (check metadata, compliance
    mappings). Suitable for analysis in Excel or Google Sheets.

    Filename format: ``polaris_scan_<hostname>_<YYYYMMDD>.csv``
    """
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
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


@api_bp.route("/scans/<scan_id>/export/json", methods=["GET"])
@login_required
def export_scan_json(scan_id: str):
    """Download all findings for a scan as a JSON file matching the agent output format.

    The JSON structure mirrors the agent's scan output so it can be re-ingested
    or used by external tooling.

    Filename format: ``polaris_scan_<hostname>_<YYYYMMDD>.json``
    """
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        if scan is None:
            return jsonify({"status": "error", "message": f"Scan {scan_id} not found"}), 404

        findings = scan.findings
        status_counts = {"PASS": 0, "FAIL": 0, "SKIPPED": 0, "ERROR": 0}
        for f in findings:
            status_counts[f.status] = status_counts.get(f.status, 0) + 1

        payload = {
            "scan_metadata": {
                "hostname": scan.hostname,
                "os_info": {
                    "name": scan.os_name,
                    "version": scan.os_version,
                },
                "scan_timestamp": scan.scan_timestamp.isoformat(),
                "privileged": scan.privileged_mode,
                "agent_version": scan.agent_version,
                "risk_score": scan.risk_score,
            },
            "summary": {
                "total_checks": len(findings),
                "passed": status_counts.get("PASS", 0),
                "failed": status_counts.get("FAIL", 0),
                "skipped": status_counts.get("SKIPPED", 0),
                "errors": status_counts.get("ERROR", 0),
            },
            "checks": [
                {
                    "check_id": f.check_id,
                    "check_name": f.name,
                    "category": f.category,
                    "status": f.status,
                    "severity": f.severity,
                    "finding": f.finding,
                    "remediation": f.remediation,
                    "cis_reference": f.cis_reference,
                    "requires_privilege": f.requires_privilege,
                    "compliance_mappings": f.compliance_mappings or {},
                }
                for f in findings
            ],
        }

        filename = (
            f"polaris_scan_{scan.hostname}_{scan.scan_timestamp.strftime('%Y%m%d')}.json"
        )
        response = current_app.response_class(
            response=__import__("json").dumps(payload, indent=2),
            mimetype="application/json",
        )
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        logger.error("Failed to export scan %s as JSON: %s", scan_id, e)
        return jsonify({
            "status": "error",
            "message": "Internal server error while exporting scan",
        }), 500


@api_bp.route("/scans/<scan_id>/export/pdf", methods=["GET"])
@login_required
def export_scan_pdf(scan_id: str):
    """Generate and download a PDF audit report for a single scan.

    Renders a styled A4 report containing scan metadata, summary counts,
    risk score, and all findings grouped by category.

    Requires WeasyPrint to be installed (``pip install weasyprint``).

    Filename format: ``polaris_report_<hostname>_<YYYYMMDD>.pdf``
    """
    try:
        from weasyprint import CSS, HTML as WeasyHTML
    except ImportError:
        return jsonify({
            "status": "error",
            "message": "PDF generation requires WeasyPrint. Install with: pip install weasyprint",
        }), 501

    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        if scan is None:
            return jsonify({"status": "error", "message": f"Scan {scan_id} not found"}), 404

        findings = list(scan.findings)
        svc = RiskService()
        risk_score = scan.risk_score if scan.risk_score is not None else svc.calculate_risk_score(findings)
        risk_level = svc.get_risk_level(risk_score)

        # ── Group findings by category ─────────────────────────────────
        from collections import defaultdict
        categories: dict = defaultdict(list)
        for f in findings:
            categories[f.category or "Uncategorised"].append(f)

        status_counts = {"PASS": 0, "FAIL": 0, "SKIPPED": 0, "ERROR": 0}
        for f in findings:
            status_counts[f.status] = status_counts.get(f.status, 0) + 1

        risk_color = {"LOW": "#00b894", "MEDIUM": "#f39c12", "HIGH": "#e74c3c"}.get(risk_level, "#8899aa")

        # ── Build findings HTML ────────────────────────────────────────
        sev_colors = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#27ae60"}
        status_colors = {"PASS": "#00b894", "FAIL": "#e74c3c", "SKIPPED": "#8899aa", "ERROR": "#e67e22"}

        findings_html = ""
        for category, cat_findings in sorted(categories.items()):
            findings_html += f'<div class="category"><h3>{category}</h3>'
            for f in cat_findings:
                sev = (f.severity or "LOW").upper()
                stat = (f.status or "ERROR").upper()
                sev_col  = sev_colors.get(sev, "#8899aa")
                stat_col = status_colors.get(stat, "#8899aa")

                remediation_block = ""
                if f.remediation:
                    remediation_block = f"""
                    <div class="remediation">
                        <strong>Remediation:</strong><br>
                        {f.remediation.replace(chr(10), '<br>')}
                    </div>"""

                cis = f'<span class="cis">CIS {f.cis_reference}</span>' if f.cis_reference else ""

                findings_html += f"""
                <div class="finding">
                    <div class="finding-header">
                        <span class="finding-name">{f.name or f.check_id}</span>
                        <span class="badge" style="background:{stat_col}20;color:{stat_col};border-color:{stat_col}40;">{stat}</span>
                        <span class="badge" style="background:{sev_col}20;color:{sev_col};border-color:{sev_col}40;">{sev}</span>
                        {cis}
                    </div>
                    {f'<p class="finding-text">{f.finding}</p>' if f.finding else ''}
                    {remediation_block}
                </div>"""
            findings_html += "</div>"

        # ── Assemble full HTML document ────────────────────────────────
        generated_at = datetime.utcnow().strftime("%d %B %Y at %H:%M UTC")
        scan_ts = scan.scan_timestamp.strftime("%d %B %Y %H:%M")
        os_str = " ".join(filter(None, [scan.os_name, scan.os_version])) or "Unknown"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
@page {{
    size: A4;
    margin: 2cm 2cm 2.5cm;
    @bottom-center {{
        content: "PolarisGRC Audit Report  ·  {scan.hostname}  ·  Page " counter(page) " of " counter(pages);
        font-size: 8pt;
        color: #999;
        font-family: Arial, sans-serif;
    }}
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: Arial, Helvetica, sans-serif; font-size: 10pt; color: #1a1a2e; line-height: 1.55; }}

/* Cover strip */
.cover {{ background: #0d1b2a; color: white; padding: 28px 32px 24px; border-radius: 6px; margin-bottom: 24px; }}
.cover-logo {{ font-size: 11pt; font-weight: 700; letter-spacing: 0.08em; color: #00d4ff; margin-bottom: 16px; }}
.cover-title {{ font-size: 22pt; font-weight: 700; margin-bottom: 6px; }}
.cover-sub {{ font-size: 10pt; color: #9db5cc; }}
.cover-meta {{ display: flex; gap: 32px; margin-top: 18px; flex-wrap: wrap; }}
.cover-meta-item {{ font-size: 9pt; color: #9db5cc; }}
.cover-meta-item strong {{ color: #e0eaf5; display: block; font-size: 10pt; }}

/* Summary row */
.summary {{ display: flex; gap: 12px; margin-bottom: 20px; }}
.summary-box {{
    flex: 1; padding: 12px 16px; border-radius: 6px;
    border: 1px solid; text-align: center;
}}
.summary-box .num {{ font-size: 20pt; font-weight: 700; }}
.summary-box .lbl {{ font-size: 8pt; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 2px; }}
.box-pass   {{ background: #e8faf6; border-color: #00b894; color: #00b894; }}
.box-fail   {{ background: #fdf0ef; border-color: #e74c3c; color: #e74c3c; }}
.box-skip   {{ background: #f5f5f7; border-color: #8899aa; color: #8899aa; }}
.box-risk   {{ background: #fff8e1; border-color: {risk_color}; color: {risk_color}; }}

/* Section headings */
h2 {{ font-size: 13pt; font-weight: 700; color: #0d1b2a; border-bottom: 2px solid #e0eaf5;
      padding-bottom: 5px; margin: 20px 0 12px; page-break-after: avoid; }}
h3 {{ font-size: 10.5pt; font-weight: 700; color: #2c3e50; margin: 14px 0 8px;
      background: #f4f7fa; padding: 6px 10px; border-radius: 4px; border-left: 3px solid #2563eb;
      page-break-after: avoid; }}

/* Findings */
.category {{ page-break-inside: avoid; margin-bottom: 8px; }}
.finding {{ border: 1px solid #e0eaf5; border-radius: 5px; padding: 10px 14px; margin-bottom: 8px; page-break-inside: avoid; }}
.finding-header {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 6px; }}
.finding-name {{ font-weight: 700; font-size: 10pt; flex: 1; min-width: 160px; }}
.badge {{ font-size: 7.5pt; font-weight: 700; padding: 2px 7px; border-radius: 4px; border: 1px solid; white-space: nowrap; }}
.cis {{ font-size: 7.5pt; color: #8899aa; font-family: 'Courier New', monospace; margin-left: auto; }}
.finding-text {{ font-size: 9pt; color: #4a5568; margin-bottom: 6px; }}
.remediation {{ font-size: 8.5pt; color: #2d3748; background: #f7fafc; border-left: 3px solid #2563eb; padding: 6px 10px; border-radius: 0 4px 4px 0; }}

/* Footer note */
.footer-note {{ margin-top: 28px; font-size: 8pt; color: #999; border-top: 1px solid #e0eaf5; padding-top: 10px; }}
</style>
</head>
<body>

<div class="cover">
    <div class="cover-logo">★ POLARIS GRC</div>
    <div class="cover-title">Security Audit Report</div>
    <div class="cover-sub">Automated infrastructure security assessment</div>
    <div class="cover-meta">
        <div class="cover-meta-item"><strong>{scan.hostname}</strong>Host</div>
        <div class="cover-meta-item"><strong>{scan_ts}</strong>Scanned</div>
        <div class="cover-meta-item"><strong>{os_str}</strong>Operating System</div>
        <div class="cover-meta-item"><strong>{'Privileged' if scan.privileged_mode else 'Unprivileged'}</strong>Scan Mode</div>
    </div>
</div>

<h2>Executive Summary</h2>
<div class="summary">
    <div class="summary-box box-pass">
        <div class="num">{status_counts['PASS']}</div>
        <div class="lbl">Passed</div>
    </div>
    <div class="summary-box box-fail">
        <div class="num">{status_counts['FAIL']}</div>
        <div class="lbl">Failed</div>
    </div>
    <div class="summary-box box-skip">
        <div class="num">{status_counts['SKIPPED'] + status_counts['ERROR']}</div>
        <div class="lbl">Skipped / Error</div>
    </div>
    <div class="summary-box box-risk">
        <div class="num">{risk_score:.0f}</div>
        <div class="lbl">Risk Score ({risk_level})</div>
    </div>
</div>

<h2>Findings by Category</h2>
{findings_html}

<div class="footer-note">
    Generated by PolarisGRC on {generated_at}.
    Risk scores are heuristic estimates based on finding severity and organisational context.
    Technical checks indicate evidence toward compliance, not full certification.
</div>
</body>
</html>"""

        pdf_bytes = WeasyHTML(string=html).write_pdf()
        buf = BytesIO(pdf_bytes)
        buf.seek(0)

        filename = f"polaris_report_{scan.hostname}_{scan.scan_timestamp.strftime('%Y%m%d')}.pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)

    except Exception as e:
        logger.error("Failed to export scan %s as PDF: %s", scan_id, e)
        return jsonify({
            "status": "error",
            "message": "Internal server error while generating PDF report",
        }), 500


@api_bp.route("/policies/download/<filename>", methods=["GET"])
def download_policy(filename: str):
    """Serve a generated policy file as a download.

    Args:
        filename: Base filename (no extension) from ``policies/generated/``.
        fmt:      Query param — ``'markdown'`` (default) or ``'pdf'``.
    """
    import re
    from pathlib import Path

    fmt = request.args.get("fmt", "markdown")
    if fmt not in ("markdown", "pdf"):
        fmt = "markdown"

    # Sanitise filename to prevent path traversal
    safe_name = re.sub(r"[^\w\-]", "", filename)
    ext = "md" if fmt == "markdown" else "pdf"
    file_path = Path(__file__).resolve().parent.parent.parent / "policies" / "generated" / f"{safe_name}.{ext}"

    if not file_path.exists():
        return jsonify({"status": "error", "message": "Policy file not found"}), 404

    mimetype = "text/markdown" if fmt == "markdown" else "application/pdf"
    return send_file(
        str(file_path),
        mimetype=mimetype,
        as_attachment=True,
        download_name=f"{safe_name}.{ext}",
    )


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
