#Web dashboard routes for viewing scan results, compliance status,
#and generating reports. Serves HTML pages to end users.

import logging
import os
import re

from collections import defaultdict
from datetime import datetime
from pathlib import Path

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

from backend import db
from backend.models import Finding, Scan
from backend.services.compliance_service import ComplianceService
from backend.services.policy_service import PolicyService
from backend.services.risk_service import RiskService

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    #display the main dashboard with a list of recent security scans
    try:
        scans = (
            Scan.query
            .filter_by(user_id=current_user.id)
            .order_by(Scan.scan_timestamp.desc())
            .limit(20)
            .all()
        )
    except Exception as e:
        logger.error("Failed to load scans for dashboard: %s", e)
        scans = []

    return render_template("dashboard.html", scans=scans)


@dashboard_bp.route("/scan/<scan_id>")
@login_required
def view_scan(scan_id: str):
    """Display detailed results for a single scan, findings grouped by category.

    Computes a risk score for the scan using the stored value when available,
    falling back to an on-the-fly calculation with default organisational context.

    Template context:
        scan:         Scan ORM object.
        categories:   OrderedDict of {category_name: [Finding, ...]}.
        status_counts: Dict of {PASS/FAIL/SKIPPED/ERROR: int}.
        risk_score:   Float 0–100.
        risk_level:   'LOW' | 'MEDIUM' | 'HIGH'.
        risk_color:   'success' | 'warning' | 'danger'.
    """
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
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

    # Risk score: use stored value when available, calculate on-the-fly otherwise
    svc = RiskService()
    if scan.risk_score is not None:
        risk_score = scan.risk_score
    else:
        risk_score = svc.calculate_risk_score(scan.findings)
    risk_level = svc.get_risk_level(risk_score)
    risk_color = svc.get_risk_color(risk_score)

    return render_template(
        "scan_detail.html",
        scan=scan,
        categories=categories,
        status_counts=status_counts,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_color=risk_color,
    )


@dashboard_bp.route("/compliance")
@login_required
def compliance_overview():
    """Display compliance framework coverage based on the most recent scan.

    Queries the most recent scan and uses ComplianceService to calculate
    how many controls within each framework (ISO 27001, GDPR, NIST CSF)
    are satisfied, failed, or not assessed.

    Template context:
        scan: Most recent Scan object, or None if no scans exist.
        compliance_data: Dict keyed by framework key with coverage details,
            or None if calculation fails. Structure per framework::

                {
                    "name":             str,    # Display name
                    "description":      str,    # One-line description
                    "total_controls":   int,
                    "satisfied":        int,
                    "failed":           int,
                    "not_assessed":     int,
                    "coverage_percent": float,  # 0.0 – 100.0
                }

        last_scan_date: scan.scan_timestamp datetime, or None.
    """
    _FRAMEWORKS = {
        "iso27001": {
            "name": "ISO 27001",
            "description": "International standard for information security management systems",
        },
        "gdpr": {
            "name": "GDPR",
            "description": "EU regulation for data protection and privacy",
        },
        "nist_csf": {
            "name": "NIST CSF",
            "description": "US framework for improving cybersecurity posture",
        },
    }

    scan = None
    try:
        scan = (Scan.query
                .filter_by(user_id=current_user.id)
                .order_by(Scan.scan_timestamp.desc())
                .first())
    except Exception as e:
        logger.error("Failed to load scan for compliance overview: %s", e)

    compliance_data: dict | None = None
    if scan:
        try:
            service = ComplianceService()
            compliance_data = {}
            for fw_key, fw_meta in _FRAMEWORKS.items():
                controls = service.get_all_controls_for_framework(fw_key)
                satisfied = failed = 0
                for control_id in controls:
                    statuses = [
                        f.status
                        for f in scan.findings
                        if control_id in (f.compliance_mappings or {}).get(fw_key, [])
                    ]
                    if not statuses or all(s in ("SKIPPED", "ERROR") for s in statuses):
                        pass  # not assessed — excluded from totals
                    elif "PASS" in statuses:
                        satisfied += 1
                    else:
                        failed += 1
                assessed = satisfied + failed
                compliance_data[fw_key] = {
                    **fw_meta,
                    "total_controls": assessed,
                    "satisfied": satisfied,
                    "failed": failed,
                    "coverage_percent": round(satisfied / assessed * 100, 1) if assessed else 0.0,
                }
        except Exception as e:
            logger.error("Failed to calculate compliance data: %s", e)
            compliance_data = None

    return render_template(
        "compliance.html",
        scan=scan,
        compliance_data=compliance_data,
        last_scan_date=scan.scan_timestamp if scan else None,
    )


_VALID_FRAMEWORKS = {
    "iso27001": "ISO 27001",
    "gdpr": "GDPR",
    "nist_csf": "NIST CSF",
}


@dashboard_bp.route("/controls/<framework>")
@login_required
def list_framework_controls(framework: str):
    """List all compliance controls for a framework with per-control status from the most recent scan.

    Template context:
        framework:       Framework key (e.g. 'iso27001').
        framework_name:  Display name (e.g. 'ISO 27001').
        controls:        Dict of {control_id: control_info} sorted by control_id.
        control_status:  Dict of {control_id: 'satisfied'|'failed'|'not_assessed'},
                         or None if no scan exists.
        scan:            Most recent Scan object, or None.

    Note: add @login_required here once Flask-Login auth is implemented.
    """
    if framework not in _VALID_FRAMEWORKS:
        flash(f"Unknown framework '{framework}'.", "error")
        return redirect(url_for("dashboard.compliance_overview"))

    service = ComplianceService()
    controls_raw = service.get_all_controls_for_framework(framework)
    if not controls_raw:
        flash("No controls found for this framework.", "error")
        return redirect(url_for("dashboard.compliance_overview"))

    # Sort controls by ID for consistent display
    controls = dict(sorted(controls_raw.items()))

    scan = None
    control_status: dict | None = None
    try:
        scan = (Scan.query
                .filter_by(user_id=current_user.id)
                .order_by(Scan.scan_timestamp.desc())
                .first())
        if scan:
            control_status = {}
            for control_id in controls:
                statuses = [
                    f.status
                    for f in scan.findings
                    if control_id in (f.compliance_mappings or {}).get(framework, [])
                ]
                if not statuses or all(s in ("SKIPPED", "ERROR") for s in statuses):
                    pass  # not assessed — excluded from list
                elif "PASS" in statuses:
                    control_status[control_id] = "satisfied"
                else:
                    control_status[control_id] = "failed"
            # Only show controls that were actually assessed
            controls = {cid: info for cid, info in controls.items() if cid in control_status}
    except Exception as e:
        logger.error("Failed to load scan for controls list: %s", e)

    return render_template(
        "controls_list.html",
        framework=framework,
        framework_name=_VALID_FRAMEWORKS[framework],
        controls=controls,
        control_status=control_status,
        scan=scan,
    )


@dashboard_bp.route("/control/<framework>/<path:control_id>")
@login_required
def view_control(framework: str, control_id: str):
    """Display plain-English explanation and technical evidence for a compliance control.

    Template context:
        framework:        Framework key (e.g. 'iso27001').
        control_id:       Control identifier (e.g. 'A.9.2.3').
        control_info:     Dict with title, description, category, domain.
        scan:             Most recent Scan object, or None.
        related_findings: List of Finding objects mapped to this control.
    """
    service = ComplianceService()
    control_info = service.get_control_info(framework, control_id)
    if control_info is None:
        flash("Control not found.", "error")
        return redirect(url_for("dashboard.compliance_overview"))

    scan = None
    related_findings = []
    try:
        scan = (Scan.query
                .filter_by(user_id=current_user.id)
                .order_by(Scan.scan_timestamp.desc())
                .first())
        if scan:
            related_findings = [
                f for f in scan.findings
                if control_id in (f.compliance_mappings or {}).get(framework, [])
            ]
    except Exception as e:
        logger.error("Failed to load findings for control view: %s", e)

    return render_template(
        "control_detail.html",
        framework=framework,
        control_id=control_id,
        control_info=control_info,
        scan=scan,
        related_findings=related_findings,
    )


_RISK_INDUSTRIES = ["healthcare", "finance", "technology", "retail", "manufacturing", "education", "government", "other"]
_RISK_SIZES = ["small", "medium", "large"]
_RISK_SENSITIVITIES = ["low", "medium", "high", "critical"]


@dashboard_bp.route("/risk-assessment", methods=["GET", "POST"])
@login_required
def risk_assessment():
    """Collect organisational context and calculate a risk score from the most recent scan.

    GET:  Render the wizard form. Redirects to dashboard if no scans exist.
    POST: Validate form input, calculate score via RiskService, store in session,
          redirect to /risk-results.

    Session keys written on success:
        risk_score    float   0–100
        risk_level    str     LOW | MEDIUM | HIGH
        risk_context  dict    cleaned form data
        scan_id       str     UUID of the scan used

    Note: add @login_required here once Flask-Login auth is implemented.
    """
    scan = None
    try:
        scan = (Scan.query
                .filter_by(user_id=current_user.id)
                .order_by(Scan.scan_timestamp.desc())
                .first())
    except Exception as e:
        logger.error("Failed to load scan for risk assessment: %s", e)

    if request.method == "GET":
        # If a previous assessment exists in session, redirect to results unless the user
        # explicitly requested a reset via the "Retake Assessment" button (?reset=1).
        if request.args.get("reset") != "1" and session.get("risk_score") is not None:
            return redirect(url_for("dashboard.risk_results"))

        if scan is None:
            flash("Please run a security scan first.", "warning")
            return redirect(url_for("dashboard.index"))

        # Clear stale session data so the wizard always starts blank on a reset.
        for key in ("risk_score", "risk_level", "risk_context", "scan_id"):
            session.pop(key, None)

        return render_template("risk_wizard.html", scan=scan)

    # ── POST ──────────────────────────────────────────────────────────────────
    org_name = request.form.get("org_name", "").strip()
    size = request.form.get("size", "").strip().lower()
    industry = request.form.get("industry", "").strip().lower()
    data_sensitivity = request.form.get("data_sensitivity", "").strip().lower()
    data_types = request.form.getlist("data_types")

    errors = []
    if not org_name:
        errors.append("Organisation name is required.")
    if size not in _RISK_SIZES:
        errors.append("Please select an organisation size.")
    if industry not in _RISK_INDUSTRIES:
        errors.append("Please select an industry.")
    if data_sensitivity not in _RISK_SENSITIVITIES:
        errors.append("Please select a data sensitivity level.")

    if errors:
        for msg in errors:
            flash(msg, "error")
        return render_template("risk_wizard.html", scan=scan), 422

    if scan is None:
        flash("No scan data found. Please run a security scan first.", "warning")
        return redirect(url_for("dashboard.index"))

    context = {
        "size": size,
        "industry": industry,
        "data_sensitivity": data_sensitivity,
    }

    svc = RiskService()
    score = svc.calculate_risk_score(scan.findings, context)
    level = svc.get_risk_level(score)

    session["risk_score"] = score
    session["risk_level"] = level
    session["risk_context"] = {**context, "org_name": org_name, "data_types": data_types}
    session["scan_id"] = scan.id

    return redirect(url_for("dashboard.risk_results"))


_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dashboard_bp.route("/risk-results")
@login_required
def risk_results():
    """Display the calculated risk score with prioritised recommendations.

    Reads session keys written by risk_assessment(). Redirects back to
    the wizard if session data is missing.

    Template context:
        score        float   0–100 risk score
        level        str     LOW | MEDIUM | HIGH
        color        str     Bootstrap colour token (success/warning/danger)
        context      dict    org context + org_name + data_types
        scan         Scan    ORM object or None
        top_risks    list    Up to 5 FAIL findings sorted HIGH→MEDIUM→LOW
        fail_counts  dict    {HIGH: n, MEDIUM: n, LOW: n} for all FAIL findings
        skipped_priv int     count of SKIPPED findings with requires_privilege
        est_reduction float  approximate score drop from fixing all HIGH failures

    Note: add @login_required here once Flask-Login auth is implemented.
    """
    score = session.get("risk_score")
    if score is None:
        flash("Please complete the risk assessment first.", "info")
        return redirect(url_for("dashboard.risk_assessment"))

    level = session.get("risk_level", "UNKNOWN")
    context = session.get("risk_context", {})
    scan_id = session.get("scan_id")

    scan = None
    if scan_id:
        try:
            scan = db.session.get(Scan, scan_id)
        except Exception as e:
            logger.error("Failed to load scan for risk results: %s", e)

    svc = RiskService()
    color = svc.get_risk_color(score)

    # Compute top risks and recommendation stats from findings
    top_risks: list = []
    fail_counts: dict = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    skipped_priv: int = 0
    est_reduction: float = 0.0

    if scan:
        failed = [f for f in scan.findings if f.status == "FAIL"]
        failed.sort(key=lambda f: _SEVERITY_ORDER.get((f.severity or "").upper(), 3))
        top_risks = failed[:5]

        for f in failed:
            sev = (f.severity or "").upper()
            if sev in fail_counts:
                fail_counts[sev] += 1

        skipped_priv = sum(
            1 for f in scan.findings
            if f.status == "SKIPPED" and f.requires_privilege
        )

        # Estimate reduction from fixing all HIGH failures (base points × multipliers)
        # Re-derive multiplier from stored context for a realistic estimate
        high_base = fail_counts["HIGH"] * 10
        if high_base:
            full_score = svc.calculate_risk_score(scan.findings, context)
            score_without_high = svc.calculate_risk_score(
                [f for f in scan.findings if not (f.status == "FAIL" and (f.severity or "").upper() == "HIGH")],
                context,
            )
            est_reduction = round(full_score - score_without_high, 1)

    return render_template(
        "risk_results.html",
        score=score,
        level=level,
        color=color,
        context=context,
        scan=scan,
        top_risks=top_risks,
        fail_counts=fail_counts,
        skipped_priv=skipped_priv,
        est_reduction=est_reduction,
    )


_TEMPLATE_DISPLAY_NAMES = {
    "access_control_policy.md.j2": "Access Control Policy",
    "acceptable_use_policy.md.j2": "Acceptable Use Policy",
    "incident_response_plan.md.j2": "Incident Response Plan",
}


@dashboard_bp.route("/policies", methods=["GET", "POST"])
@login_required
def policy_generator():
    """Display the policy generator form and handle policy generation.

    GET:  Renders the generator with available templates and recent scans.
    POST: Validates form input, generates a policy document via PolicyService,
          saves it to policies/generated/, stores the filename in session, and
          redirects to /policies/preview.

    Session keys written on success:
        policy_filename  str   Base filename of the generated file (no extension)
        policy_format    str   'markdown' or 'pdf'
        policy_title     str   Human-readable policy name for display

    Note: add @login_required here once Flask-Login auth is implemented.
    """
    svc = PolicyService()

    if request.method == "GET":
        raw_templates = svc.get_available_templates()
        templates = [
            {"filename": t, "display_name": _TEMPLATE_DISPLAY_NAMES.get(t, t.replace("_", " ").replace(".md.j2", "").title())}
            for t in raw_templates
        ]
        scans = (Scan.query
                 .filter_by(user_id=current_user.id)
                 .order_by(Scan.scan_timestamp.desc())
                 .limit(10).all())
        return render_template("policy_generator.html", templates=templates, scans=scans)

    # ── POST ──────────────────────────────────────────────────────────────────
    policy_type = request.form.get("policy_type", "").strip()
    scan_id = request.form.get("scan_id", "").strip()
    org_name = request.form.get("org_name", "").strip()
    policy_owner = request.form.get("policy_owner", "").strip()
    output_format = request.form.get("output_format", "markdown").strip()

    errors = []
    if not policy_type:
        errors.append("Please select a policy template.")
    if not scan_id:
        errors.append("Please select a scan to base the policy on.")
    if not org_name:
        errors.append("Organisation name is required.")
    if not policy_owner:
        errors.append("Policy owner is required.")
    if output_format not in ("markdown", "pdf"):
        output_format = "markdown"

    if errors:
        for msg in errors:
            flash(msg, "error")
        raw_templates = svc.get_available_templates()
        templates = [
            {"filename": t, "display_name": _TEMPLATE_DISPLAY_NAMES.get(t, t.replace("_", " ").replace(".md.j2", "").title())}
            for t in raw_templates
        ]
        scans = (Scan.query
                 .filter_by(user_id=current_user.id)
                 .order_by(Scan.scan_timestamp.desc())
                 .limit(10).all())
        return render_template("policy_generator.html", templates=templates, scans=scans), 422

    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if scan is None:
        flash("Selected scan not found.", "error")
        return redirect(url_for("dashboard.policy_generator"))

    org_data = {
        "org_name": org_name,
        "policy_owner": policy_owner,
        "incident_response_lead": request.form.get("incident_response_lead", "").strip() or None,
        "it_manager": request.form.get("it_manager", "").strip() or None,
        "iso_officer": request.form.get("iso_officer", "").strip() or None,
        "legal_contact": request.form.get("legal_contact", "").strip() or None,
        "comms_officer": request.form.get("comms_officer", "").strip() or None,
    }

    try:
        content = svc.generate_policy(
            template_name=policy_type,
            org_data=org_data,
            scan_findings=list(scan.findings),
            output_format=output_format,
        )

        import re
        safe_org = re.sub(r"[^\w\-]", "_", org_name.lower())
        safe_type = policy_type.replace(".md.j2", "")
        from datetime import date
        filename = f"{safe_org}_{safe_type}_{date.today().strftime('%Y%m%d')}"

        saved_path = svc.save_policy(content, filename=filename, fmt=output_format)

        session["policy_filename"] = filename
        session["policy_format"] = output_format
        session["policy_title"] = _TEMPLATE_DISPLAY_NAMES.get(policy_type, "Security Policy")

        logger.info("Policy generated and saved: %s", saved_path)
        return redirect(url_for("dashboard.policy_preview"))

    except Exception as exc:
        logger.error("Policy generation failed: %s", exc)
        flash(f"Policy generation failed: {exc}", "error")
        return redirect(url_for("dashboard.policy_generator"))


@dashboard_bp.route("/policies/preview")
@login_required
def policy_preview():
    """Display the most recently generated policy document with download options.

    Reads session keys written by policy_generator(). Redirects to the generator
    if no policy has been generated yet.

    Template context:
        policy_title    str   Human-readable policy name
        policy_format   str   'markdown' or 'pdf'
        policy_content  str   Raw Markdown content (None for PDF)
        filename        str   Base filename for the download link
    """
    filename = session.get("policy_filename")
    if not filename:
        flash("No policy has been generated yet. Use the form below.", "info")
        return redirect(url_for("dashboard.policy_generator"))

    fmt = session.get("policy_format", "markdown")
    title = session.get("policy_title", "Security Policy")

    policy_content = None
    if fmt == "markdown":
        from pathlib import Path
        md_path = Path(__file__).resolve().parent.parent.parent / "policies" / "generated" / f"{filename}.md"
        try:
            policy_content = md_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.error("Could not read generated policy file %s: %s", md_path, exc)
            flash("Generated policy file could not be read.", "error")
            return redirect(url_for("dashboard.policy_generator"))

    return render_template(
        "policy_preview.html",
        policy_title=title,
        policy_format=fmt,
        policy_content=policy_content,
        filename=filename,
    )


_GENERATED_DIR = Path(__file__).resolve().parent.parent.parent / "policies" / "generated"

# Filename fragments → human-readable policy type label
_TYPE_LABELS = {
    "access_control_policy": "Access Control Policy",
    "acceptable_use_policy": "Acceptable Use Policy",
    "incident_response_plan": "Incident Response Plan",
}


def _policy_file_info(path: Path) -> dict:
    """Build a metadata dict for a single file in policies/generated/."""
    stat = path.stat()
    size_bytes = stat.st_size
    if size_bytes < 1024:
        size_str = f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        size_str = f"{size_bytes / 1024:.1f} KB"
    else:
        size_str = f"{size_bytes / (1024 * 1024):.2f} MB"

    fmt = "pdf" if path.suffix == ".pdf" else "markdown"
    stem = path.stem  # filename without extension

    # Derive a display name: strip org prefix + date suffix, map to label
    policy_type = "Security Policy"
    for fragment, label in _TYPE_LABELS.items():
        if fragment in stem:
            policy_type = label
            break

    # Convert stem to title-cased display name as fallback
    display_name = policy_type if policy_type != "Security Policy" else stem.replace("_", " ").title()

    return {
        "filename": stem,
        "display_name": display_name,
        "policy_type": policy_type,
        "format": fmt,
        "date_created": datetime.fromtimestamp(stat.st_mtime).strftime("%d %b %Y %H:%M"),
        "date_ts": stat.st_mtime,
        "file_size": size_str,
    }


@dashboard_bp.route("/policies/manage")
@login_required
def manage_policies():
    """List all previously generated policy files with metadata.

    Scans ``policies/generated/`` for ``.md`` and ``.pdf`` files and returns
    them sorted newest-first.

    Template context:
        policies  list[dict]  Sorted list of policy metadata dicts. Each dict
                              has keys: filename, display_name, policy_type,
                              format, date_created, file_size.

    Note: add @login_required here once Flask-Login auth is implemented.
    """
    policies: list[dict] = []
    try:
        if _GENERATED_DIR.is_dir():
            for path in _GENERATED_DIR.iterdir():
                if path.suffix in (".md", ".pdf") and path.name != ".gitkeep":
                    try:
                        policies.append(_policy_file_info(path))
                    except OSError as exc:
                        logger.warning("Skipping unreadable policy file %s: %s", path.name, exc)

        policies.sort(key=lambda p: p["date_ts"], reverse=True)
        for p in policies:
            del p["date_ts"]  # not needed in template

    except Exception as exc:
        logger.error("Failed to list generated policies: %s", exc)
        flash("Could not load policy library.", "error")

    return render_template("policy_management.html", policies=policies)


@dashboard_bp.route("/policies/delete/<path:filename>", methods=["POST"])
@login_required
def delete_policy(filename: str):
    """Delete a generated policy file from ``policies/generated/``.

    Accepts the base filename (no extension). Tries both ``.md`` and ``.pdf``
    variants and deletes whichever exists. Sanitises the filename to prevent
    path traversal.

    Args:
        filename: Base filename (no extension) of the policy to delete.

    Note: add @login_required here once Flask-Login auth is implemented.
    """
    safe_name = re.sub(r"[^\w\-]", "", filename)
    if not safe_name:
        flash("Invalid filename.", "error")
        return redirect(url_for("dashboard.manage_policies"))

    deleted = False
    for ext in (".md", ".pdf"):
        target = _GENERATED_DIR / f"{safe_name}{ext}"
        try:
            if target.exists():
                os.remove(target)
                deleted = True
        except OSError as exc:
            logger.error("Failed to delete policy file %s: %s", target, exc)

    if deleted:
        flash("Policy deleted successfully.", "success")
    else:
        flash("Policy file not found.", "error")

    return redirect(url_for("dashboard.manage_policies"))


# Register this blueprint in backend/__init__.py:
#   from backend.routes.dashboard import dashboard_bp
#   app.register_blueprint(dashboard_bp)
