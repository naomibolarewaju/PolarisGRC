"""
Policy generation service for PolarisGRC.

Renders Jinja2 policy templates (``policies/templates/``) into finished Markdown
documents, optionally informed by live scan findings. Generated files are written
to ``policies/generated/``.

Typical usage
-------------
::

    from backend.services.policy_service import PolicyService

    svc = PolicyService()

    # List available templates
    templates = svc.get_available_templates()

    # Render a policy, tailored to the latest scan
    content = svc.generate_policy(
        template_name="access_control_policy.md.j2",
        org_data={
            "org_name": "Acme Ltd",
            "policy_owner": "Jane Smith",
        },
        scan_findings=findings_list,
    )

    # Persist to disk
    path = svc.save_policy(content, filename="acme_access_control_policy")
    print(f"Saved to {path}")

Limitations
-----------
* PDF output requires WeasyPrint to be installed (``pip install weasyprint``).
  If WeasyPrint is unavailable the service raises ``ImportError`` rather than
  silently returning an empty file.
* Template autoescape is enabled only for HTML/XML extensions; Markdown
  templates (``.md.j2``) are rendered without HTML escaping so that Markdown
  syntax is preserved verbatim.
"""

import logging
from datetime import date, timedelta
from io import BytesIO
from pathlib import Path
from typing import Any

import markdown
from jinja2 import (
    Environment,
    FileSystemLoader,
    TemplateNotFound,
    TemplateSyntaxError,
    select_autoescape,
)

try:
    from weasyprint import CSS, HTML as WeasyHTML
    _WEASYPRINT_AVAILABLE = True
except ImportError:
    _WEASYPRINT_AVAILABLE = False

logger = logging.getLogger(__name__)

# Absolute path to the policies directory (two levels above this file:
# backend/services/policy_service.py → backend/ → project root → policies/)
_POLICIES_DIR = Path(__file__).resolve().parent.parent.parent / "policies"
_TEMPLATES_DIR = _POLICIES_DIR / "templates"
_GENERATED_DIR = _POLICIES_DIR / "generated"

# check_id substrings mapped to analysis flags
_CHECK_ID_FLAGS: dict[str, str] = {
    "ssh_root": "ssh_root_login_failed",
    "root_login": "ssh_root_login_failed",
    "password_policy": "weak_password_policy",
    "password_complexity": "weak_password_policy",
    "password_max_age": "weak_password_policy",
    "password_min_length": "weak_password_policy",
    "shadow": "weak_password_policy",
    "sudo": "passwordless_sudo_found",
    "nopasswd": "passwordless_sudo_found",
    "firewall": "no_firewall",
    "ufw": "no_firewall",
    "iptables": "no_firewall",
    "nftables": "no_firewall",
    "auditd": "no_auditd",
    "audit_log": "no_auditd",
}


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Return ``obj[key]`` for dicts or ``obj.key`` for ORM objects."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class PolicyService:
    """Generate security policy documents from Jinja2 templates.

    The service wraps a Jinja2 ``Environment`` pointed at
    ``policies/templates/``. It analyses scan findings to set conditional
    template flags (e.g. ``ssh_root_login_failed``) so the rendered document
    reflects the organisation's actual security posture rather than generic
    boilerplate.

    Thread safety
    -------------
    ``PolicyService`` instances are stateless after ``__init__`` — the
    ``Environment`` object is read-only at render time. It is safe to share a
    single instance across threads.
    """

    PDF_CSS = """
@page {
    size: A4;
    margin: 2.5cm;
    @top-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9pt;
        color: #666;
    }
}

body {
    font-family: 'Helvetica', 'Arial', sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #333;
}

h1 {
    font-size: 24pt;
    color: #2563eb;
    border-bottom: 2px solid #2563eb;
    padding-bottom: 10px;
    page-break-after: avoid;
}

h2 {
    font-size: 18pt;
    color: #1e40af;
    margin-top: 20pt;
    page-break-after: avoid;
}

h3 {
    font-size: 14pt;
    color: #1e3a8a;
    margin-top: 15pt;
    page-break-after: avoid;
}

h4 {
    font-size: 12pt;
    color: #1e3a8a;
    margin-top: 10pt;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
    page-break-inside: avoid;
}

th {
    background-color: #2563eb;
    color: white;
    padding: 10px;
    text-align: left;
    font-weight: bold;
}

td {
    padding: 8px;
    border: 1px solid #ddd;
    vertical-align: top;
}

tr:nth-child(even) {
    background-color: #f9fafb;
}

strong {
    color: #1e40af;
    font-weight: 600;
}

code {
    background-color: #f3f4f6;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 10pt;
}

pre {
    background-color: #f3f4f6;
    padding: 12px;
    border-radius: 4px;
    border-left: 3px solid #2563eb;
    font-size: 9pt;
    overflow-x: auto;
    page-break-inside: avoid;
}

blockquote {
    border-left: 4px solid #2563eb;
    padding: 8px 15px;
    margin: 12px 0;
    color: #4b5563;
    font-style: italic;
    background-color: #eff6ff;
}

ul, ol {
    margin: 10px 0;
    padding-left: 25px;
}

li {
    margin: 5px 0;
}

hr {
    border: none;
    border-top: 1px solid #d1d5db;
    margin: 20px 0;
}

p {
    margin: 8px 0;
}

.page-break {
    page-break-before: always;
}
"""

    def __init__(self) -> None:
        """Initialise the Jinja2 environment.

        The template loader is rooted at ``policies/templates/`` relative to the
        project root. Autoescape is enabled for HTML/XML extensions only; Markdown
        templates are rendered without HTML escaping so that ``*bold*`` and
        ``# Heading`` syntax is preserved verbatim.

        Raises:
            OSError: If the templates directory does not exist or is not readable.
        """
        if not _TEMPLATES_DIR.is_dir():
            raise OSError(
                f"Policy templates directory not found: {_TEMPLATES_DIR}. "
                "Ensure the 'policies/templates/' directory exists."
            )

        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(enabled_extensions=("html", "xml")),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

        logger.debug("PolicyService initialised with templates dir: %s", _TEMPLATES_DIR)

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_available_templates(self) -> list[str]:
        """Return the filenames of all available policy templates.

        Scans ``policies/templates/`` for files with the ``.md.j2`` extension.

        Returns:
            List of template filenames (e.g.
            ``['access_control_policy.md.j2', ...]``), sorted alphabetically.
            Returns an empty list if no templates are found.

        Example::

            svc = PolicyService()
            for name in svc.get_available_templates():
                print(name)
        """
        try:
            return sorted(p.name for p in _TEMPLATES_DIR.glob("*.md.j2"))
        except OSError as exc:
            logger.error("Could not list templates: %s", exc)
            return []

    def analyze_findings(
        self,
        findings: list[dict[str, Any]],
        org_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Analyse scan findings and return boolean flags for template conditionals.

        Each flag corresponds to a ``{% if flag %}`` block in the policy
        templates. A flag is set to ``True`` when a FAIL or ERROR finding whose
        ``check_id`` matches a known pattern is detected.

        Args:
            findings: List of finding dicts or ORM ``Finding`` objects. Each
                item must expose ``check_id``, ``status``, ``severity``,
                ``name``, and ``compliance_mappings`` (as a dict with
                ``iso27001``, ``gdpr``, ``nist_csf`` lists).
            org_context: Optional organisational context dict (from the risk
                wizard). Used to set ``handles_pii`` and
                ``handles_remote_access`` flags.

        Returns:
            Dict with the following keys:

            * ``ssh_root_login_failed`` (bool)
            * ``weak_password_policy`` (bool)
            * ``passwordless_sudo_found`` (bool)
            * ``no_firewall`` (bool)
            * ``no_auditd`` (bool)
            * ``handles_pii`` (bool) — set from org_context data_types
            * ``handles_remote_access`` (bool) — set from org_context
            * ``compliance_gaps`` (list[str]) — human-readable gap descriptions
            * ``password_min_length`` (int) — 12 (default; override via org_context)
            * ``password_max_age`` (int) — 90 (default; override via org_context)

        Example::

            flags = svc.analyze_findings(scan.findings, org_context={"data_types": ["pii"]})
            print(flags["ssh_root_login_failed"])  # True / False
        """
        ctx = org_context if isinstance(org_context, dict) else {}

        flags: dict[str, Any] = {
            "ssh_root_login_failed": False,
            "weak_password_policy": False,
            "passwordless_sudo_found": False,
            "no_firewall": False,
            "no_auditd": False,
            "handles_pii": False,
            "handles_remote_access": False,
            "compliance_gaps": [],
            "password_min_length": 12,
            "password_max_age": 90,
        }

        # Derive PII / remote-access flags from organisational context
        data_types = ctx.get("data_types") or []
        if isinstance(data_types, list):
            pii_keywords = {"pii", "personal", "health", "financial", "gdpr"}
            flags["handles_pii"] = any(
                any(kw in str(dt).lower() for kw in pii_keywords) for dt in data_types
            )
        flags["handles_remote_access"] = ctx.get("has_remote_workers", False)

        compliance_gaps: list[str] = []

        for finding in findings:
            status = (_get(finding, "status") or "").upper()
            if status not in ("FAIL", "ERROR"):
                continue

            check_id = (_get(finding, "check_id") or "").lower()
            check_name = _get(finding, "name") or _get(finding, "check_name") or check_id
            severity = (_get(finding, "severity") or "LOW").upper()

            # Match check_id against known patterns
            for pattern, flag_name in _CHECK_ID_FLAGS.items():
                if pattern in check_id:
                    flags[flag_name] = True

            # Build a human-readable compliance gap entry for FAIL findings
            mappings = _get(finding, "compliance_mappings") or {}
            iso_controls = mappings.get("iso27001", [])
            gdpr_controls = mappings.get("gdpr", [])

            refs: list[str] = []
            if iso_controls:
                refs.append("ISO 27001: " + ", ".join(iso_controls[:2]))
            if gdpr_controls:
                refs.append("GDPR: " + ", ".join(gdpr_controls[:1]))

            ref_str = " | ".join(refs)
            gap = f"[{severity}] {check_name}" + (f" — {ref_str}" if ref_str else "")
            compliance_gaps.append(gap)

        # Deduplicate while preserving order (HIGH first)
        _seen: set[str] = set()
        unique_gaps: list[str] = []
        for gap in sorted(compliance_gaps, key=lambda g: (0 if "[HIGH]" in g else 1 if "[MEDIUM]" in g else 2)):
            if gap not in _seen:
                _seen.add(gap)
                unique_gaps.append(gap)

        flags["compliance_gaps"] = unique_gaps
        logger.debug(
            "analyze_findings: flags=%s, gap_count=%d",
            {k: v for k, v in flags.items() if k != "compliance_gaps"},
            len(unique_gaps),
        )
        return flags

    def generate_policy(
        self,
        template_name: str,
        org_data: dict[str, Any],
        scan_findings: list[dict[str, Any]] | None = None,
        output_format: str = "markdown",
        org_context: dict[str, Any] | None = None,
    ) -> str:
        """Render a policy template to a finished document string.

        Args:
            template_name: Filename of the template inside ``policies/templates/``
                (e.g. ``'access_control_policy.md.j2'``). A ``.md.j2`` suffix
                is appended automatically if omitted.
            org_data: Organisation metadata used to populate the document header.
                Recognised keys:

                * ``org_name`` (str, required) — organisation display name
                * ``policy_owner`` (str) — name of the policy author/owner
                * ``incident_response_lead`` (str) — IRP-specific field
                * ``it_manager`` (str) — IRP-specific field
                * ``iso_officer`` (str) — IRP-specific field
                * ``legal_contact`` (str) — IRP-specific field
                * ``comms_officer`` (str) — IRP-specific field

            scan_findings: Optional list of finding dicts or ORM ``Finding``
                objects. When supplied the document is customised with
                conditional sections based on detected issues.
            org_context: Optional context dict from the risk wizard (same shape
                as the session ``risk_context``). Used for PII / remote-access
                flags.
            output_format: ``'markdown'`` (default) returns the rendered string.
                ``'pdf'`` converts via WeasyPrint and returns bytes.

        Returns:
            Rendered policy as a UTF-8 string (Markdown) or bytes (PDF).

        Raises:
            ValueError: If the template is not found or the format is unknown.
            TemplateSyntaxError: If the template contains a Jinja2 syntax error.
            ImportError: If ``output_format='pdf'`` and WeasyPrint is not installed.

        Example::

            md = svc.generate_policy(
                "access_control_policy.md.j2",
                org_data={"org_name": "Acme Ltd", "policy_owner": "J. Smith"},
                scan_findings=findings,
            )
        """
        # Normalise template name
        if not template_name.endswith(".j2"):
            template_name = template_name + ".md.j2"

        if output_format not in ("markdown", "pdf"):
            raise ValueError(
                f"Unknown output_format '{output_format}'. "
                "Supported values: 'markdown', 'pdf'."
            )

        # Load template
        try:
            template = self._env.get_template(template_name)
        except TemplateNotFound:
            available = self.get_available_templates()
            raise ValueError(
                f"Template '{template_name}' not found in {_TEMPLATES_DIR}. "
                f"Available templates: {available}"
            )
        except TemplateSyntaxError as exc:
            logger.error("Syntax error in template '%s': %s", template_name, exc)
            raise

        # Build rendering context
        today = date.today()
        context: dict[str, Any] = {
            "policy_date": f"{today.day} {today.strftime('%B %Y')}",
            "review_date": (lambda d: f"{d.day} {d.strftime('%B %Y')}")(today + timedelta(days=365)),
            # Defaults for optional variables referenced in templates
            "policy_owner": "Information Security Team",
            "incident_response_lead": None,
            "it_manager": None,
            "iso_officer": None,
            "legal_contact": None,
            "comms_officer": None,
            "review_frequency": 12,
            # Findings-derived flags (all False until analysis runs)
            "ssh_root_login_failed": False,
            "weak_password_policy": False,
            "passwordless_sudo_found": False,
            "no_firewall": False,
            "no_auditd": False,
            "handles_pii": False,
            "handles_remote_access": False,
            "compliance_gaps": [],
            "password_min_length": 12,
            "password_max_age": 90,
        }

        # Merge org_data (caller values override defaults)
        context.update(org_data)

        # Analyse findings and merge flags
        if scan_findings:
            analysis = self.analyze_findings(scan_findings, org_context=org_context)
            context.update(analysis)

        # Render
        try:
            rendered: str = template.render(**context)
        except Exception as exc:
            logger.error("Failed to render template '%s': %s", template_name, exc)
            raise

        if output_format == "markdown":
            return rendered

        # PDF path — requires WeasyPrint
        return self.generate_pdf(rendered)

    def save_policy(
        self,
        content: str,
        filename: str,
        fmt: str = "markdown",
    ) -> str:
        """Write rendered policy content to ``policies/generated/``.

        Args:
            content: Rendered policy string (Markdown) or bytes (PDF).
            filename: Base filename without extension
                (e.g. ``'acme_access_control_policy'``).
            fmt: ``'markdown'`` writes a ``.md`` file; ``'pdf'`` writes ``.pdf``.

        Returns:
            Absolute path of the written file as a string.

        Raises:
            ValueError: If ``fmt`` is not ``'markdown'`` or ``'pdf'``.
            OSError: If the file cannot be written.

        Example::

            path = svc.save_policy(content, "acme_aup")
            print(path)  # /abs/path/policies/generated/acme_aup.md
        """
        if fmt not in ("markdown", "pdf"):
            raise ValueError(f"Unknown format '{fmt}'. Supported: 'markdown', 'pdf'.")

        ext = "md" if fmt == "markdown" else "pdf"
        _GENERATED_DIR.mkdir(parents=True, exist_ok=True)
        out_path = _GENERATED_DIR / f"{filename}.{ext}"

        try:
            if fmt == "pdf" and isinstance(content, bytes):
                out_path.write_bytes(content)
            else:
                out_path.write_text(content, encoding="utf-8")
            logger.info("Policy saved to %s", out_path)
        except OSError as exc:
            logger.error("Failed to write policy to %s: %s", out_path, exc)
            raise

        return str(out_path)

    # ── PDF generation ─────────────────────────────────────────────────────────

    def generate_pdf(self, markdown_content: str) -> bytes:
        """Convert a rendered Markdown policy document to a styled PDF.

        The conversion pipeline is:

        1. ``markdown`` library converts Markdown to an HTML fragment
           (extensions: ``tables``, ``fenced_code``, ``nl2br``).
        2. The fragment is wrapped in a full HTML document with a ``<style>``
           block containing :attr:`PDF_CSS`.
        3. WeasyPrint renders the HTML/CSS to PDF bytes using its built-in
           renderer (no browser required).

        Args:
            markdown_content: Fully rendered Markdown string, typically the
                output of :meth:`generate_policy` with ``output_format='markdown'``.

        Returns:
            Raw PDF bytes suitable for writing to a ``.pdf`` file or returning
            as a Flask ``send_file`` response.

        Raises:
            ImportError: If WeasyPrint is not installed.
            ValueError: If the Markdown content is empty.
            RuntimeError: If WeasyPrint fails to render the document.

        Example::

            md = svc.generate_policy("access_control_policy.md.j2", org_data)
            pdf_bytes = svc.generate_pdf(md)
            Path("policy.pdf").write_bytes(pdf_bytes)
        """
        if not markdown_content or not markdown_content.strip():
            raise ValueError("Cannot generate PDF from empty Markdown content.")

        if not _WEASYPRINT_AVAILABLE:
            raise ImportError(
                "PDF generation requires WeasyPrint. "
                "Install it with: pip install weasyprint"
            )

        # Step 1: Markdown → HTML fragment
        try:
            html_body = markdown.markdown(
                markdown_content,
                extensions=["tables", "fenced_code", "nl2br"],
            )
        except Exception as exc:
            logger.error("Markdown conversion failed: %s", exc)
            raise RuntimeError(f"Failed to convert Markdown to HTML: {exc}") from exc

        # Step 2: Wrap in full HTML document (CSS injected via WeasyPrint CSS object)
        full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Policy Document</title>
</head>
<body>
{html_body}
</body>
</html>"""

        # Step 3: Render to PDF via WeasyPrint
        try:
            html_obj = WeasyHTML(string=full_html)
            css_obj = CSS(string=self.PDF_CSS)
            pdf_bytes: bytes = html_obj.write_pdf(stylesheets=[css_obj])
        except Exception as exc:
            logger.error("WeasyPrint PDF rendering failed: %s", exc)
            raise RuntimeError(f"PDF rendering failed: {exc}") from exc

        logger.debug("generate_pdf: produced %d bytes", len(pdf_bytes))
        return pdf_bytes
