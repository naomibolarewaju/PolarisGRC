"""Export service for converting scan results to various formats.

Currently supports CSV export suitable for analysis in spreadsheet tools
such as Microsoft Excel or Google Sheets.
"""

import csv
import io
from typing import List

from backend.models import Finding, Scan

_HEADERS = [
    "Check ID",
    "Check Name",
    "Category",
    "Status",
    "Severity",
    "Finding",
    "Remediation",
    "CIS Reference",
    "ISO 27001",
    "GDPR",
    "NIST CSF",
]

_FINDING_MAX = 200
_REMEDIATION_MAX = 500


def _str(value) -> str:
    """Return value as a string, replacing None with an empty string."""
    return "" if value is None else str(value)


def _truncate(value, limit: int) -> str:
    s = _str(value)
    return s[:limit] + "…" if len(s) > limit else s


def _mappings(finding: Finding, framework: str) -> str:
    """Return compliance controls for a framework as a comma-separated string."""
    mappings = finding.compliance_mappings or {}
    controls = mappings.get(framework, [])
    return ", ".join(controls) if controls else ""


class ExportService:
    """Converts scan data into exportable formats for offline analysis."""

    def export_scan_to_csv(self, scan: Scan, findings: List[Finding]) -> str:
        """Serialise scan findings to a CSV string.

        Columns (in order):
            Check ID, Check Name, Category, Status, Severity,
            Finding (≤ 200 chars), Remediation (≤ 500 chars),
            CIS Reference, ISO 27001, GDPR, NIST CSF

        Compliance mapping columns contain the relevant control identifiers
        joined by ", " (e.g. "A.9.2.3, A.9.4.3" for ISO 27001).
        None values are written as empty strings.
        Fields containing commas, quotes, or newlines are automatically
        quoted by the csv module (QUOTE_MINIMAL dialect).

        Args:
            scan:     The parent Scan ORM object (used for metadata only).
            findings: List of Finding ORM objects belonging to the scan.

        Returns:
            A UTF-8 CSV string with a header row followed by one row per finding.
        """
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)

        writer.writerow(_HEADERS)

        for f in findings:
            writer.writerow([
                _str(f.check_id),
                _str(f.name),
                _str(f.category),
                _str(f.status),
                _str(f.severity),
                _truncate(f.finding, _FINDING_MAX),
                _truncate(f.remediation, _REMEDIATION_MAX),
                _str(f.cis_reference),
                _mappings(f, "iso27001"),
                _mappings(f, "gdpr"),
                _mappings(f, "nist_csf"),
            ])

        return buf.getvalue()
