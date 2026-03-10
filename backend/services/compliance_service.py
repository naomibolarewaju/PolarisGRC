"""
Compliance data access service for PolarisGRC.

Loads compliance_mappings.json (check_id → framework controls) and
control_descriptions.json (framework → control metadata) once at startup
and exposes them through a simple query interface.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent / "data"


class ComplianceService:
    """Singleton service that centralizes access to compliance reference data.

    Loads two JSON files from the ``data/`` directory at first instantiation:

    * **compliance_mappings.json** — maps each agent check ID to the framework
      controls it provides evidence for.
      Schema: ``{check_id: {framework: [control_id, ...]}}``

    * **control_descriptions.json** — human-readable metadata for each control.
      Schema: ``{framework: {control_id: {title, description, category, domain}}}``

    Usage::

        svc = ComplianceService()
        mappings = svc.get_frameworks_for_check('ssh_root_login')
        # {'iso27001': ['A.9.2.3', 'A.9.4.3'], 'gdpr': [...], 'nist_csf': [...]}

        info = svc.get_control_info('iso27001', 'A.9.2.3')
        # {'title': '...', 'description': '...', 'category': '...', 'domain': '...'}
    """

    _instance: "ComplianceService | None" = None

    def __new__(cls) -> "ComplianceService":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialised = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialised:  # type: ignore[has-type]
            return
        self._initialised = True
        self.mappings: dict = self._load_json("compliance_mappings.json")
        self.descriptions: dict = self._load_json("control_descriptions.json")

    # ── Private helpers ───────────────────────────────────────

    @staticmethod
    def _load_json(filename: str) -> dict:
        """Load a JSON file from the data directory.

        Args:
            filename: Basename of the file inside ``data/``.

        Returns:
            Parsed JSON as a dict, or an empty dict on any error.
        """
        path = _DATA_DIR / filename
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            logger.warning("Compliance data file not found: %s", path)
            return {}
        except json.JSONDecodeError as exc:
            logger.error("Malformed JSON in %s: %s", path, exc)
            return {}

    # ── Public API ────────────────────────────────────────────

    def get_frameworks_for_check(self, check_id: str) -> dict:
        """Return the framework control mappings for a given agent check.

        Args:
            check_id: The agent check identifier (e.g. ``'ssh_root_login'``).

        Returns:
            A dict of framework → list of control IDs, or an empty dict if the
            check has no mapping entry::

                {
                    "iso27001": ["A.9.2.3", "A.9.4.3"],
                    "gdpr":     ["Article 32(1)(b)"],
                    "nist_csf": ["PR.AC-4", "PR.AC-7"],
                }
        """
        return dict(self.mappings.get(check_id, {}))

    def get_control_info(self, framework: str, control_id: str) -> dict | None:
        """Return metadata for a single compliance control.

        Args:
            framework:  Framework name (e.g. ``'iso27001'``, ``'gdpr'``,
                        ``'nist_csf'``).
            control_id: Control identifier (e.g. ``'A.9.2.3'``,
                        ``'Article 32(1)(b)'``, ``'PR.AC-4'``).

        Returns:
            A dict with keys ``title``, ``description``, ``category``, and
            ``domain``, or ``None`` if the control is not found::

                {
                    "title":       "Management of privileged access rights",
                    "description": "...",
                    "category":    "Access Control",
                    "domain":      "User Access Management",
                }
        """
        framework_data = self.descriptions.get(framework, {})
        info = framework_data.get(control_id)
        return dict(info) if info else None

    def get_all_controls_for_framework(self, framework: str) -> dict:
        """Return all control descriptions for a compliance framework.

        Args:
            framework: Framework name — ``'iso27001'``, ``'gdpr'``, or
                       ``'nist_csf'``.

        Returns:
            A dict of ``{control_id: control_info}``, or an empty dict if the
            framework is not found::

                {
                    "A.9.2.3": {"title": "...", "description": "...", ...},
                    "A.9.4.3": {"title": "...", "description": "...", ...},
                    ...
                }
        """
        return dict(self.descriptions.get(framework, {}))
