"""
Risk scoring service for PolarisGRC.

Calculates a simplified organisational risk score (0–100) from audit findings
and optional organisational context. The score is intended for prioritisation
and dashboard display only.

Limitations
-----------
* This is a simplified heuristic model, not a formal risk assessment
  methodology (e.g. ISO 27005, NIST SP 800-30).
* Severity weights and multipliers are illustrative defaults and should be
  tuned to the organisation's actual risk appetite.
* Skipped checks contribute uncertainty points, not confirmed risk.
* Use the score as guidance only — not as a compliance or audit conclusion.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Severity weights for FAIL findings ────────────────────────────────────────
_SEVERITY_WEIGHTS: dict[str, int] = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
}

# Points added per skipped privileged check (represents unknown/unverified risk)
_SKIPPED_PRIVILEGE_POINTS: int = 3

# ── Context multiplier tables ─────────────────────────────────────────────────
_SIZE_MULTIPLIERS: dict[str, float] = {
    "small": 1.0,
    "medium": 1.2,
    "large": 1.5,
}

_SENSITIVITY_MULTIPLIERS: dict[str, float] = {
    "low": 1.0,
    "medium": 1.3,
    "high": 1.6,
    "critical": 2.0,
}

_HIGH_RISK_INDUSTRIES = {"healthcare", "finance"}


class RiskService:
    """Calculates a simplified organisational risk score from audit findings.

    The score ranges from 0.0 (no detected risk) to 100.0 (maximum risk).
    A higher score indicates more urgent remediation is needed.

    The algorithm has three stages:

    1. **Base risk** — sum severity-weighted points for every FAIL finding.
       Skipped checks that required elevated privileges add a smaller penalty
       to account for unverified risk.

    2. **Context multipliers** — the raw base risk is scaled by up to three
       independent multipliers derived from organisational context:
       organisation size, data sensitivity classification, and industry sector.

    3. **Normalisation** — the result is capped at 100 and rounded to one
       decimal place.

    Example usage::

        svc = RiskService()

        # Minimal usage (uses default context)
        score = svc.calculate_risk_score(findings)

        # With organisational context
        score = svc.calculate_risk_score(findings, {
            'size': 'large',
            'data_sensitivity': 'high',
            'industry': 'finance',
        })

        level = svc.get_risk_level(score)   # 'LOW' | 'MEDIUM' | 'HIGH'
        color = svc.get_risk_color(score)   # 'success' | 'warning' | 'danger'

    .. note::
        This is a simplified model for prioritisation purposes only.
        It is not a substitute for a formal risk assessment conducted under
        ISO 27005, NIST SP 800-30, or equivalent methodology.
    """

    # ── Public API ─────────────────────────────────────────────────────────────

    def calculate_risk_score(
        self,
        findings: list,
        context: Optional[dict] = None,
    ) -> float:
        """Calculate a risk score (0–100) from audit findings and context.

        Args:
            findings: List of finding objects or dicts.  Each item must expose
                      ``status``, ``severity``, and optionally
                      ``requires_privilege`` either as dict keys or object
                      attributes.  Unknown or missing values are handled
                      gracefully — they simply contribute 0 points.
            context:  Optional organisational context dict.  Recognised keys:

                      * ``size`` — ``'small'``, ``'medium'``, or ``'large'``.
                        Larger organisations typically have a broader attack
                        surface. Default: ``'medium'``.
                      * ``data_sensitivity`` — ``'low'``, ``'medium'``,
                        ``'high'``, or ``'critical'``.  Reflects the value /
                        regulatory exposure of the data processed.
                        Default: ``'medium'``.
                      * ``industry`` — free-form string; ``'healthcare'`` and
                        ``'finance'`` attract an additional 1.4× multiplier
                        due to elevated regulatory requirements.
                        Default: ``'other'``.

                      Any unrecognised values silently fall back to the default
                      multiplier for that dimension (1.0×).

        Returns:
            Risk score as a ``float`` in the range ``[0.0, 100.0]``, rounded
            to one decimal place.  Returns ``0.0`` for an empty findings list.

        Example::

            svc = RiskService()
            score = svc.calculate_risk_score(findings, {'size': 'large'})
            # e.g. 42.5
        """
        if not findings:
            return 0.0

        ctx = {**self.get_default_context(), **(context or {})}

        # Stage 1: base risk from findings
        base_risk: float = 0.0
        for finding in findings:
            status = _get(finding, "status", "")
            severity = (_get(finding, "severity") or "").upper()
            requires_privilege = _get(finding, "requires_privilege", False)

            if status == "FAIL":
                base_risk += _SEVERITY_WEIGHTS.get(severity, 0)
            elif status == "SKIPPED" and requires_privilege:
                base_risk += _SKIPPED_PRIVILEGE_POINTS

        if base_risk == 0.0:
            return 0.0

        # Stage 2: context multipliers
        size_mult = _SIZE_MULTIPLIERS.get(
            str(ctx.get("size", "")).lower(), 1.0
        )
        sensitivity_mult = _SENSITIVITY_MULTIPLIERS.get(
            str(ctx.get("data_sensitivity", "")).lower(), 1.0
        )
        industry = str(ctx.get("industry", "")).lower()
        industry_mult = 1.4 if industry in _HIGH_RISK_INDUSTRIES else 1.0

        total_multiplier = size_mult * sensitivity_mult * industry_mult

        # Stage 3: normalise to 0–100
        score = min(base_risk * total_multiplier, 100.0)
        return round(score, 1)

    def get_risk_level(self, score: float) -> str:
        """Classify a risk score into a human-readable level.

        Args:
            score: Risk score in the range 0–100.

        Returns:
            ``'LOW'`` for scores below 30,
            ``'MEDIUM'`` for 30–69 (inclusive),
            ``'HIGH'`` for 70 and above.

        Example::

            svc.get_risk_level(25.0)  # 'LOW'
            svc.get_risk_level(55.0)  # 'MEDIUM'
            svc.get_risk_level(82.0)  # 'HIGH'
        """
        if score < 30:
            return "LOW"
        if score < 70:
            return "MEDIUM"
        return "HIGH"

    def get_risk_color(self, score: float) -> str:
        """Return a Bootstrap colour class corresponding to the risk level.

        Intended for use in Jinja2 templates::

            <span class="badge bg-{{ risk_service.get_risk_color(score) }}">
              {{ score }}
            </span>

        Args:
            score: Risk score in the range 0–100.

        Returns:
            ``'success'`` (green) for LOW,
            ``'warning'`` (yellow) for MEDIUM,
            ``'danger'`` (red) for HIGH.
        """
        level = self.get_risk_level(score)
        return {"LOW": "success", "MEDIUM": "warning", "HIGH": "danger"}[level]

    @staticmethod
    def get_default_context() -> dict:
        """Return the default organisational context used when none is provided.

        Returns:
            Dict with keys ``size``, ``data_sensitivity``, and ``industry``
            set to conservative mid-range defaults::

                {
                    'size': 'medium',
                    'data_sensitivity': 'medium',
                    'industry': 'other',
                }
        """
        return {
            "size": "medium",
            "data_sensitivity": "medium",
            "industry": "other",
        }


# ── Module-level helper ────────────────────────────────────────────────────────

def _get(obj, key: str, default=None):
    """Retrieve a value from either a dict or an object attribute."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)
