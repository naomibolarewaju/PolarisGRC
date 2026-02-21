import re
from pathlib import Path

PAM_PATHS = [
    "/etc/pam.d/common-password",  # Debian/Ubuntu
    "/etc/pam.d/system-auth",      # RHEL/CentOS
]
PWQUALITY_CONF_PATH = "/etc/security/pwquality.conf"
LOGIN_DEFS_PATH = "/etc/login.defs"
MIN_LENGTH_THRESHOLD = 12
DEFAULT_MINLEN = 8
PASS_MAX_DAYS_THRESHOLD = 90


class PasswordChecker:
    #password policy security checks

    def __init__(self) -> None:
        #initialize PasswordChecker with empty checks list
        self.checks: list[dict] = []

    def check_password_min_length(self) -> dict:
        #check that PAM enforces a minimum password length of 12 or more
        result: dict = {
            "check_id": "password_min_length",
            "name": "Password Minimum Length >= 12",
            "category": "Password Policy",
            "status": "PASS",
            "severity": "MEDIUM",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "5.4.1.1",
            "compliance_mappings": {
                "iso27001": ["A.9.4.3"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-1"],
            },
        }

        # Try each PAM config path
        content: str | None = None
        for pam_path in PAM_PATHS:
            try:
                content = Path(pam_path).read_text()
                break
            except FileNotFoundError:
                continue
            except PermissionError:
                result["status"] = "ERROR"
                result["finding"] = f"Permission denied reading {pam_path}"
                self.checks.append(result)
                return result

        if content is None:
            result["status"] = "ERROR"
            result["finding"] = "PAM password config not found (checked common-password and system-auth)"
            self.checks.append(result)
            return result

        # Look for minlen in pam_pwquality.so or pam_unix.so lines
        minlen = DEFAULT_MINLEN
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if "pam_pwquality.so" in stripped or "pam_unix.so" in stripped:
                match = re.search(r"minlen=(\d+)", stripped)
                if match:
                    minlen = int(match.group(1))
                    break

        result["finding"] = f"Minimum password length is {minlen} characters"

        if minlen >= MIN_LENGTH_THRESHOLD:
            result["status"] = "PASS"
        else:
            result["status"] = "FAIL"
            result["remediation"] = (
                "Edit /etc/security/pwquality.conf:\n"
                "  minlen = 12\n"
                "Or edit /etc/pam.d/common-password:\n"
                "  password requisite pam_pwquality.so minlen=12"
            )

        self.checks.append(result)
        return result

    def check_sha512_hashing(self) -> dict:
        #check that passwords are hashed with SHA-512
        result: dict = {
            "check_id": "password_sha512",
            "name": "SHA-512 Password Hashing Used",
            "category": "Password Policy",
            "status": "PASS",
            "severity": "HIGH",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "5.4.2",
            "compliance_mappings": {
                "iso27001": ["A.9.4.3", "A.10.1.1"],
                "gdpr": ["Article 32(1)(a)"],
                "nist_csf": ["PR.DS-1"],
            },
        }

        try:
            content = Path(LOGIN_DEFS_PATH).read_text()
        except FileNotFoundError:
            result["status"] = "ERROR"
            result["finding"] = "/etc/login.defs file not found"
            self.checks.append(result)
            return result
        except PermissionError:
            result["status"] = "ERROR"
            result["finding"] = "Permission denied reading /etc/login.defs"
            self.checks.append(result)
            return result

        encrypt_method: str | None = None
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0] == "ENCRYPT_METHOD":
                encrypt_method = parts[1]
                break

        if encrypt_method is None:
            result["status"] = "FAIL"
            result["finding"] = "Password encryption method is: not set"
            result["remediation"] = (
                "Edit /etc/login.defs:\n"
                "  ENCRYPT_METHOD SHA512"
            )
        elif encrypt_method.upper() == "SHA512":
            result["status"] = "PASS"
            result["finding"] = f"Password encryption method is: {encrypt_method}"
        else:
            result["status"] = "FAIL"
            result["finding"] = f"Password encryption method is: {encrypt_method}"
            result["remediation"] = (
                "Edit /etc/login.defs:\n"
                "  ENCRYPT_METHOD SHA512"
            )

        self.checks.append(result)
        return result

    def check_password_complexity(self) -> dict:
        #check that password complexity requirements are enforced via PAM
        result: dict = {
            "check_id": "password_complexity",
            "name": "Password Complexity Requirements",
            "category": "Password Policy",
            "status": "PASS",
            "severity": "HIGH",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "5.4.1.2",
            "compliance_mappings": {
                "iso27001": ["A.9.4.3"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-1"],
            },
        }

        _REMEDIATION = (
            "Configure password complexity in /etc/security/pwquality.conf:\n"
            "  minclass = 3\n"
            "  ucredit = -1\n"
            "  lcredit = -1\n"
            "  dcredit = -1\n"
            "  ocredit = -1\n"
            "\n"
            "Or install pwquality: sudo apt-get install libpam-pwquality"
        )

        _CREDIT_KEYS = ("ucredit", "lcredit", "dcredit", "ocredit")

        def _parse_key_value_settings(text: str) -> dict[str, int]:
            """Extract minclass / ucredit / lcredit / dcredit / ocredit from a config file."""
            settings: dict[str, int] = {}
            pattern = re.compile(
                r"^(minclass|ucredit|lcredit|dcredit|ocredit)\s*=\s*(-?\d+)",
                re.IGNORECASE,
            )
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m = pattern.match(stripped)
                if m:
                    settings[m.group(1).lower()] = int(m.group(2))
            return settings

        def _parse_pam_inline_settings(text: str) -> dict[str, int]:
            """Extract complexity params from the pam_pwquality.so / pam_cracklib.so line."""
            settings: dict[str, int] = {}
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or not stripped:
                    continue
                if "pam_pwquality.so" not in stripped and "pam_cracklib.so" not in stripped:
                    continue
                for key in ("minclass",) + _CREDIT_KEYS:
                    m = re.search(rf"{key}=(-?\d+)", stripped)
                    if m:
                        settings[key] = int(m.group(1))
                break  # only the first matching line matters
            return settings

        def _evaluate(settings: dict[str, int]) -> tuple[bool, str]:
            """Return (passed, finding_detail) for a given set of parsed settings."""
            if settings.get("minclass", 0) >= 3:
                return True, f"minclass = {settings['minclass']} (requires {settings['minclass']}+ character types)"
            all_credits = all(
                settings.get(k) is not None and settings[k] < 0
                for k in _CREDIT_KEYS
            )
            if all_credits:
                credit_str = ", ".join(f"{k}={settings[k]}" for k in _CREDIT_KEYS)
                return True, f"all character class credits enforced ({credit_str})"
            # Build a descriptive failure message
            parts: list[str] = []
            if "minclass" in settings:
                parts.append(f"minclass = {settings['minclass']} (need >= 3)")
            missing = [k for k in _CREDIT_KEYS if k not in settings or settings[k] >= 0]
            if missing:
                parts.append(f"missing/non-negative credits: {', '.join(missing)}")
            detail = "; ".join(parts) if parts else "no recognised complexity settings"
            return False, detail

        # ── 1. Try /etc/security/pwquality.conf ────────────────
        try:
            conf_text = Path(PWQUALITY_CONF_PATH).read_text()
            settings = _parse_key_value_settings(conf_text)
            passed, detail = _evaluate(settings)
            if passed:
                result["status"] = "PASS"
                result["finding"] = (
                    f"Password complexity enforced via {PWQUALITY_CONF_PATH}: {detail}"
                )
            else:
                result["status"] = "FAIL"
                result["finding"] = (
                    f"Insufficient complexity settings in {PWQUALITY_CONF_PATH}: {detail}"
                )
                result["remediation"] = _REMEDIATION
            self.checks.append(result)
            return result
        except FileNotFoundError:
            pass  # fall through to PAM files
        except PermissionError:
            result["status"] = "ERROR"
            result["finding"] = f"Permission denied reading {PWQUALITY_CONF_PATH}"
            self.checks.append(result)
            return result

        # ── 2. Fall back to PAM files ───────────────────────────
        pam_text: str | None = None
        for pam_path in PAM_PATHS:
            try:
                pam_text = Path(pam_path).read_text()
                break
            except FileNotFoundError:
                continue
            except PermissionError:
                result["status"] = "ERROR"
                result["finding"] = f"Permission denied reading {pam_path}"
                self.checks.append(result)
                return result

        if pam_text is None:
            result["status"] = "SKIPPED"
            result["skip_reason"] = "Password complexity configuration not found"
            result["finding"] = "Password complexity configuration not found"
            self.checks.append(result)
            return result

        pam_settings = _parse_pam_inline_settings(pam_text)
        if not pam_settings:
            result["status"] = "FAIL"
            result["finding"] = (
                "No pam_pwquality.so or pam_cracklib.so with complexity settings "
                "found in PAM configuration"
            )
            result["remediation"] = _REMEDIATION
            self.checks.append(result)
            return result

        passed, detail = _evaluate(pam_settings)
        if passed:
            result["status"] = "PASS"
            result["finding"] = f"Password complexity enforced via PAM: {detail}"
        else:
            result["status"] = "FAIL"
            result["finding"] = f"Insufficient complexity settings in PAM config: {detail}"
            result["remediation"] = _REMEDIATION

        self.checks.append(result)
        return result

    def check_password_max_age(self) -> dict:
        #check that PASS_MAX_DAYS in /etc/login.defs is set to 90 days or fewer
        result: dict = {
            "check_id": "password_max_age",
            "name": "Password Maximum Age",
            "category": "Password Policy",
            "status": "PASS",
            "severity": "MEDIUM",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "5.4.1.4",
            "compliance_mappings": {
                "iso27001": ["A.9.4.3"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-1"],
            },
        }

        _REMEDIATION = (
            "Edit /etc/login.defs and set:\n"
            "  PASS_MAX_DAYS 90\n"
            "\n"
            "Then for existing users, run:\n"
            "  sudo chage --maxdays 90 <username>"
        )

        try:
            content = Path(LOGIN_DEFS_PATH).read_text()
        except FileNotFoundError:
            result["status"] = "SKIPPED"
            result["skip_reason"] = "login.defs not found"
            result["finding"] = "login.defs not found"
            self.checks.append(result)
            return result
        except PermissionError:
            result["status"] = "ERROR"
            result["finding"] = f"Permission denied reading {LOGIN_DEFS_PATH}"
            self.checks.append(result)
            return result

        max_days: int | None = None
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0] == "PASS_MAX_DAYS":
                try:
                    max_days = int(parts[1])
                except ValueError:
                    result["status"] = "ERROR"
                    result["finding"] = (
                        f"Could not parse PASS_MAX_DAYS value: '{parts[1]}'"
                    )
                    self.checks.append(result)
                    return result
                break

        if max_days is None:
            result["status"] = "FAIL"
            result["finding"] = "PASS_MAX_DAYS is not configured (defaults to no expiry)"
            result["remediation"] = _REMEDIATION
        elif max_days == 99999:
            result["status"] = "FAIL"
            result["finding"] = "Passwords are set to never expire (PASS_MAX_DAYS=99999)"
            result["remediation"] = _REMEDIATION
        elif max_days > PASS_MAX_DAYS_THRESHOLD:
            result["status"] = "FAIL"
            result["finding"] = (
                f"Password maximum age is {max_days} days "
                f"(should be <= {PASS_MAX_DAYS_THRESHOLD})"
            )
            result["remediation"] = _REMEDIATION
        else:
            result["status"] = "PASS"
            result["finding"] = f"Password maximum age is set to {max_days} days"

        self.checks.append(result)
        return result

    def run_all_checks(self) -> list[dict]:
        #run all password policy security checks
        self.checks = []
        self.check_password_min_length()
        self.check_sha512_hashing()
        self.check_password_complexity()
        self.check_password_max_age()
        return self.checks
