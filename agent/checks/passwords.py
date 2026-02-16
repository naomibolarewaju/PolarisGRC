import re
from pathlib import Path

PAM_PATHS = [
    "/etc/pam.d/common-password",  # Debian/Ubuntu
    "/etc/pam.d/system-auth",      # RHEL/CentOS
]
LOGIN_DEFS_PATH = "/etc/login.defs"
MIN_LENGTH_THRESHOLD = 12
DEFAULT_MINLEN = 8


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

    def run_all_checks(self) -> list[dict]:
        #run all password policy security checks
        self.checks = []
        self.check_password_min_length()
        self.check_sha512_hashing()
        return self.checks
