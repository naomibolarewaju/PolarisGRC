import subprocess
from pathlib import Path

PASSWD_PATH = "/etc/passwd"
SUDOERS_PATH = "/etc/sudoers"
SUDOERS_DIR = "/etc/sudoers.d"


class UserChecker:
    #user and privilege management security checks

    def __init__(self) -> None:
        #initialize UserChecker with empty checks list.
        self.checks: list[dict] = []

    def _run_command(self, cmd: list[str]) -> tuple[str, str, int]:
        #run a shell command and return stdout, stderr, returncode
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return (proc.stdout, proc.stderr, proc.returncode)
        except subprocess.TimeoutExpired:
            return ("", "Command timeout", 1)
        except FileNotFoundError:
            return ("", "Command not found", 1)

    def check_uid_zero(self) -> dict:
        #check that only root has UID 0
        result: dict = {
            "check_id": "uid_zero_root_only",
            "name": "Only Root Has UID 0",
            "category": "User Management",
            "status": "PASS",
            "severity": "HIGH",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "6.2.9",
            "compliance_mappings": {
                "iso27001": ["A.9.2.3"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-4"],
            },
        }

        try:
            content = Path(PASSWD_PATH).read_text()
        except FileNotFoundError:
            result["status"] = "ERROR"
            result["finding"] = "/etc/passwd file not found"
            self.checks.append(result)
            return result
        except PermissionError:
            result["status"] = "ERROR"
            result["finding"] = "Permission denied reading /etc/passwd"
            self.checks.append(result)
            return result

        uid_zero_users: list[str] = []
        for line in content.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                uid_zero_users.append(parts[0])

        if uid_zero_users:
            result["status"] = "FAIL"
            names = ", ".join(uid_zero_users)
            result["finding"] = (
                f"Found {len(uid_zero_users)} users with UID 0: {names}"
            )
            result["remediation"] = (
                "Review users with UID 0. Only root should have UID 0:\n"
                "  sudo userdel <username>"
            )
        else:
            result["status"] = "PASS"
            result["finding"] = "Only root has UID 0"

        self.checks.append(result)
        return result

    def check_passwordless_sudo(self) -> dict:
        #check that no users have passwordless sudo access via NOPASSWD
        result: dict = {
            "check_id": "no_passwordless_sudo",
            "name": "No Passwordless Sudo Allowed",
            "category": "Privilege Management",
            "status": "PASS",
            "severity": "HIGH",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "5.6",
            "compliance_mappings": {
                "iso27001": ["A.9.2.3", "A.9.4.1"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-4"],
            },
        }

        nopasswd_hits: list[str] = []

        #check /etc/sudoers
        try:
            content = Path(SUDOERS_PATH).read_text()
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "NOPASSWD" in stripped:
                    nopasswd_hits.append(f"{SUDOERS_PATH} ({stripped})")
        except PermissionError:
            result["status"] = "SKIPPED"
            result["finding"] = "Insufficient privileges to read sudoers files"
            result["requires_privilege"] = True
            result["privilege_level"] = "root"
            result["skip_reason"] = "Requires root to read sudoers files"
            self.checks.append(result)
            return result
        except FileNotFoundError:
            pass  #no sudoers file, continue to sudoers.d

        #check /etc/sudoers.d/*
        sudoers_dir = Path(SUDOERS_DIR)
        if sudoers_dir.is_dir():
            try:
                for filepath in sudoers_dir.iterdir():
                    if not filepath.is_file():
                        continue
                    try:
                        content = filepath.read_text()
                        for line in content.splitlines():
                            stripped = line.strip()
                            if not stripped or stripped.startswith("#"):
                                continue
                            if "NOPASSWD" in stripped:
                                nopasswd_hits.append(f"{filepath} ({stripped})")
                    except PermissionError:
                        result["status"] = "SKIPPED"
                        result["finding"] = "Insufficient privileges to read sudoers files"
                        result["requires_privilege"] = True
                        result["privilege_level"] = "root"
                        result["skip_reason"] = "Requires root to read sudoers files"
                        self.checks.append(result)
                        return result
            except PermissionError:
                result["status"] = "SKIPPED"
                result["finding"] = "Insufficient privileges to read sudoers files"
                result["requires_privilege"] = True
                result["privilege_level"] = "root"
                result["skip_reason"] = "Requires root to read sudoers files"
                self.checks.append(result)
                return result

        if nopasswd_hits:
            result["status"] = "FAIL"
            locations = "; ".join(nopasswd_hits)
            result["finding"] = f"Found passwordless sudo in: {locations}"
            result["remediation"] = (
                "Review and remove NOPASSWD entries from sudoers files:\n"
                "  sudo visudo\n"
                "  Remove NOPASSWD tags or add password requirement"
            )
        else:
            result["status"] = "PASS"
            result["finding"] = "No passwordless sudo entries found"

        self.checks.append(result)
        return result

    def run_all_checks(self) -> list[dict]:
        #run all user management security checks
        self.checks = []
        self.check_uid_zero()
        self.check_passwordless_sudo()
        return self.checks
