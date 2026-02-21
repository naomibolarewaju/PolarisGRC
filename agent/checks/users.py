import subprocess
from datetime import datetime, timedelta
from pathlib import Path

PASSWD_PATH = "/etc/passwd"
SUDOERS_PATH = "/etc/sudoers"
SUDOERS_DIR = "/etc/sudoers.d"
LASTLOG_INACTIVE_DAYS = 90
MIN_REAL_USER_UID = 1000


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

    def check_inactive_users(self) -> dict:
        #check for real user accounts (UID >= 1000) that haven't logged in for 90+ days
        result: dict = {
            "check_id": "inactive_users",
            "name": "Inactive User Accounts",
            "category": "User Management",
            "status": "PASS",
            "severity": "MEDIUM",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "6.2.14",
            "compliance_mappings": {
                "iso27001": ["A.9.2.5", "A.9.2.6"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-1"],
            },
        }

        _REMEDIATION = (
            "Review and disable/remove inactive accounts:\n"
            "  sudo usermod -L <username>  # Lock account\n"
            "  sudo userdel <username>     # Delete account\n"
            "\n"
            "Or set account expiration:\n"
            "  sudo chage -E $(date -d '+30 days' +%Y-%m-%d) <username>"
        )

        # Step 1: read real users from /etc/passwd (UID >= MIN_REAL_USER_UID)
        try:
            passwd_text = Path(PASSWD_PATH).read_text()
        except FileNotFoundError:
            result["status"] = "ERROR"
            result["finding"] = "/etc/passwd not found"
            self.checks.append(result)
            return result
        except PermissionError:
            result["status"] = "ERROR"
            result["finding"] = "Permission denied reading /etc/passwd"
            self.checks.append(result)
            return result

        real_users: set[str] = set()
        for line in passwd_text.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 3:
                try:
                    if int(parts[2]) >= MIN_REAL_USER_UID:
                        real_users.add(parts[0])
                except ValueError:
                    continue

        if not real_users:
            result["status"] = "PASS"
            result["finding"] = "No regular user accounts found"
            self.checks.append(result)
            return result

        # Step 2: run lastlog to get last login times
        stdout, stderr, returncode = self._run_command(["lastlog"])
        if returncode != 0:
            reason = (
                "lastlog command not available"
                if stderr == "Command not found"
                else "Unable to determine last login times"
            )
            result["status"] = "SKIPPED"
            result["skip_reason"] = reason
            result["finding"] = "Unable to determine last login times"
            self.checks.append(result)
            return result

        # Step 3: parse lastlog output
        # Format: "username  port  from  Mon Jan 27 12:00:00 +0000 2026"
        # or:     "username                **Never logged in**"
        last_logins: dict[str, datetime | None] = {}
        cutoff = datetime.now() - timedelta(days=LASTLOG_INACTIVE_DAYS)

        for line in stdout.splitlines()[1:]:  # skip header
            parts = line.split()
            if not parts or parts[0] not in real_users:
                continue

            username = parts[0]

            if "**Never logged in**" in line:
                last_logins[username] = None
                continue

            # Try to parse the trailing date tokens:
            # with timezone: "Mon Jan 27 12:00:00 +0000 2026"  (last 6 tokens)
            # without:       "Mon Jan 27 12:00:00 2026"         (last 5 tokens)
            login_time: datetime | None = None
            for n_tokens, fmt in (
                (6, "%a %b %d %H:%M:%S %z %Y"),
                (5, "%a %b %d %H:%M:%S %Y"),
            ):
                if len(parts) > n_tokens:  # username occupies parts[0]
                    try:
                        parsed = datetime.strptime(" ".join(parts[-n_tokens:]), fmt)
                        login_time = parsed.replace(tzinfo=None)
                        break
                    except ValueError:
                        continue

            if login_time is not None:
                last_logins[username] = login_time

        # Step 4: classify each real user
        inactive: list[str] = []
        never_logged_in: list[str] = []

        for username in real_users:
            if username not in last_logins:
                never_logged_in.append(username)
            elif last_logins[username] is None:
                never_logged_in.append(username)
            elif last_logins[username] < cutoff:
                inactive.append(username)

        all_inactive = sorted(inactive) + sorted(never_logged_in)

        if all_inactive:
            result["status"] = "FAIL"
            names = ", ".join(all_inactive)
            result["finding"] = (
                f"Found {len(all_inactive)} inactive user account(s): {names}\n"
                f"These accounts have not logged in for {LASTLOG_INACTIVE_DAYS}+ days"
            )
            result["remediation"] = _REMEDIATION
        else:
            result["status"] = "PASS"
            result["finding"] = "No inactive user accounts found"

        self.checks.append(result)
        return result

    def run_all_checks(self) -> list[dict]:
        #run all user management security checks
        self.checks = []
        self.check_uid_zero()
        self.check_passwordless_sudo()
        self.check_inactive_users()
        return self.checks
