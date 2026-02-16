import subprocess
from datetime import datetime
from pathlib import Path

APT_HISTORY_LOG = "/var/log/apt/history.log"
UPDATE_THRESHOLD_DAYS = 7


class UpdatesChecker:
    #patch management security checks

    def __init__(self) -> None:
        #initialize UpdatesChecker with empty checks list
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

    def check_last_update(self) -> dict:
        #check when the system was last updated via apt
        result: dict = {
            "check_id": "recent_updates",
            "name": "System Updated Within 7 Days",
            "category": "Patch Management",
            "status": "PASS",
            "severity": "MEDIUM",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "N/A",
            "compliance_mappings": {
                "iso27001": ["A.12.6.1"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.IP-12"],
            },
        }

        try:
            content = Path(APT_HISTORY_LOG).read_text()
        except FileNotFoundError:
            result["status"] = "ERROR"
            result["finding"] = "APT history log not found; cannot determine last update"
            self.checks.append(result)
            return result
        except PermissionError:
            result["status"] = "ERROR"
            result["finding"] = "Permission denied reading APT history log"
            self.checks.append(result)
            return result

        # Find the most recent Start-Date entry
        last_date: datetime | None = None
        for line in content.splitlines():
            if line.startswith("Start-Date:"):
                date_str = line.split("Start-Date:")[1].strip()
                # Format: "2026-01-29  14:30:00"
                try:
                    last_date = datetime.strptime(date_str, "%Y-%m-%d  %H:%M:%S")
                except ValueError:
                    continue

        if last_date is None:
            result["status"] = "ERROR"
            result["finding"] = "No update entries found in APT history log"
            self.checks.append(result)
            return result

        days_ago = (datetime.now() - last_date).days
        date_display = last_date.strftime("%Y-%m-%d")
        result["finding"] = f"Last update was {days_ago} days ago ({date_display})"

        if days_ago <= UPDATE_THRESHOLD_DAYS:
            result["status"] = "PASS"
        else:
            result["status"] = "FAIL"
            result["remediation"] = (
                "Update system packages:\n"
                "  sudo apt update && sudo apt upgrade"
            )

        self.checks.append(result)
        return result

    def check_auto_updates(self) -> dict:
        #check if automatic updates are enabled via unattended-upgrades
        result: dict = {
            "check_id": "auto_updates_enabled",
            "name": "Automatic Updates Enabled",
            "category": "Patch Management",
            "status": "PASS",
            "severity": "MEDIUM",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "1.9",
            "compliance_mappings": {
                "iso27001": ["A.12.6.1"],
                "gdpr": [],
                "nist_csf": ["PR.IP-12"],
            },
        }

        stdout, stderr, rc = self._run_command(["dpkg", "-l", "unattended-upgrades"])

        if rc == 0 and "ii" in stdout:
            result["status"] = "PASS"
            result["finding"] = "unattended-upgrades package is installed"
        else:
            result["status"] = "FAIL"
            result["finding"] = "unattended-upgrades package is not installed"
            result["remediation"] = (
                "Enable automatic updates:\n"
                "  sudo apt install unattended-upgrades\n"
                "  sudo dpkg-reconfigure -plow unattended-upgrades"
            )

        self.checks.append(result)
        return result

    def run_all_checks(self) -> list[dict]:
        #run all patch management security checks
        self.checks = []
        self.check_last_update()
        self.check_auto_updates()
        return self.checks
