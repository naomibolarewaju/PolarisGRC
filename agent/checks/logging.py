import subprocess


class LoggingChecker:
    #audit logging security checks

    def __init__(self) -> None:
        #initialize LoggingChecker with empty checks list
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

    def check_auditd_enabled(self) -> dict:
        #checks if auditd (Linux Audit Framework) is installed and actively running
        #note: check will always fail on WSL2 due to kernel limitations, test on VM
        result: dict = {
            "check_id": "auditd_enabled",
            "name": "Auditd Installed and Active",
            "category": "Logging & Auditing",
            "status": "PASS",
            "severity": "HIGH",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "4.1.1",
            "compliance_mappings": {
                "iso27001": ["A.12.4.1", "A.12.4.3"],
                "gdpr": ["Article 32(1)(d)", "Article 32(2)"],
                "nist_csf": ["PR.PT-1", "DE.CM-1"],
            },
        }

        stdout, stderr, rc = self._run_command(["systemctl", "is-active", "auditd"])

        if "permission denied" in stderr.lower():
            result["status"] = "SKIPPED"
            result["finding"] = "Insufficient privileges to check auditd status"
            result["requires_privilege"] = True
            result["privilege_level"] = "root"
            result["skip_reason"] = "Requires root/sudo to check service status"
        elif rc == 0 and stdout.strip() == "active":
            result["status"] = "PASS"
            result["finding"] = "Auditd is active"
        else:
            result["status"] = "FAIL"
            result["finding"] = "Auditd is not running/installed"
            result["remediation"] = (
                "Install and enable auditd:\n"
                "  sudo apt install auditd\n"
                "  sudo systemctl enable auditd\n"
                "  sudo systemctl start auditd"
            )

        self.checks.append(result)
        return result

    def run_all_checks(self) -> list[dict]:
        #run all audit logging security checks
        self.checks = []
        self.check_auditd_enabled()
        return self.checks
