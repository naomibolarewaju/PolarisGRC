import subprocess

REMEDIATION_UFW = (
    "Enable UFW firewall:\n"
    "  sudo apt install ufw\n"
    "  sudo ufw enable\n"
    "  sudo ufw allow ssh"
)


class FirewallChecker:
    #firewall configuration security checks

    def __init__(self) -> None:
        #initialize FirewallChecker with empty checks list
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

    def check_firewall_enabled(self) -> dict:
        #check if a firewall (UFW or iptables) is active
        result: dict = {
            "check_id": "firewall_enabled",
            "name": "Firewall Enabled",
            "category": "Network Security",
            "status": "FAIL",
            "severity": "HIGH",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "3.5.1",
            "compliance_mappings": {
                "iso27001": ["A.13.1.1"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-5"],
            },
        }

        #try UFW first
        stdout, stderr, rc = self._run_command(["ufw", "status"])

        if "permission denied" in stderr.lower():
            result["status"] = "SKIPPED"
            result["finding"] = "Insufficient privileges to check firewall status"
            result["requires_privilege"] = True
            result["privilege_level"] = "root"
            result["skip_reason"] = "Requires root/sudo to check firewall status"
            self.checks.append(result)
            return result

        if rc == 0 and "Status: active" in stdout:
            result["status"] = "PASS"
            result["finding"] = "UFW firewall is active"
            self.checks.append(result)
            return result

        #fall back to iptables
        stdout, stderr, rc = self._run_command(["iptables", "-L", "-n"])

        if "permission denied" in stderr.lower():
            result["status"] = "SKIPPED"
            result["finding"] = "Insufficient privileges to check firewall status"
            result["requires_privilege"] = True
            result["privilege_level"] = "root"
            result["skip_reason"] = "Requires root/sudo to check firewall status"
            self.checks.append(result)
            return result

        if rc == 0 and len(stdout.splitlines()) > 8:
            result["status"] = "PASS"
            result["finding"] = "iptables firewall has active rules"
            self.checks.append(result)
            return result

        result["status"] = "FAIL"
        result["finding"] = "No active firewall detected"
        result["remediation"] = REMEDIATION_UFW
        self.checks.append(result)
        return result

    def run_all_checks(self) -> list[dict]:
        #run all firewall security checks.
        self.checks = []
        self.check_firewall_enabled()
        return self.checks
