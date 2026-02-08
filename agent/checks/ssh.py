from pathlib import Path

SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"


class SSHChecker:
    #SSH configuration security checks

    def __init__(self) -> None:
        #initialize SSHChecker with default config path and empty checks list
        self.sshd_config_path: str = SSHD_CONFIG_PATH
        self.checks: list[dict] = []

    def _read_sshd_config(self) -> dict[str, str]:
        #read and parse the sshd_config file

        try:
            content = Path(self.sshd_config_path).read_text()
        except FileNotFoundError:
            return {"_error": "SSH config not found"}
        except PermissionError:
            return {"_error": "Permission denied"}

        config: dict[str, str] = {}
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                config[parts[0].lower()] = parts[1]

        return config

    def check_permit_root_login(self) -> dict:
        #check if SSH root login is disabled
        config = self._read_sshd_config()

        result: dict = {
            "check_id": "ssh_root_login",
            "name": "SSH Root Login Disabled",
            "category": "Remote Access",
            "status": "PASS",
            "severity": "HIGH",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "5.2.8",
            "compliance_mappings": {
                "iso27001": ["A.9.2.3", "A.9.4.3"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-4"],
            },
        }

        if "_error" in config:
            result["status"] = "ERROR"
            result["finding"] = config["_error"]
        else:
            value = config.get("permitrootlogin", "yes")
            if value.lower() == "no":
                result["status"] = "PASS"
                result["finding"] = "PermitRootLogin is set to 'no'"
            else:
                result["status"] = "FAIL"
                result["finding"] = f"PermitRootLogin is set to '{value}'"
                result["remediation"] = (
                    "Edit /etc/ssh/sshd_config:\n"
                    "  PermitRootLogin no\n"
                    "Then restart SSH: sudo systemctl restart sshd"
                )

        self.checks.append(result)
        return result

    def check_password_authentication(self) -> dict:
        #check if SSH password authentication is disabled for key auth
        config = self._read_sshd_config()

        result: dict = {
            "check_id": "ssh_password_auth",
            "name": "SSH Password Authentication Disabled",
            "category": "Remote Access",
            "status": "PASS",
            "severity": "MEDIUM",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "5.2.10",
            "compliance_mappings": {
                "iso27001": ["A.9.4.2"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-1"],
            },
        }

        if "_error" in config:
            result["status"] = "ERROR"
            result["finding"] = config["_error"]
        else:
            value = config.get("passwordauthentication", "yes")
            if value.lower() == "no":
                result["status"] = "PASS"
                result["finding"] = "PasswordAuthentication is set to 'no'"
            else:
                result["status"] = "FAIL"
                result["finding"] = f"PasswordAuthentication is set to '{value}'"
                result["remediation"] = (
                    "Edit /etc/ssh/sshd_config:\n"
                    "  PasswordAuthentication no\n"
                    "Ensure users have SSH keys configured before making this change"
                )

        self.checks.append(result)
        return result

    def check_protocol_version(self) -> dict:
        #check that SSH protocol version 2
        config = self._read_sshd_config()

        result: dict = {
            "check_id": "ssh_protocol_version",
            "name": "SSH Protocol Version 2",
            "category": "Remote Access",
            "status": "PASS",
            "severity": "HIGH",
            "finding": "",
            "remediation": None,
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "5.2.4",
            "compliance_mappings": {
                "iso27001": ["A.13.1.1"],
                "gdpr": [],
                "nist_csf": ["PR.DS-2"],
            },
        }

        if "_error" in config:
            result["status"] = "ERROR"
            result["finding"] = config["_error"]
        else:
            value = config.get("protocol")
            if value is None or value.strip() == "2":
                result["status"] = "PASS"
                result["finding"] = "SSH Protocol 2 is in use (default)"
            else:
                result["status"] = "FAIL"
                result["finding"] = f"SSH Protocol is set to '{value}'"
                result["remediation"] = (
                    "Edit /etc/ssh/sshd_config:\n"
                    "  Protocol 2"
                )

        self.checks.append(result)
        return result

    def run_all_checks(self) -> list[dict]:
        #run SSH security checks
        self.checks = []
        self.check_permit_root_login()
        self.check_password_authentication()
        self.check_protocol_version()
        return self.checks
