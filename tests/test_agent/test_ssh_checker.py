import pytest
from unittest.mock import patch

from agent.checks.ssh import SSHChecker


MOCK_CONFIG_SECURE = (
    "PermitRootLogin no\n"
    "PasswordAuthentication no\n"
    "Protocol 2\n"
)

MOCK_CONFIG_INSECURE = (
    "PermitRootLogin yes\n"
    "PasswordAuthentication yes\n"
    "Protocol 1\n"
)


class TestSSHChecker:

    def test_permit_root_login_pass(self):
        with patch("pathlib.Path.read_text", return_value=MOCK_CONFIG_SECURE):
            checker = SSHChecker()
            result = checker.check_permit_root_login()

            assert result["check_id"] == "ssh_root_login"
            assert result["status"] == "PASS"
            assert result["severity"] == "HIGH"
            assert result["remediation"] is None

    def test_permit_root_login_fail(self):
        with patch("pathlib.Path.read_text", return_value=MOCK_CONFIG_INSECURE):
            checker = SSHChecker()
            result = checker.check_permit_root_login()

            assert result["status"] == "FAIL"
            assert result["remediation"] is not None
            assert "yes" in result["finding"].lower()

    def test_permit_root_login_missing_key(self):
        mock_config = "Port 22\n"
        with patch("pathlib.Path.read_text", return_value=mock_config):
            checker = SSHChecker()
            result = checker.check_permit_root_login()

            assert result["status"] == "FAIL"
            assert "yes" in result["finding"].lower()

    def test_permit_root_login_file_not_found(self):
        with patch("pathlib.Path.read_text", side_effect=FileNotFoundError()):
            checker = SSHChecker()
            result = checker.check_permit_root_login()

            assert result["status"] == "ERROR"
            assert "not found" in result["finding"].lower()

    def test_permit_root_login_permission_denied(self):
        with patch("pathlib.Path.read_text", side_effect=PermissionError()):
            checker = SSHChecker()
            result = checker.check_permit_root_login()

            assert result["status"] == "ERROR"
            assert "permission" in result["finding"].lower()

    def test_password_auth_pass(self):
        with patch("pathlib.Path.read_text", return_value=MOCK_CONFIG_SECURE):
            checker = SSHChecker()
            result = checker.check_password_authentication()

            assert result["check_id"] == "ssh_password_auth"
            assert result["status"] == "PASS"
            assert result["remediation"] is None

    def test_password_auth_fail(self):
        with patch("pathlib.Path.read_text", return_value=MOCK_CONFIG_INSECURE):
            checker = SSHChecker()
            result = checker.check_password_authentication()

            assert result["status"] == "FAIL"
            assert result["remediation"] is not None

    def test_protocol_version_pass(self):
        with patch("pathlib.Path.read_text", return_value=MOCK_CONFIG_SECURE):
            checker = SSHChecker()
            result = checker.check_protocol_version()

            assert result["check_id"] == "ssh_protocol_version"
            assert result["status"] == "PASS"

    def test_protocol_version_fail(self):
        with patch("pathlib.Path.read_text", return_value=MOCK_CONFIG_INSECURE):
            checker = SSHChecker()
            result = checker.check_protocol_version()

            assert result["status"] == "FAIL"
            assert "1" in result["finding"]

    def test_protocol_version_default_pass(self):
        mock_config = "Port 22\n"
        with patch("pathlib.Path.read_text", return_value=mock_config):
            checker = SSHChecker()
            result = checker.check_protocol_version()

            assert result["status"] == "PASS"
            assert "default" in result["finding"].lower()

    def test_run_all_checks(self):
        with patch("pathlib.Path.read_text", return_value=MOCK_CONFIG_SECURE):
            checker = SSHChecker()
            results = checker.run_all_checks()

            assert isinstance(results, list)
            assert len(results) == 3
            check_ids = [r["check_id"] for r in results]
            assert "ssh_root_login" in check_ids
            assert "ssh_password_auth" in check_ids
            assert "ssh_protocol_version" in check_ids

    def test_result_has_all_required_fields(self):
        required_fields = [
            "check_id", "name", "category", "status", "severity",
            "finding", "remediation", "requires_privilege", "privilege_level",
            "skip_reason", "cis_reference", "compliance_mappings",
        ]
        with patch("pathlib.Path.read_text", return_value=MOCK_CONFIG_SECURE):
            checker = SSHChecker()
            result = checker.check_permit_root_login()

            for field in required_fields:
                assert field in result, f"Missing field: {field}"

    def test_compliance_mappings_structure(self):
        with patch("pathlib.Path.read_text", return_value=MOCK_CONFIG_SECURE):
            checker = SSHChecker()
            result = checker.check_permit_root_login()

            mappings = result["compliance_mappings"]
            assert "iso27001" in mappings
            assert "gdpr" in mappings
            assert "nist_csf" in mappings
            assert isinstance(mappings["iso27001"], list)
