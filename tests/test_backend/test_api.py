import pytest

from backend import create_app, db
from backend.models import Finding, Scan


class TestConfig:
    SECRET_KEY = "test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TESTING = True


@pytest.fixture
def app():
    app = create_app(TestConfig)
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def init_database(app):
    with app.app_context():
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()


VALID_SCAN = {
    "agent_version": "1.0.0",
    "hostname": "test-server",
    "os_info": {"name": "Ubuntu", "version": "22.04"},
    "scan_timestamp": "2026-02-19T12:00:00",
    "privileged_mode": False,
    "checks": [
        {
            "check_id": "ssh_root_login",
            "name": "SSH Root Login Disabled",
            "category": "Remote Access",
            "status": "PASS",
            "severity": "HIGH",
            "finding": "PermitRootLogin is set to 'no'",
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
        },
        {
            "check_id": "firewall_enabled",
            "name": "Firewall Enabled",
            "category": "Network Security",
            "status": "FAIL",
            "severity": "HIGH",
            "finding": "No active firewall detected",
            "remediation": "Enable UFW firewall",
            "requires_privilege": False,
            "privilege_level": None,
            "skip_reason": None,
            "cis_reference": "3.5.1",
            "compliance_mappings": {
                "iso27001": ["A.13.1.1"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-5"],
            },
        },
    ],
    "summary": {"total": 2, "passed": 1, "failed": 1, "skipped": 0, "errors": 0},
}


class TestScanAPI:

    def test_health_check(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_submit_scan_success(self, client):
        resp = client.post("/api/scan-results", json=VALID_SCAN)
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["status"] == "success"
        assert "scan_id" in data
        assert data["message"] == "Scan results saved successfully"

    def test_submit_scan_missing_hostname(self, client):
        bad_data = {
            "scan_timestamp": "2026-02-19T12:00:00",
            "checks": [],
            "summary": {"total": 0, "passed": 0, "failed": 0, "skipped": 0, "errors": 0},
        }
        resp = client.post("/api/scan-results", json=bad_data)
        assert resp.status_code == 400
        assert "hostname" in resp.get_json()["message"]

    def test_submit_scan_missing_multiple_fields(self, client):
        resp = client.post("/api/scan-results", json={"hostname": "test"})
        assert resp.status_code == 400
        msg = resp.get_json()["message"]
        assert "scan_timestamp" in msg
        assert "checks" in msg
        assert "summary" in msg

    def test_submit_scan_no_json(self, client):
        resp = client.post("/api/scan-results", data="not json", content_type="text/plain")
        assert resp.status_code == 400

    def test_get_scans_empty(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        assert resp.get_json()["scans"] == []

    def test_get_scans_with_data(self, client):
        client.post("/api/scan-results", json=VALID_SCAN)

        resp = client.get("/api/scans")
        assert resp.status_code == 200
        scans = resp.get_json()["scans"]
        assert len(scans) == 1
        scan = scans[0]
        assert scan["hostname"] == "test-server"
        assert "scan_id" in scan
        assert "timestamp" in scan
        assert scan["summary"]["total"] == 2
        assert scan["summary"]["passed"] == 1
        assert scan["summary"]["failed"] == 1

    def test_get_scan_detail(self, client):
        resp = client.post("/api/scan-results", json=VALID_SCAN)
        scan_id = resp.get_json()["scan_id"]

        resp = client.get(f"/api/scans/{scan_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["scan_id"] == scan_id
        assert data["hostname"] == "test-server"
        assert data["os_info"]["name"] == "Ubuntu"
        assert data["os_info"]["version"] == "22.04"
        assert data["privileged_mode"] is False
        assert len(data["findings"]) == 2

        check_ids = [f["check_id"] for f in data["findings"]]
        assert "ssh_root_login" in check_ids
        assert "firewall_enabled" in check_ids

    def test_get_scan_detail_findings_complete(self, client):
        resp = client.post("/api/scan-results", json=VALID_SCAN)
        scan_id = resp.get_json()["scan_id"]

        resp = client.get(f"/api/scans/{scan_id}")
        finding = resp.get_json()["findings"][0]
        required_keys = [
            "check_id", "name", "category", "status", "severity",
            "finding", "remediation", "compliance_mappings",
        ]
        for key in required_keys:
            assert key in finding, f"Missing key: {key}"

    def test_get_scan_not_found(self, client):
        resp = client.get("/api/scans/nonexistent-id")
        assert resp.status_code == 404
        assert "not found" in resp.get_json()["message"].lower()
