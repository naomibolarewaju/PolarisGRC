import uuid
from datetime import datetime

from backend import db


class Scan(db.Model):
    #stores scan results submitted by the audit agent
    __tablename__ = "scans"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = db.Column(db.String(255), nullable=False)
    agent_version = db.Column(db.String(20))
    os_name = db.Column(db.String(50))
    os_version = db.Column(db.String(50))
    scan_timestamp = db.Column(db.DateTime, nullable=False)
    privileged_mode = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    total_checks = db.Column(db.Integer)
    passed_checks = db.Column(db.Integer)
    failed_checks = db.Column(db.Integer)
    skipped_checks = db.Column(db.Integer)
    error_checks = db.Column(db.Integer)

    findings = db.relationship("Finding", backref="scan", lazy=True, cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan {self.id[:8]} {self.hostname} {self.scan_timestamp}>"


class Finding(db.Model):
    #stores individual check results linked to a scan
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.String(36), db.ForeignKey("scans.id"), nullable=False)

    check_id = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100))

    status = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.String(20))
    finding = db.Column(db.Text)
    remediation = db.Column(db.Text)

    requires_privilege = db.Column(db.Boolean, default=False)
    privilege_level = db.Column(db.String(50))
    skip_reason = db.Column(db.Text)

    cis_reference = db.Column(db.String(20))
    compliance_mappings = db.Column(db.JSON)

    def __repr__(self) -> str:
        return f"<Finding {self.check_id} {self.status}>"
