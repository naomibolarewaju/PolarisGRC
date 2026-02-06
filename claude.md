# PolarisGRC - Project Context for Claude Code

**Version:** 1.0  
**Last Updated:** January 29, 2026  
**Project Type:** Final Year Computer Science Project  
**Submission Deadline:** April 2026

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture & Design](#architecture--design)
3. [Technology Stack](#technology-stack)
4. [File Structure](#file-structure)
5. [Data Schemas & Contracts](#data-schemas--contracts)
6. [Design Patterns & Principles](#design-patterns--principles)
7. [Code Conventions](#code-conventions)
8. [Testing Guidelines](#testing-guidelines)
9. [Important Constraints](#important-constraints)

---

## Project Overview

### What is PolarisGRC?

PolarisGRC (Governance, Risk and Compliance) is a cybersecurity auditing and governance platform designed to help small and medium-sized enterprises (SMEs) assess their security posture, understand compliance obligations, and automatically generate actionable reports.

### The Problem

Many SMEs in Ireland and the EU struggle to implement technical and organizational controls required by frameworks like ISO 27001 and GDPR. Existing GRC platforms are often:
- Too expensive for small organizations
- Complex and require dedicated compliance teams
- Focus on documentation rather than actual system verification

### The Solution

PolarisGRC provides:
1. **Automated Security Auditing** - A local agent that scans Linux systems for misconfigurations
2. **Compliance Mapping** - Links technical findings to ISO 27001, GDPR, and NIST CSF controls
3. **Risk Assessment** - Combines technical findings with organizational context
4. **Policy Generation** - Auto-generates security policies based on scan results
5. **Dashboard** - User-friendly interface for viewing results and tracking compliance

### Key Differentiators

1. **Technical Verification** - Derives compliance insights from actual system configurations, not self-reported questionnaires
2. **SME-Focused** - Designed for organizations without dedicated cybersecurity teams
3. **Explainability** - "Explain This Control" feature provides plain English explanations
4. **Affordable** - Open-source alternative to enterprise GRC suites

### Target Audience

- Small to medium-sized enterprises (10-250 employees)
- Organizations in Ireland and EU
- Companies required to demonstrate GDPR compliance
- Businesses pursuing ISO 27001 certification

---

## Architecture & Design

### High-Level Architecture

```
┌─────────────────┐
│  Target System  │ (Linux server/VM)
│   (Ubuntu/     │
│    Debian)      │
└────────┬────────┘
         │
         │ Local scan
         ▼
┌─────────────────┐
│  Audit Agent    │ (Python CLI)
│  - Checks SSH   │
│  - Checks users │
│  - Checks FW    │
│  - Outputs JSON │
└────────┬────────┘
         │
         │ HTTPS POST /api/scan-results
         │ Bearer Token Auth
         ▼
┌─────────────────┐
│  Flask Backend  │
│  - REST API     │
│  - Risk Engine  │
│  - Compliance   │
│  - PDF Reports  │
└────────┬────────┘
         │
         │ SQLAlchemy ORM
         ▼
┌─────────────────┐
│  SQLite DB      │
│  - Scans        │
│  - Findings     │
│  - Users        │
└─────────────────┘
         │
         │ Template Rendering
         ▼
┌─────────────────┐
│  Web Dashboard  │ (HTML/CSS/JS)
│  - View scans   │
│  - Compliance   │
│  - Download PDF │
└─────────────────┘
```

### Component Breakdown

#### 1. Audit Agent (Python CLI)
- Runs locally on target Linux systems
- Performs read-only security configuration checks
- Outputs structured JSON results
- Can run with or without elevated privileges

#### 2. Backend (Flask)
- REST API for receiving scan data
- Business logic for risk scoring and compliance mapping
- PDF report generation
- User authentication and authorization

#### 3. Database (SQLite)
- Stores scan results and findings
- User accounts and agent tokens
- Historical compliance data

#### 4. Dashboard (Web UI)
- Displays scan results and compliance status
- Provides remediation guidance
- Generates downloadable reports
- Dark mode support

---

## Technology Stack

### Core Technologies

**Language:** Python 3.11+

**Backend Framework:** Flask 3.0+
- Flask-SQLAlchemy for ORM
- Flask-Login for authentication
- Jinja2 for templating

**Database:** SQLite 3
- Development and production
- Persistent volume for deployment
- Can migrate to PostgreSQL if needed

**CLI Framework:** Click 8.1+
- Declarative command-line interface
- Automatic help text generation
- Type validation

**PDF Generation:** WeasyPrint
- HTML to PDF conversion
- CSS styling support
- Fallback: Markdown generation

**Frontend:**
- Bootstrap 5 (CSS framework)
- Vanilla JavaScript (no heavy frameworks)
- Chart.js (optional for historical trends)

### Development Environment

**OS:** Windows (development), Linux (testing/target)
- Windows-specific paths and commands
- WSL2 or VirtualBox for Linux testing

**Version Control:** Git + GitHub

**Testing:** pytest
- Unit tests for agent checks
- Integration tests for API endpoints
- Mocking for file system operations

---

## File Structure

```
PolarisGRC/
├── claude.md                      # This file - project context
├── README.md                      # Project documentation
├── requirements.txt               # Python dependencies
├── .gitignore                     # Git ignore patterns
├── .env.example                   # Environment variables template
│
├── agent/                         # Audit agent (CLI tool)
│   ├── __init__.py
│   ├── cli.py                     # Click CLI entry point
│   ├── core.py                    # Orchestration logic
│   ├── utils.py                   # Helper functions
│   ├── checks/                    # Check modules
│   │   ├── __init__.py
│   │   ├── ssh.py                 # SSH configuration checks
│   │   ├── firewall.py            # Firewall checks
│   │   ├── users.py               # User/privilege checks
│   │   ├── passwords.py           # Password policy checks
│   │   ├── permissions.py         # File permission checks
│   │   ├── updates.py             # Patch management checks
│   │   ├── logging.py             # Audit logging checks
│   │   └── docker.py              # Docker security (optional)
│   └── config.yaml.example        # Agent configuration template
│
├── backend/                       # Flask backend
│   ├── __init__.py                # App factory
│   ├── config.py                  # Configuration management
│   ├── models.py                  # SQLAlchemy models
│   ├── routes/                    # Flask blueprints
│   │   ├── __init__.py
│   │   ├── api.py                 # REST API endpoints
│   │   └── dashboard.py           # Web UI routes
│   ├── services/                  # Business logic
│   │   ├── __init__.py
│   │   ├── scan_service.py        # Scan processing
│   │   ├── risk_service.py        # Risk scoring
│   │   ├── compliance_service.py  # Compliance mapping
│   │   └── report_service.py      # PDF generation
│   ├── templates/                 # Jinja2 templates
│   │   ├── base.html              # Base template
│   │   ├── dashboard.html         # Main dashboard
│   │   ├── scan_detail.html       # Scan details
│   │   ├── control_detail.html    # Control explanation
│   │   └── login.html             # Authentication
│   └── static/                    # Static assets
│       ├── css/
│       │   └── style.css          # Custom styles
│       └── js/
│           └── main.js            # Dashboard interactions
│
├── data/                          # Static reference data
│   ├── compliance_mappings.json   # Check → framework mappings
│   └── control_descriptions.json  # Framework → control details
│
├── policies/                      # Policy templates
│   ├── access_control.md.j2       # Access Control Policy
│   ├── acceptable_use.md.j2       # Acceptable Use Policy
│   └── incident_response.md.j2    # Incident Response Plan
│
├── tests/                         # Test suite
│   ├── __init__.py
│   ├── test_agent/                # Agent tests
│   │   ├── test_ssh_checker.py
│   │   ├── test_firewall_checker.py
│   │   └── test_user_checker.py
│   ├── test_backend/              # Backend tests
│   │   ├── test_api.py
│   │   ├── test_risk_service.py
│   │   └── test_compliance_service.py
│   └── fixtures/                  # Test data
│       └── sample_scans.json
│
└── docs/                          # Documentation
    ├── IMPLEMENTATION_GUIDE.md    # Step-by-step build guide
    └── architecture.md            # Architecture details
```

---

## Data Schemas & Contracts

### Agent Check Output Format

Every check performed by the agent MUST return a dict with this exact structure:

```python
{
    # Identification
    "check_id": str,              # Unique identifier (e.g., "ssh_root_login")
    "name": str,                  # Human-readable name
    "category": str,              # Group (e.g., "Remote Access", "Network Security")
    
    # Result
    "status": str,                # "PASS" | "FAIL" | "SKIPPED" | "ERROR"
    "severity": str,              # "HIGH" | "MEDIUM" | "LOW"
    "finding": str,               # Description of current state
    "remediation": str | None,    # How to fix (null if passed)
    
    # Privilege handling
    "requires_privilege": bool,   # Does this check need elevated privileges?
    "privilege_level": str | None,  # "root" | "docker_group" | "sudo" | null
    "skip_reason": str | None,    # Why skipped (null if not skipped)
    
    # Compliance
    "cis_reference": str,         # CIS Benchmark reference (e.g., "5.2.8")
    "compliance_mappings": {      # Framework mappings
        "iso27001": list[str],    # e.g., ["A.9.2.3", "A.9.4.3"]
        "gdpr": list[str],        # e.g., ["Article 32(1)(b)"]
        "nist_csf": list[str]     # e.g., ["PR.AC-4"]
    }
}
```

**Example:**

```python
{
    "check_id": "ssh_root_login",
    "name": "SSH Root Login Disabled",
    "category": "Remote Access",
    "status": "FAIL",
    "severity": "HIGH",
    "finding": "PermitRootLogin is set to 'yes'",
    "remediation": "Edit /etc/ssh/sshd_config:\n  PermitRootLogin no\nThen restart SSH: sudo systemctl restart sshd",
    "requires_privilege": false,
    "privilege_level": null,
    "skip_reason": null,
    "cis_reference": "5.2.8",
    "compliance_mappings": {
        "iso27001": ["A.9.2.3", "A.9.4.3"],
        "gdpr": ["Article 32(1)(b)"],
        "nist_csf": ["PR.AC-4"]
    }
}
```

### Agent Scan Output Format

The complete scan output from the agent:

```python
{
    "agent_version": str,         # e.g., "1.0.0"
    "hostname": str,              # Target system hostname
    "os_info": {                  # Operating system details
        "name": str,              # e.g., "Ubuntu"
        "version": str,           # e.g., "22.04"
        "kernel": str             # e.g., "5.15.0-generic"
    },
    "scan_timestamp": str,        # ISO 8601 format
    "privileged_mode": bool,      # Was scan run with elevated privileges?
    "checks": list[dict],         # Array of check results (format above)
    "summary": {
        "total": int,
        "passed": int,
        "failed": int,
        "skipped": int,
        "errors": int
    }
}
```

### API Endpoints

#### POST /api/scan-results

**Request Headers:**
```
Authorization: Bearer <agent_token>
Content-Type: application/json
```

**Request Body:**
```json
{
    "agent_version": "1.0.0",
    "hostname": "web-server-01",
    "os_info": {
        "name": "Ubuntu",
        "version": "22.04",
        "kernel": "5.15.0-generic"
    },
    "scan_timestamp": "2026-01-29T14:30:00Z",
    "privileged_mode": true,
    "checks": [
        {/* check result object */}
    ],
    "summary": {
        "total": 15,
        "passed": 10,
        "failed": 3,
        "skipped": 2,
        "errors": 0
    }
}
```

**Response (201 Created):**
```json
{
    "scan_id": "uuid-string",
    "status": "success",
    "message": "Scan results saved successfully"
}
```

#### GET /api/scans

**Response (200 OK):**
```json
{
    "scans": [
        {
            "scan_id": "uuid",
            "hostname": "web-server-01",
            "timestamp": "2026-01-29T14:30:00Z",
            "summary": {
                "total": 15,
                "passed": 10,
                "failed": 3,
                "skipped": 2
            },
            "risk_score": 65.5
        }
    ]
}
```

#### GET /api/scans/{scan_id}

**Response (200 OK):**
```json
{
    "scan_id": "uuid",
    "hostname": "web-server-01",
    "timestamp": "2026-01-29T14:30:00Z",
    "findings": [
        {/* check result objects */}
    ],
    "compliance_summary": {
        "iso27001": {
            "total_controls": 20,
            "satisfied": 15,
            "failed": 5,
            "coverage_percent": 75.0
        },
        "gdpr": {/* similar structure */},
        "nist_csf": {/* similar structure */}
    },
    "risk_score": 65.5
}
```

### Database Models

#### Scan Model

```python
class Scan(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # UUID
    hostname = db.Column(db.String(255), nullable=False)
    agent_version = db.Column(db.String(20))
    os_name = db.Column(db.String(50))
    os_version = db.Column(db.String(50))
    scan_timestamp = db.Column(db.DateTime, nullable=False)
    privileged_mode = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Summary counts
    total_checks = db.Column(db.Integer)
    passed_checks = db.Column(db.Integer)
    failed_checks = db.Column(db.Integer)
    skipped_checks = db.Column(db.Integer)
    error_checks = db.Column(db.Integer)
    
    # Relationships
    findings = db.relationship('Finding', backref='scan', lazy=True, cascade='all, delete-orphan')
```

#### Finding Model

```python
class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scan.id'), nullable=False)
    
    # Check identification
    check_id = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100))
    
    # Result
    status = db.Column(db.String(20), nullable=False)  # PASS/FAIL/SKIPPED/ERROR
    severity = db.Column(db.String(20))  # HIGH/MEDIUM/LOW
    finding = db.Column(db.Text)
    remediation = db.Column(db.Text)
    
    # Privilege info
    requires_privilege = db.Column(db.Boolean, default=False)
    privilege_level = db.Column(db.String(50))
    skip_reason = db.Column(db.Text)
    
    # Compliance
    cis_reference = db.Column(db.String(20))
    compliance_mappings = db.Column(db.JSON)  # Store as JSON
```

#### User Model (for authentication)

```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Agent tokens for this user
    agent_tokens = db.relationship('AgentToken', backref='user', lazy=True)
```

#### AgentToken Model

```python
class AgentToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(255))  # e.g., "web-server-01"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    revoked = db.Column(db.Boolean, default=False)
```

---

## Design Patterns & Principles

### 1. Modular Check Architecture

**Pattern:** Each security check is a separate class with standardized interface

**Implementation:**
```python
# Each checker class follows this pattern
class SSHChecker:
    def __init__(self):
        self.checks = []
    
    def run_all_checks(self) -> list[dict]:
        """Run all checks and return results"""
        self.checks = []
        self.check_permit_root_login()
        self.check_password_authentication()
        self.check_protocol_version()
        return self.checks
    
    def check_permit_root_login(self):
        """Individual check method"""
        # Perform check
        # Append result dict to self.checks
```

**Benefits:**
- Easy to add new checks (just add new method)
- Easy to test (test each method independently)
- Easy to disable checks (skip method call)

### 2. Privilege Handling

**Pattern:** Graceful degradation for checks requiring elevated privileges

**Implementation:**
```python
# Default behavior: mark as SKIPPED if privilege needed
if requires_privilege and not privileged_mode:
    result["status"] = "SKIPPED"
    result["skip_reason"] = f"Requires {privilege_level} privileges"
    result["finding"] = None
```

**Agent CLI:**
```bash
# Normal run (unprivileged checks only)
python agent/cli.py

# Privileged run (all checks)
sudo python agent/cli.py --privileged

# Show what needs privileges
python agent/cli.py --show-privileged
```

**Dashboard Display:**
- Show skipped checks with explanation
- Provide instructions: "Run with --privileged flag for complete audit"

### 3. Error Handling

**Pattern:** Never crash on errors; report errors as check results

**Implementation:**
```python
try:
    with open('/etc/ssh/sshd_config', 'r') as f:
        config = f.read()
except FileNotFoundError:
    return {
        "status": "ERROR",
        "finding": "SSH config file not found",
        "remediation": "Ensure OpenSSH server is installed"
    }
except PermissionError:
    return {
        "status": "ERROR",
        "finding": "Permission denied reading SSH config",
        "remediation": "Run with elevated privileges"
    }
```

**Never use:**
- Bare `except:` clauses
- `sys.exit()` in library code (only in CLI entry point)
- Uncaught exceptions that crash the agent

### 4. Compliance Mapping

**Pattern:** Separation of check logic from compliance mappings

**Implementation:**
```python
# Load mappings from external JSON file
import json
from pathlib import Path

mappings_file = Path(__file__).parent.parent / "data" / "compliance_mappings.json"
with open(mappings_file) as f:
    COMPLIANCE_MAPPINGS = json.load(f)

# Add mappings to check result
result["compliance_mappings"] = COMPLIANCE_MAPPINGS.get(check_id, {})
```

**Benefits:**
- Easy to update mappings without changing code
- Can be reviewed by non-developers
- Supports multiple framework versions

**Important Note:**
Technical checks provide **evidence toward** compliance, not full compliance. One check may partially satisfy multiple controls. Document this limitation clearly.

### 5. Flask Blueprint Organization

**Pattern:** Separation of concerns using blueprints

**Structure:**
```python
# backend/routes/api.py - REST API
api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/scan-results', methods=['POST'])
def submit_scan():
    # API logic here
    pass

# backend/routes/dashboard.py - Web UI
dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def index():
    # Render template
    pass
```

**App Factory:**
```python
# backend/__init__.py
def create_app():
    app = Flask(__name__)
    app.config.from_object('backend.config.Config')
    
    db.init_app(app)
    
    # Register blueprints
    from backend.routes.api import api_bp
    from backend.routes.dashboard import dashboard_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)
    
    return app
```

### 6. Service Layer Pattern

**Pattern:** Business logic separated from routes

**Implementation:**
```python
# backend/services/risk_service.py
class RiskService:
    @staticmethod
    def calculate_risk_score(findings: list[dict], context: dict) -> float:
        """Calculate risk score from findings and org context"""
        # Risk calculation logic
        pass

# backend/routes/api.py
from backend.services.risk_service import RiskService

@api_bp.route('/scan-results', methods=['POST'])
def submit_scan():
    data = request.get_json()
    
    # Use service for business logic
    risk_score = RiskService.calculate_risk_score(
        data['checks'], 
        get_org_context()
    )
    
    # Save to database
    # Return response
```

**Benefits:**
- Testable business logic (without Flask context)
- Reusable across different routes
- Clear separation of concerns

### 7. Read-Only Operations

**Pattern:** Agent never modifies system state

**Implementation:**
- All checks are READ operations only
- No `--fix` flag in MVP (document as future enhancement)
- No automatic remediation
- Provide manual remediation instructions instead

**Security Benefits:**
- Reduced risk of running as root
- Audit trail is passive observation
- Users maintain control over their systems

---

## Code Conventions

### Python Style

**Follow PEP 8:**
- 4 spaces for indentation
- Max line length: 100 characters (not strict 79)
- Snake_case for functions and variables
- PascalCase for classes
- UPPER_CASE for constants

**Type Hints:**
```python
def check_permit_root_login(self) -> dict:
    """Check if root login via SSH is disabled"""
    config: dict[str, str] = self._read_sshd_config()
    # ...
```

**Docstrings:**
```python
def calculate_risk_score(findings: list[dict], context: dict) -> float:
    """Calculate organizational risk score.
    
    Args:
        findings: List of check result dicts
        context: Organization context (size, industry, data types)
    
    Returns:
        Risk score between 0-100 (higher = more risk)
    
    Example:
        >>> risk_score = calculate_risk_score(findings, {"size": "small"})
        >>> print(risk_score)
        65.5
    """
```

### File Operations

**Use pathlib.Path:**
```python
from pathlib import Path

# Good
config_path = Path("/etc/ssh/sshd_config")
if config_path.exists():
    content = config_path.read_text()

# Avoid
import os
if os.path.exists("/etc/ssh/sshd_config"):
    with open("/etc/ssh/sshd_config") as f:
        content = f.read()
```

### Error Handling

**Specific exceptions:**
```python
# Good
try:
    config = Path(sshd_config_path).read_text()
except FileNotFoundError:
    return {"_error": "Config file not found"}
except PermissionError:
    return {"_error": "Permission denied"}

# Bad
try:
    config = Path(sshd_config_path).read_text()
except Exception as e:
    return {"_error": str(e)}
```

### Logging

**Use Python logging module:**
```python
import logging

logger = logging.getLogger(__name__)

# In code
logger.info(f"Starting scan on {hostname}")
logger.warning(f"Check {check_id} requires elevated privileges")
logger.error(f"Failed to read config: {e}")
```

**Log levels:**
- `DEBUG`: Detailed diagnostic info
- `INFO`: Confirmation things are working
- `WARNING`: Something unexpected but handled
- `ERROR`: Serious problem, operation failed

### Constants

**Define at module level:**
```python
# agent/checks/ssh.py
SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
DEFAULT_SSH_PORT = 22

class SSHChecker:
    def __init__(self):
        self.config_path = SSHD_CONFIG_PATH
```

### Git Commits

**Format:**
```
type(scope): Short description

Longer explanation if needed

Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, missing semicolons, etc.
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Build process, dependencies

**Examples:**
```
feat(agent): Add SSH password authentication check

Implements check for PasswordAuthentication setting in sshd_config.
Maps to ISO 27001 A.9.4.2 and CIS 5.2.10.

fix(api): Handle missing hostname in scan submission

Added validation to ensure hostname is present in request body.
Returns 400 Bad Request with clear error message.
```

---

## Testing Guidelines

### Test Framework

**Use pytest:**
```bash
# Install
pip install pytest pytest-cov

# Run tests
pytest

# Run with coverage
pytest --cov=agent --cov=backend
```

### Test Organization

**Mirror source structure:**
```
tests/
├── test_agent/
│   ├── test_ssh_checker.py
│   ├── test_firewall_checker.py
│   └── test_user_checker.py
└── test_backend/
    ├── test_api.py
    └── test_services/
        ├── test_risk_service.py
        └── test_compliance_service.py
```

### Agent Tests (Unit Tests)

**Mock file system operations:**
```python
# tests/test_agent/test_ssh_checker.py
import pytest
from unittest.mock import mock_open, patch
from agent.checks.ssh import SSHChecker

def test_permit_root_login_disabled():
    """Test SSH root login check when properly configured"""
    mock_config = "PermitRootLogin no\nPort 22\n"
    
    with patch("builtins.open", mock_open(read_data=mock_config)):
        checker = SSHChecker()
        result = checker.check_permit_root_login()
        
        assert result["check_id"] == "ssh_root_login"
        assert result["status"] == "PASS"
        assert result["severity"] == "HIGH"

def test_permit_root_login_enabled():
    """Test SSH root login check when misconfigured"""
    mock_config = "PermitRootLogin yes\nPort 22\n"
    
    with patch("builtins.open", mock_open(read_data=mock_config)):
        checker = SSHChecker()
        result = checker.check_permit_root_login()
        
        assert result["status"] == "FAIL"
        assert "yes" in result["finding"].lower()
        assert result["remediation"] is not None

def test_permit_root_login_file_not_found():
    """Test SSH check when config file missing"""
    with patch("builtins.open", side_effect=FileNotFoundError()):
        checker = SSHChecker()
        result = checker.check_permit_root_login()
        
        assert result["status"] == "ERROR"
        assert "not found" in result["finding"].lower()
```

### Backend Tests (Integration Tests)

**Test with Flask test client:**
```python
# tests/test_backend/test_api.py
import pytest
import json
from backend import create_app, db

@pytest.fixture
def client():
    app = create_app('testing')
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

def test_submit_scan_success(client):
    """Test successful scan submission"""
    scan_data = {
        "agent_version": "1.0.0",
        "hostname": "test-server",
        "os_info": {"name": "Ubuntu", "version": "22.04"},
        "scan_timestamp": "2026-01-29T14:30:00Z",
        "privileged_mode": False,
        "checks": [],
        "summary": {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
    }
    
    response = client.post(
        '/api/scan-results',
        data=json.dumps(scan_data),
        headers={
            'Authorization': 'Bearer test_token',
            'Content-Type': 'application/json'
        }
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'scan_id' in data
    assert data['status'] == 'success'

def test_submit_scan_missing_hostname(client):
    """Test scan submission with missing required field"""
    scan_data = {
        "agent_version": "1.0.0",
        # hostname missing
        "checks": []
    }
    
    response = client.post(
        '/api/scan-results',
        data=json.dumps(scan_data),
        headers={'Content-Type': 'application/json'}
    )
    
    assert response.status_code == 400
```

### Test Coverage Goals

- **Agent checks:** 80%+ coverage
- **Backend services:** 80%+ coverage
- **API endpoints:** 90%+ coverage
- **UI:** Manual testing (no automated frontend tests in MVP)

### Test Data

**Use fixtures:**
```python
# tests/fixtures/sample_scans.json
{
  "simple_scan": {
    "agent_version": "1.0.0",
    "hostname": "test-server",
    "checks": [...]
  }
}

# In tests
import json
from pathlib import Path

@pytest.fixture
def sample_scan():
    fixtures_dir = Path(__file__).parent / "fixtures"
    with open(fixtures_dir / "sample_scans.json") as f:
        return json.load(f)["simple_scan"]
```

---

## Important Constraints

### Platform Support

**Linux Only (v1.0):**
- Target systems: Ubuntu 22.04/24.04, Debian 11/12
- Agent checks are Linux-specific (SSH, PAM, auditd, etc.)
- Windows support deferred to v2.0 (document as future work)

**Development on Windows:**
- Agent code written on Windows but tested on Linux
- Use WSL2 or VirtualBox for testing
- Windows-specific paths in documentation (`venv\Scripts\activate`)

### Privilege Requirements

**Some checks require elevated privileges:**

**Needs root/sudo:**
- auditd status and configuration
- /etc/sudoers file parsing
- Some file permission scans
- Docker socket access (unless user in docker group)

**Usually doesn't need sudo:**
- SSH config reading (/etc/ssh/sshd_config often readable)
- Firewall status (varies by configuration)
- Basic user enumeration

**Implementation:**
- Default run mode is unprivileged
- Mark privileged checks as SKIPPED with clear reason
- Optional `--privileged` flag for complete scan
- Never silently fail - always report status

### Compliance Mapping Interpretation

**Critical Understanding:**

Technical checks provide **evidence toward** compliance, NOT full compliance.

**Example:**
- Check: "SSH root login disabled"
- Satisfies **part** of ISO 27001 A.9.2.3 (Management of privileged access rights)
- Does NOT fully satisfy the control (which also requires policies, training, documentation)

**Implementation:**
- Use phrases like "technical requirements met" or "evidence provided"
- Show coverage indicators: "3/5 technical controls for A.9.2 satisfied"
- Document limitations in final report
- Prepare viva answer on interpretation vs. automation

### Security Considerations

**Agent Security:**
- Read-only operations (no system modifications)
- Handles sensitive data (scan results reveal vulnerabilities)
- Should use HTTPS for backend communication
- Bearer token authentication for API

**Backend Security:**
- HTTPS enforced (no HTTP)
- Password hashing with bcrypt or Argon2
- SQL injection prevention (use SQLAlchemy ORM, no raw queries)
- CSRF protection on forms
- Input validation on all endpoints

**Data Protection:**
- Scan results contain sensitive system information
- Store securely in database
- Limit access to authenticated users only
- Consider encrypting scan results at rest (future enhancement)

### Database Choice

**SQLite is sufficient:**
- Zero configuration
- Portable (single file database)
- Perfect for development and demos
- Works fine for deployment with persistent volumes

**PostgreSQL optional:**
- Only if deploying to production at scale
- Not required for FYP submission
- Can migrate later if needed

### Deployment Considerations

**If deploying (optional):**
- Use Railway.app, Render.com, or Fly.io (free tiers)
- Mount persistent volume for SQLite database
- Set environment variables for secrets
- Use HTTPS (automatic on these platforms)

**Not required:**
- Deployment is optional for FYP
- Local demo is sufficient for submission
- Document deployment as "production ready" in report

### Feature Prioritization

**MVP (Must Have):**
1. Agent with 5-6 core checks
2. Backend API + database
3. Basic dashboard
4. Compliance mapping (ISO 27001 minimum)
5. Simple PDF reports

**High Priority (Should Have):**
6. Risk assessment wizard
7. Policy generator
8. "Explain This Control" pages
9. Authentication (username/password)

**Lower Priority (Nice to Have):**
10. Docker scanner
11. MFA (TOTP)
12. Historical tracking with charts
13. Email/Slack alerts
14. Sandbox testing environments

**Backup Plan:**
If behind schedule by Week 6, cut items 10-14. Better to have 9 features working perfectly than 14 half-finished.

### Timeline Constraints

**Submission:** April 2026 (2nd week)
**Development Time:** ~10-11 weeks
**Reserve:** 1 week for final documentation and polish

**Critical Path:**
- Weeks 1-4: Agent + Backend MVP
- Weeks 5-7: Compliance mapping + Policy generator
- Weeks 8-10: Polish + Testing
- Week 11: Documentation + Submission prep

---

## Final Notes

### This Document's Purpose

This `claude.md` file provides persistent context for Claude Code. Reference it when:
- Making architectural decisions
- Determining code structure
- Choosing data formats
- Implementing new features

### Staying Consistent

**All generated code should:**
- Follow the schemas defined here
- Use the file structure specified
- Adhere to code conventions
- Match the design patterns
- Respect the constraints

### When in Doubt

**Refer back to:**
- Data schemas for structure
- Design patterns for approach
- Constraints for limitations
- Code conventions for style

### Feedback Loop

As the project evolves, update this document to reflect:
- Architectural changes
- New patterns discovered
- Lessons learned
- Constraint adjustments

---

**End of claude.md**
