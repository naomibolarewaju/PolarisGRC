"""SQLAlchemy ORM models for PolarisGRC.

Models
------
* :class:`User`    — Authenticated dashboard user with bcrypt password hashing.
* :class:`Scan`    — A single audit agent run submitted via the REST API.
* :class:`Finding` — An individual check result belonging to a ``Scan``.
"""

import uuid
from datetime import datetime

import bcrypt
from flask_login import UserMixin

from backend import db


class User(db.Model, UserMixin):
    """An authenticated PolarisGRC dashboard user.

    Inherits :class:`flask_login.UserMixin` which provides default
    implementations of ``is_authenticated``, ``is_active``, ``is_anonymous``,
    and ``get_id()`` required by Flask-Login.

    Passwords are **never** stored in plain text.  Use :meth:`set_password`
    to hash a new password and :meth:`check_password` to verify it.

    Attributes:
        id (int): Auto-incrementing primary key.
        username (str): Unique login name (max 80 chars).
        email (str): Unique email address (max 120 chars).
        password_hash (str): bcrypt hash of the user's password.
        created_at (datetime): UTC timestamp of account creation.
        is_admin (bool): Reserved for future role-based access control.
        scans (list[Scan]): All scans submitted by this user.
    """

    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin      = db.Column(db.Boolean, default=False)

    scans = db.relationship(
        "Scan",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan",
    )

    # ── Password management ────────────────────────────────────────────────────

    def set_password(self, password: str) -> None:
        """Hash *password* with bcrypt and store the result in ``password_hash``.

        A fresh salt is generated on every call, so two calls with the same
        password will produce different hashes (both will verify correctly).

        Args:
            password: The plain-text password chosen by the user.  Must not
                be empty.

        Example::

            user = User(username="alice", email="alice@example.com")
            user.set_password("correct-horse-battery-staple")
            db.session.add(user)
            db.session.commit()
        """
        self.password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(),
        ).decode("utf-8")

    def check_password(self, password: str) -> bool:
        """Return ``True`` if *password* matches the stored bcrypt hash.

        Uses :func:`bcrypt.checkpw` which is timing-safe and handles salt
        extraction from the stored hash automatically.

        Args:
            password: The plain-text password to verify.

        Returns:
            ``True`` if the password is correct, ``False`` otherwise.

        Example::

            if user.check_password(form.password.data):
                login_user(user)
            else:
                flash("Invalid password.", "error")
        """
        if not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode("utf-8"),
            self.password_hash.encode("utf-8"),
        )

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Scan(db.Model):
    """A single security audit submitted by the PolarisGRC agent.

    Attributes:
        id (str): UUID4 primary key.
        hostname (str): Target system hostname reported by the agent.
        agent_version (str): Version string of the agent that ran the scan.
        os_name (str): Operating system name (e.g. ``'Ubuntu'``).
        os_version (str): OS version string (e.g. ``'22.04'``).
        scan_timestamp (datetime): When the scan was performed on the target.
        privileged_mode (bool): Whether the agent ran with elevated privileges.
        risk_score (float): Baseline risk score calculated on ingestion (0–100).
        created_at (datetime): UTC timestamp when the record was inserted.
        user_id (int | None): Foreign key to the owning :class:`User`, or
            ``None`` for scans submitted before authentication was enabled.
        total_checks / passed_checks / failed_checks / skipped_checks /
            error_checks (int): Counters from the agent's summary block.
        findings (list[Finding]): All check results for this scan.
    """

    __tablename__ = "scans"

    id            = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname      = db.Column(db.String(255), nullable=False)
    agent_version = db.Column(db.String(20))
    os_name       = db.Column(db.String(50))
    os_version    = db.Column(db.String(50))
    scan_timestamp  = db.Column(db.DateTime, nullable=False)
    privileged_mode = db.Column(db.Boolean, default=False)
    risk_score      = db.Column(db.Float)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    # Nullable so existing scans without an owner remain valid
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    total_checks   = db.Column(db.Integer)
    passed_checks  = db.Column(db.Integer)
    failed_checks  = db.Column(db.Integer)
    skipped_checks = db.Column(db.Integer)
    error_checks   = db.Column(db.Integer)

    findings = db.relationship(
        "Finding",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Scan {self.id[:8]} {self.hostname} {self.scan_timestamp}>"


class Finding(db.Model):
    """An individual check result belonging to a :class:`Scan`.

    Attributes:
        id (int): Auto-incrementing primary key.
        scan_id (str): Foreign key to the parent ``Scan``.
        check_id (str): Machine-readable check identifier (e.g. ``'ssh_root_login'``).
        name (str): Human-readable check name.
        category (str): Logical grouping (e.g. ``'Remote Access'``).
        status (str): ``'PASS'`` | ``'FAIL'`` | ``'SKIPPED'`` | ``'ERROR'``.
        severity (str): ``'HIGH'`` | ``'MEDIUM'`` | ``'LOW'``.
        finding (str): Description of the current (potentially insecure) state.
        remediation (str): Step-by-step instructions for fixing the issue.
        requires_privilege (bool): Whether the check needs elevated privileges.
        privilege_level (str | None): ``'root'`` | ``'sudo'`` | ``None``.
        skip_reason (str | None): Explanation when ``status == 'SKIPPED'``.
        cis_reference (str): CIS Benchmark control reference (e.g. ``'5.2.8'``).
        compliance_mappings (dict): Framework → control-ID lists, e.g.
            ``{"iso27001": ["A.9.2.3"], "gdpr": ["Article 32(1)(b)"], "nist_csf": ["PR.AC-4"]}``.
    """

    __tablename__ = "findings"

    id      = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.String(36), db.ForeignKey("scans.id"), nullable=False)

    check_id = db.Column(db.String(100), nullable=False)
    name     = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100))

    status      = db.Column(db.String(20), nullable=False)
    severity    = db.Column(db.String(20))
    finding     = db.Column(db.Text)
    remediation = db.Column(db.Text)

    requires_privilege = db.Column(db.Boolean, default=False)
    privilege_level    = db.Column(db.String(50))
    skip_reason        = db.Column(db.Text)

    cis_reference       = db.Column(db.String(20))
    compliance_mappings = db.Column(db.JSON)

    def __repr__(self) -> str:
        return f"<Finding {self.check_id} {self.status}>"
