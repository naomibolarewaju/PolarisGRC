# PolarisGRC

A cybersecurity auditing and governance platform for small and medium-sized
enterprises (SMEs). PolarisGRC automates security configuration checks on
Linux systems and maps findings to compliance frameworks including ISO 27001,
GDPR, and NIST CSF — presenting results through a web dashboard with risk
scoring, remediation guidance, and policy generation.

## Features

- **Audit Agent** — CLI tool that runs 15 security checks across SSH
  configuration, password policy, firewall, patch management, user
  privileges, file permissions, and audit logging
- **Compliance Mapping** — automatic mapping of findings to ISO 27001,
  GDPR Article 32, and NIST CSF controls with coverage percentages
- **Risk Assessment** — weighted risk scoring combining technical findings
  with organisational context (industry, size, data sensitivity)
- **Policy Generator** — generates Access Control Policy, Acceptable Use
  Policy, and Incident Response Plan in PDF and Markdown formats
- **Web Dashboard** — scan history, per-finding compliance tags, remediation
  guidance, and CSV/JSON/HTML export
- **Authentication** — user registration and login with bcrypt password
  hashing and CSRF protection
- **Dark and Light Mode** — responsive UI with theme toggle

## Tech Stack

- **Backend** — Python, Flask, SQLAlchemy, SQLite
- **Frontend** — Jinja2, Tailwind CSS
- **Agent** — Python, Click
- **PDF Generation** — WeasyPrint
- **Auth** — Flask-Login, Flask-Bcrypt, Flask-WTF

The agent is designed for Ubuntu/Debian Linux systems. Several checks
- (auditd, firewall) will return SKIPPED on WSL2 due to kernel limitations —
  a full Linux VM is recommended for accurate results.


This project was developed by Naomi Bolarewaju as a Final Year Project at the University of
Galway, 2026.
