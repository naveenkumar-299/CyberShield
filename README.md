# LoginGuard-SOC: Intelligent App-Lock Authentication & Security Operations Center

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.x-green.svg)](https://flask.palletsprojects.com/)
[![Hashing](https://img.shields.io/badge/Cryptography-Argon2id%20(RFC%209106)-orange.svg)](https://argon2-cffi.readthedocs.io/)
[![Database](https://img.shields.io/badge/Database-SQLite%20%2F%20SQLAlchemy-lightgrey.svg)](https://www.sqlalchemy.org/)
[![Tests](https://img.shields.io/badge/Tests-28%20Passed-brightgreen.svg)](https://docs.pytest.org/)

**LoginGuard-SOC** is an enterprise-grade cybersecurity final-year project featuring a web-based app-lock authentication system, automated multi-factor authentication (MFA) challenge enforcement, host authentication security telemetry, Suricata EVE JSON intrusion detection system (IDS) integration, IPS-style automated defensive countermeasures, and a dedicated Security Operations Center (SOC) investigation dashboard.

---

## Key Highlights & Architectural Capabilities

1. **Role-Separated Authentication**:
   - Exactly **10 provisioned normal user accounts** (`user01` to `user10`) accessing a modern, app-lock-themed protected vault (`/app`).
   - Exactly **1 separately provisioned SOC Administrator account** (`admin_soc`) accessing the dedicated SOC Command Console (`/admin/dashboard`).
   - Independent server-side authorization policies, preventing privilege escalation or horizontal credential crossover.

2. **Argon2id Password Security**:
   - Zero plaintext password storage.
   - All passwords hashed using the RFC 9106 recommended Argon2id parameters (2 iterations, 64 MiB memory cost, 2 parallel lanes).

3. **Third-Consecutive-Failure MFA Challenge Protocol**:
   - Consecutive failed username/password attempts are tracked per account and source IP.
   - Upon the **3rd consecutive failed attempt**, the system triggers a mandatory one-time verification challenge.
   - Dispatches a single-use, short-lived (300s expiry), cryptographically random OTP to the Administrator's registered alert channel.
   - OTP verifier is hashed using HMAC-SHA256 with constant-time equality checks; raw OTP is never stored in database or logs.
   - Single-use consumption with replay protection and attempt limits (max 3 tries before challenge burns and triggers defensive lockout).

4. **Suricata EVE JSON Network IDS Integration**:
   - Native parser for Suricata EVE JSON logs (`alert`, `flow`, `dns`).
   - Validates schema, timestamps, IPs, ports, protocol, alert signatures, and severities.
   - Fault-tolerant parser safely handles missing, corrupt, or malformed JSON records.
   - Built-in safe synthetic demo mode with pre-packaged signatures (port scans, SSH brute force, web vulnerability probes).

5. **IPS Defensive Countermeasures Engine**:
   - Application-level rate limiting via `Flask-Limiter` and progressive exponential delays.
   - Auditable IP blocklist and account restriction engine with **Dry-Run mode enabled by default**.
   - Input strictly validated using Python's `ipaddress` library (zero shell execution or command injection vectors).
   - Safe administrator unblock workflows with immutable audit logging.

6. **Detection, Correlation, & Risk Scoring**:
   - Temporal window correlation (15-minute sliding window) linking authentication anomalies with IDS signatures.
   - Automated incident grouping into unique case dossiers (`INC-2026-XXXX`).
   - Duplicate-alert suppression to eliminate SOC alert fatigue.
   - Transparent risk engine (0–100 score) detailing contributing factors (failed logins, MFA failures, credential spraying, high-severity IDS alerts).

7. **SOC Command Dashboard & Incident Dossier**:
   - Responsive dark navy & blue interface (`#0a1128`, `#001f54`, `#034078`, `#1282a2`).
   - Live KPI cards, interactive Plotly visualizations (Authentication outcomes donut chart, IDS severity distribution, Incident breakdown).
   - Detailed incident investigation dossier with correlated evidence timelines, risk score meters, and analyst workbench.
   - Official executive PDF dossier export powered by ReportLab and CSV exports with spreadsheet formula injection protection.

8. **Audit Trail & Safe Record Retention**:
   - Dedicated `audit_logs` table tracking all administrative actions.
   - Security audit logs are protected from routine deletion.
   - Archive/prune operation requires the explicit safety confirmation phrase `CONFIRM_ARCHIVE`.

---

## Directory Structure

```text
LoginGuard-SOC/
├── run.py                          # Flask application runner
├── setup_admin.py                  # Interactive PowerShell SOC Administrator setup utility
├── config.py                       # Configuration classes & environment variable parser
├── requirements.txt                # Python package dependencies
├── .env.example                    # Environment variable template
├── .gitignore                      # Git exclusion rules
├── README.md                       # Comprehensive project documentation
├── app/
│   ├── __init__.py                 # Application factory & CLI command registration
│   ├── extensions.py               # SQLAlchemy, LoginManager, CSRFProtect, Limiter
│   ├── models/                     # SQLAlchemy Models
│   │   ├── user.py                 # User account model (normal & admin roles)
│   │   ├── auth_event.py           # Authentication attempts log
│   │   ├── mfa_event.py            # MFA challenge sessions & verifiers
│   │   ├── network_event.py        # Suricata EVE IDS network events
│   │   ├── security_alert.py       # Generated security alerts
│   │   ├── incident.py             # Correlated security incidents
│   │   ├── response_action.py      # IPS blocks & defensive restrictions
│   │   ├── audit_log.py            # Immutable administrative audit trail
│   │   ├── session_metadata.py     # Active session tracker
│   │   └── notification.py         # Email delivery log & status
│   ├── auth/                       # Normal User Authentication Package
│   │   ├── forms.py                # Flask-WTF login & MFA forms
│   │   ├── routes.py               # /login, /mfa/challenge, /app, /logout
│   │   ├── auth_service.py         # Login workflow & 3rd failure challenge orchestration
│   │   ├── password_service.py     # Argon2id hashing & verification
│   │   ├── otp_service.py          # Cryptographic OTP generator, verifier & replay checks
│   │   ├── email_service.py        # SMTP delivery with graceful fallback simulation
│   │   ├── session_service.py      # Idle timeout enforcement & tracking
│   │   └── decorators.py           # @admin_required, @user_required, @session_protected
│   ├── admin/                      # SOC Administrator Package
│   │   ├── routes.py               # /admin/login, /admin/dashboard, /admin/database-view...
│   │   ├── dashboard_service.py    # Plotly analytics charts
│   │   ├── user_management.py      # Account locking, unlocking & counter resets
│   │   └── audit_service.py        # Audit trail logger & safe data pruning
│   ├── detection/                  # Anomaly Detection & Correlation
│   │   ├── rules.py                # Detection rule definitions
│   │   ├── risk_engine.py          # Transparent risk score calculator
│   │   └── correlation.py          # Temporal correlation & incident grouping
│   ├── ids/                        # Intrusion Detection Package
│   │   ├── eve_parser.py           # Suricata EVE JSON parser & schema validator
│   │   └── network_service.py      # EVE ingestion & synthetic demo generator
│   ├── ips/                        # Intrusion Prevention Package
│   │   ├── rate_limiter.py         # Progressive delay calculator
│   │   └── response_engine.py      # Auditable IP blocking, restrictions & unblocking
│   ├── database/                   # Database Management
│   │   ├── init_db.py              # Schema initialization & account seeding
│   │   └── repositories.py         # Filtering & pagination query layer
│   ├── reports/                    # Reporting & Exports
│   │   ├── csv_exporter.py         # Sanitized CSV generator
│   │   └── pdf_generator.py        # ReportLab incident PDF dossier generator
│   ├── static/                     # Assets
│   │   ├── css/
│   │   │   ├── split_auth.css      # Split-screen Dark Cyber Portal theme (reference UI)
│   │   │   ├── soc_dark.css        # Professional SOC dark navy & blue theme
│   │   │   └── user_portal.css     # App-lock portal theme
│   │   └── js/
│   │       ├── admin_soc.js        # Plotly chart renderers & confirmation dialogs
│   │       └── auth.js             # Countdown timer & input formatting
│   └── templates/                  # Jinja2 Templates
│       ├── base.html
│       ├── auth/                   # login.html, mfa_challenge.html, app.html
│       └── admin/                  # dashboard.html, database_view.html, incidents.html...
│       ├── admin/                  # dashboard.html, auth_monitor.html, incidents.html...
│       └── errors/                 # 403.html, 404.html, 429.html, 500.html
├── data/
│   └── sample_events.json          # Synthetic Suricata EVE JSON alert logs
├── instance/                       # SQLite storage (loginguard.db)
├── logs/                           # Rotating application log files
└── tests/                          # 28 Comprehensive automated pytest tests
```

---

## Provisioned Account Credentials

During database initialization, credentials are read securely from environment variables (`.env`) or configured interactively. All accounts are persisted as Argon2id hashes:

| Role | Username | Email Address | Default Initial Password | Portal URL |
| :--- | :--- | :--- | :--- | :--- |
| **SOC Admin** | `analyst` *(or custom)* | `naveenlenin29@gmail.com` | Configured via `setup_admin.py` | `/admin/login` |
| **Normal User 01** | `user01` | `user01@loginguard.local` | `UserSecure#2026!Passcode` | `/login` |
| **Normal User 02** | `user02` | `user02@loginguard.local` | `UserSecure#2026!Passcode` | `/login` |
| **Normal User 03** | `user03` | `user03@loginguard.local` | `UserSecure#2026!Passcode` | `/login` |
| **Normal User 04** | `user04` | `user04@loginguard.local` | `UserSecure#2026!Passcode` | `/login` |
| **Normal User 05** | `user05` | `user05@loginguard.local` | `UserSecure#2026!Passcode` | `/login` |
| **Normal User 06** | `user06` | `user06@loginguard.local` | `UserSecure#2026!Passcode` | `/login` |
| **Normal User 07** | `user07` | `user07@loginguard.local` | `UserSecure#2026!Passcode` | `/login` |
| **Normal User 08** | `user08` | `user08@loginguard.local` | `UserSecure#2026!Passcode` | `/login` |
| **Normal User 09** | `user09` | `user09@loginguard.local` | `UserSecure#2026!Passcode` | `/login` |
| **Normal User 10** | `user10` | `user10@loginguard.local` | `UserSecure#2026!Passcode` | `/login` |

> [!NOTE]
> Normal users cannot log into `/admin/login` and administrators cannot log into `/login`. URL tampering or unauthorized escalation to admin endpoints returns an immediate **HTTP 403 Forbidden** and logs an immutable audit alert.

---

## Windows PowerShell Step-by-Step Execution Guide

### Step 1: Open PowerShell in Project Directory
Ensure your terminal is in the project root:
```powershell
cd "c:\Users\navee\Downloads\tech stack"
```

### Step 2: Configure & Remember Administrator Credentials Interactively
Run the interactive setup utility to prompt for your custom SOC administrator username, email, and password. This utility updates `.env` and immediately records the Argon2id hash in SQLite:
```powershell
python setup_admin.py
```
*(Enter your desired administrator username, notification email, and password. The system remembers them permanently.)*

### Step 3: Run Verification Test Suite (Optional but Recommended)
Run the 28 automated tests covering authentication, MFA challenge, IDS EVE parsing, IPS blocking, and PDF/CSV reports:
```powershell
python -m pytest -v
```

### Step 4: Start the LoginGuard-SOC Server
Launch the application server on `http://127.0.0.1:5000`:
```powershell
python run.py
```

### Step 5: Explore the Application

1. **Client Portal (Redesigned Split-Screen Theme)**:
   - Navigate to: `http://127.0.0.1:5000/login`
   - Log in with any provisioned user, e.g.:
     - **Username**: `user01`
     - **Password**: `UserSecure#2026!Passcode`
   - You will enter the protected Vault (`/app`).

2. **Trigger 3rd-Failure MFA Challenge & Google SMTP OTP**:
   - Log out, then intentionally enter a wrong password for `user01` **3 consecutive times**.
   - On the 3rd attempt, you are redirected to `/mfa/challenge`.
   - A real 6-digit OTP is immediately delivered to `naveenlenin29@gmail.com` via Google SMTP.
   - Enter the OTP received in your inbox to complete verification.

3. **SOC Administrator Console & Database Explorer**:
   - Navigate to: `http://127.0.0.1:5000/admin/login`
   - Log in using your configured Administrator credentials (`analyst`).
   - Access the **SOC Dashboard** (`/admin/dashboard`) to view live KPIs, donut charts, and the "Test Gmail Alert Channel" button.
   - Click **Database Explorer** in the sidebar navigation (`/admin/database-view`) to inspect live SQLite table records, foreign keys, and PRAGMA integrity metrics.
Start the LoginGuard-SOC local server:
```powershell
python run.py
```
The server will bind to `http://127.0.0.1:5000`.

- **Normal User Portal**: [http://127.0.0.1:5000/login](http://127.0.0.1:5000/login)
- **SOC Admin Console**: [http://127.0.0.1:5000/admin/login](http://127.0.0.1:5000/admin/login)

---

## Testing the 3rd-Failure MFA Workflow End-to-End

1. Open [http://127.0.0.1:5000/login](http://127.0.0.1:5000/login).
2. Attempt login as `user01` with an incorrect password:
   - **Attempt 1**: Rejection notice (*"Invalid credentials. Warning: 2 attempt(s) until mandatory MFA challenge lock."*)
   - **Attempt 2**: Rejection notice (*"Invalid credentials. Warning: 1 attempt(s) until mandatory MFA challenge lock."*)
   - **Attempt 3**: Trigger threshold met! The application locks normal authentication and redirects to the **Security Challenge** interface (`/mfa/challenge/<uuid>`).
3. Behind the scenes:
   - A single-use 6-digit numeric OTP is generated and hashed with HMAC-SHA256.
   - An alert email notification is logged to the database and dispatched to `admin.soc@loginguard.local`.
   - A high-severity Security Alert and correlated Incident (`INC-2026-0001`) are created.
4. Obtain the token:
   - In demo/development mode, the admin can inspect the dispatched token under **Audit & Archive > Notification Delivery Stream** or in the console logs.
5. Enter the correct 6-digit code on the challenge screen:
   - Access is granted, the failed attempt counter resets to 0, and the protected application vault (`/app`) unlocks for `user01`.
   - Replay test: Attempting to submit the same OTP again is immediately rejected.

---

## Testing IDS & IPS Defense Capabilities

1. Navigate to **SOC Admin Console > Suricata IDS Monitor** (`/admin/ids-monitor`).
2. Click **"Ingest Synthetic Demo Batch"**:
   - The system parses `data/sample_events.json`, importing synthetic Nmap scans, SSH brute-force attempts, and web probes.
   - Events are clearly flagged with `[SYNTHETIC DEMO]` badges.
3. Observe Automated Correlation:
   - The correlation engine cross-references the network probe signatures against incoming authentication telemetry.
   - Open cases appear under **Incident Response Queue** (`/admin/incidents`), complete with calculated risk scores and contributing factor breakdowns.
4. Click **Dossier** on any incident:
   - Review correlated authentication and network evidence timelines.
   - Update lifecycle status and enter analyst investigation notes.
   - Click **"Export Official PDF Report"** to generate a cryptographic PDF dossier.
5. Navigate to **IPS Defenses** (`/admin/ips-actions`):
   - Review active restrictions.
   - Apply a manual IP block with input validation (e.g. `198.51.100.88`).
   - Notice the restriction badge displays `[SIMULATED]` in Dry-Run mode.
   - Test safe unblocking with the **Unblock** action button.

---

## Security Architecture & Design Considerations

- **No Plaintext Credential Exposure**: Plaintext passwords, raw OTPs, session tokens, and master keys are never stored in SQLite, rendered in templates, or emitted to log files.
- **CSRF & Cookie Protection**: CSRF tokens are enforced on all POST forms via `Flask-WTF`. Session cookies are configured with `HttpOnly=True` and `SameSite=Lax`.
- **Injection Defenses**:
  - Raw shell execution is prohibited. IP addresses are verified using standard Python `ipaddress` objects.
  - CSV exports neutralize spreadsheet formula injection (`=`, `+`, `-`, `@`).
  - Database queries use SQLAlchemy parameterized expressions.
- **Immunity of Audit Logs**:
  - The archive/purge functionality strictly protects the `audit_logs` table. Routine pruning of old events never erases investigator actions.
- **Dry-Run Default**:
  - The IPS engine operates in dry-run simulation by default, preventing accidental network isolation during academic demonstrations.

---

## Verification & Test Results

The full automated test suite was executed against Python 3.11.5:
```text
tests/test_admin_access.py::test_admin_successful_login PASSED
tests/test_admin_access.py::test_normal_user_blocked_from_all_admin_routes PASSED
tests/test_admin_access.py::test_unauthenticated_user_redirected_to_admin_login PASSED
tests/test_admin_access.py::test_admin_cannot_login_through_normal_portal PASSED
tests/test_auth.py::test_seeded_accounts_and_argon2_hashing PASSED
tests/test_auth.py::test_valid_login_opens_protected_app PASSED
tests/test_auth.py::test_invalid_login_records_failure PASSED
tests/test_auth.py::test_logout_invalidates_session PASSED
tests/test_detection_correlation.py::test_repeated_login_failure_detection PASSED
tests/test_detection_correlation.py::test_risk_scoring_transparency_and_factors PASSED
tests/test_detection_correlation.py::test_correlation_and_incident_grouping PASSED
tests/test_ids_parser.py::test_valid_suricata_eve_line_parsing PASSED
tests/test_ids_parser.py::test_malformed_json_handled_safely PASSED
tests/test_ids_parser.py::test_missing_and_empty_fields_handled_gracefully PASSED
tests/test_ids_parser.py::test_load_sample_file_in_database PASSED
tests/test_ips_responses.py::test_ip_validation_rejects_malformed_and_injection PASSED
tests/test_ips_responses.py::test_dry_run_ip_blocking_and_unblocking PASSED
tests/test_ips_responses.py::test_account_temporary_lock_and_unlock PASSED
tests/test_mfa_challenge.py::test_mfa_triggered_strictly_on_third_failure PASSED
tests/test_mfa_challenge.py::test_correct_otp_grants_access_as_normal_user_not_admin PASSED
tests/test_mfa_challenge.py::test_incorrect_otp_increments_attempts PASSED
tests/test_mfa_challenge.py::test_replayed_otp_is_rejected PASSED
tests/test_mfa_challenge.py::test_expired_otp_is_rejected PASSED
tests/test_record_management.py::test_archive_pruning_requires_exact_confirmation PASSED
tests/test_record_management.py::test_archive_prunes_old_events_and_preserves_audit_logs PASSED
tests/test_reports.py::test_csv_formula_injection_sanitization PASSED
tests/test_reports.py::test_pdf_report_generation PASSED
tests/test_reports.py::test_csv_export_endpoint_access PASSED

============================= 28 passed in 40.42s =============================
```
