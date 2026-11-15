"""
BugHawk AI 2.0 — Demo Data Seeder

Creates a complete, realistic demo project with:
- Demo user
- Demo project: "BugHawk Demo Application"
- Authorized scopes
- Discovered assets
- Security findings with evidence (clearly marked as DEMO DATA)
- Remediation suggestions
- Attack path data

Run this script from the backend/ directory after running migrations:
    python seed_demo.py

IMPORTANT: All seeded data is marked with is_demo=True.
No real scan data is claimed. All findings are synthetic examples.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime, timezone, timedelta
from app.database.session import SessionLocal
from app.database.base import Base
from app.database.session import engine
from app.models import (
    User, Project, AuthorizedScope, Asset, ScanJob, SecurityFinding,
    FindingEvidence, RemediationSuggestion, AttackPath, AgentExecution,
    UserRole, AssetStatus, AssetType, ScanStatus, Severity,
    ConfidenceLevel, ValidationStatus, RemediationStatus, AgentStatus
)
from app.core.security import hash_password
from app.config import settings
import hashlib

def compute_hash(title: str, endpoint: str = "") -> str:
    key = f"{title.lower().strip()}|{endpoint.lower().strip()}|demo"
    return hashlib.sha256(key.encode()).hexdigest()[:64]


DEMO_FINDINGS = [
    {
        "title": "Missing Security Headers",
        "vulnerability_type": "Security Misconfiguration",
        "scanner_severity": Severity.MEDIUM,
        "cwe_id": "CWE-16",
        "endpoint": "https://app.bughawk-demo.local/",
        "description": (
            "[DEMO DATA] The application does not return critical HTTP security headers. "
            "Missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, "
            "Referrer-Policy, Permissions-Policy."
        ),
        "impact": "Increases attack surface. Without CSP, XSS attacks are significantly more impactful.",
        "remediation": "Add security headers to web server or application middleware configuration.",
        "evidence": {
            "type": "http_response",
            "request": "GET / HTTP/1.1\nHost: app.bughawk-demo.local",
            "response_status": 200,
            "missing_headers": [
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy"
            ],
            "tool": "nuclei",
            "template": "http/misconfiguration/http-missing-security-headers.yaml",
            "demo": True,
        },
        "source_tool": "nuclei",
        "source_template": "http/misconfiguration/http-missing-security-headers.yaml",
        "confidence": ConfidenceLevel.HIGH,
        "validation_status": ValidationStatus.CONFIRMED,
        "risk_score": 5.2,
        "risk_factors": {
            "severity": 2.0,
            "evidence_quality": 2.0,
            "asset_exposure": 1.2,
            "note": "DEMO — Explainable risk score, not CVSS."
        },
        "needs_human_review": False,
        "remediation_data": {
            "root_cause": "Web server not configured to send security-relevant HTTP response headers.",
            "recommendation": (
                "Add the following directives to your Nginx/Apache/application configuration:\n\n"
                "Nginx:\n"
                "add_header Content-Security-Policy \"default-src 'self'\" always;\n"
                "add_header X-Frame-Options \"DENY\" always;\n"
                "add_header X-Content-Type-Options \"nosniff\" always;\n"
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
            ),
            "secure_code_example": (
                "# Python/FastAPI middleware example\n"
                "from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware\n\n"
                "@app.middleware('http')\n"
                "async def add_security_headers(request, call_next):\n"
                "    response = await call_next(request)\n"
                "    response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
                "    response.headers['X-Frame-Options'] = 'DENY'\n"
                "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                "    return response"
            ),
            "code_language": "python",
            "verification_checklist": [
                "Run nuclei template after fix to confirm headers are present",
                "Verify on all subdomains and API endpoints separately",
                "Use securityheaders.com for independent validation",
                "Confirm headers are present on both HTTP and HTTPS responses",
            ],
        },
    },
    {
        "title": "SQL Injection Indicator",
        "vulnerability_type": "SQL Injection",
        "scanner_severity": Severity.CRITICAL,
        "cwe_id": "CWE-89",
        "endpoint": "https://app.bughawk-demo.local/api/login",
        "description": (
            "[DEMO DATA] A database error message was observed in the HTTP response when "
            "a single-quote character was submitted in the 'username' parameter. "
            "This indicates possible SQL query construction from unsanitized user input."
        ),
        "impact": (
            "If confirmed: complete database read/write access, authentication bypass, "
            "potential remote code execution via database features."
        ),
        "remediation": "Use parameterized queries. Never concatenate user input into SQL.",
        "evidence": {
            "type": "http_request_response",
            "request": (
                "POST /api/login HTTP/1.1\n"
                "Host: app.bughawk-demo.local\n"
                "Content-Type: application/json\n\n"
                '{"username": "admin\'", "password": "test"}'
            ),
            "response_status": 500,
            "response_body_excerpt": "You have an error in your SQL syntax near 'admin'' at line 1",
            "tool": "nuclei",
            "template": "http/vulnerabilities/generic/sql-error-based.yaml",
            "demo": True,
            "note": "SYNTHETIC DEMO — Not a real scan result.",
        },
        "source_tool": "nuclei",
        "source_template": "http/vulnerabilities/generic/sql-error-based.yaml",
        "confidence": ConfidenceLevel.MEDIUM,
        "validation_status": ValidationStatus.NEEDS_REVIEW,
        "risk_score": 9.1,
        "risk_factors": {
            "severity": 4.0,
            "evidence_quality": 2.5,
            "asset_exposure": 1.8,
            "exploitability": 0.8,
            "note": "DEMO — Explainable risk score. Manual confirmation required before treating as confirmed."
        },
        "needs_human_review": True,
        "remediation_data": {
            "root_cause": "User input concatenated directly into SQL query string without parameterization.",
            "recommendation": (
                "IMMEDIATE: Replace all string-concatenated SQL queries with parameterized queries or ORM.\n"
                "Rotate database credentials after fix.\n"
                "Review all query construction in authentication module."
            ),
            "secure_code_example": (
                "# VULNERABLE (DO NOT USE)\n"
                "query = f\"SELECT * FROM users WHERE username = '{username}'\"\n\n"
                "# SECURE — Parameterized query\n"
                "query = text('SELECT * FROM users WHERE username = :username')\n"
                "result = db.execute(query, {'username': username})\n\n"
                "# BEST PRACTICE — Use ORM\n"
                "user = db.query(User).filter(User.username == username).first()"
            ),
            "code_language": "python",
            "verification_checklist": [
                "Verify fix with sqlmap --level=1 --risk=1 (authorized systems only)",
                "Code review: audit all raw SQL query construction",
                "Confirm parameterized queries across all database interaction points",
                "Rotate database credentials",
                "Enable database query logging and review for anomalies",
            ],
        },
    },
    {
        "title": "Cross-Site Scripting (Reflected XSS) Indicator",
        "vulnerability_type": "Cross-Site Scripting (XSS)",
        "scanner_severity": Severity.HIGH,
        "cwe_id": "CWE-79",
        "endpoint": "https://app.bughawk-demo.local/search?q=<payload>",
        "description": (
            "[DEMO DATA] The search parameter 'q' reflects input directly into the HTML response "
            "without encoding. A test payload <script>alert(1)</script> was reflected in the response body."
        ),
        "impact": "Reflected XSS allows attackers to execute arbitrary JavaScript in victim browsers, enabling session hijacking, credential theft, and malware distribution.",
        "remediation": "Encode all user-controlled output in HTML context. Implement CSP.",
        "evidence": {
            "type": "http_request_response",
            "request": "GET /search?q=<script>alert(1)</script> HTTP/1.1\nHost: app.bughawk-demo.local",
            "response_status": 200,
            "reflected_payload": "<script>alert(1)</script>",
            "response_context": "HTML body — unencoded reflection in <div class='results'>",
            "tool": "nuclei",
            "demo": True,
            "note": "SYNTHETIC DEMO — Not a real scan result.",
        },
        "source_tool": "nuclei",
        "confidence": ConfidenceLevel.MEDIUM,
        "validation_status": ValidationStatus.NEEDS_REVIEW,
        "risk_score": 7.4,
        "risk_factors": {
            "severity": 3.0,
            "evidence_quality": 2.5,
            "asset_exposure": 1.5,
            "note": "DEMO — Explainable risk score."
        },
        "needs_human_review": True,
        "remediation_data": {
            "root_cause": "User-controlled input reflected into HTML response without output encoding.",
            "recommendation": "Use framework-provided output encoding. Implement Content-Security-Policy.",
            "secure_code_example": (
                "# Python — HTML escape before rendering\n"
                "import html\n"
                "safe_query = html.escape(user_query)\n\n"
                "# Template — Jinja2 auto-escaping (enabled by default)\n"
                "# SAFE: {{ user_query }}  — auto-escaped\n"
                "# UNSAFE: {{ user_query | safe }}  — bypasses escaping"
            ),
            "code_language": "python",
            "verification_checklist": [
                "Test all input parameters for reflection",
                "Verify CSP header blocks inline script execution",
                "Review all template rendering for | safe or similar escape bypasses",
                "Scan with Nuclei XSS templates after fix",
            ],
        },
    },
    {
        "title": "Insecure Server Configuration — Directory Listing Enabled",
        "vulnerability_type": "Information Disclosure",
        "scanner_severity": Severity.LOW,
        "cwe_id": "CWE-548",
        "endpoint": "https://app.bughawk-demo.local/static/",
        "description": (
            "[DEMO DATA] The web server returns a directory listing for /static/ path. "
            "This exposes file names and potentially sensitive configuration or backup files."
        ),
        "impact": "Attackers can enumerate application files, discover backup files, configuration files, or other sensitive resources.",
        "remediation": "Disable directory listing in web server configuration.",
        "evidence": {
            "type": "http_response",
            "request": "GET /static/ HTTP/1.1\nHost: app.bughawk-demo.local",
            "response_status": 200,
            "response_body_excerpt": "Index of /static/ — Parent Directory, app.min.js, config.backup.json",
            "tool": "nuclei",
            "demo": True,
        },
        "source_tool": "nuclei",
        "confidence": ConfidenceLevel.HIGH,
        "validation_status": ValidationStatus.CONFIRMED,
        "risk_score": 3.1,
        "risk_factors": {
            "severity": 1.0,
            "evidence_quality": 2.0,
            "asset_exposure": 0.6,
            "note": "DEMO — Explainable risk score."
        },
        "needs_human_review": False,
        "remediation_data": {
            "root_cause": "Web server autoindex feature enabled on static file directory.",
            "recommendation": "Disable autoindex in web server config.",
            "secure_code_example": (
                "# Nginx — disable directory listing\n"
                "server {\n"
                "    location /static/ {\n"
                "        autoindex off;  # Explicitly disable\n"
                "        alias /app/static/;\n"
                "    }\n"
                "}"
            ),
            "code_language": "nginx",
            "verification_checklist": [
                "Confirm GET /static/ returns 403 or 404 after fix",
                "Audit all web server location blocks for autoindex",
                "Remove any sensitive files (*.backup, *.config) from web-accessible directories",
            ],
        },
    },
    {
        "title": "Weak Authorization Pattern — IDOR Indicator",
        "vulnerability_type": "Broken Access Control",
        "scanner_severity": Severity.HIGH,
        "cwe_id": "CWE-284",
        "endpoint": "https://app.bughawk-demo.local/api/users/123/profile",
        "description": (
            "[DEMO DATA] The API endpoint /api/users/{id}/profile accepts sequential integer IDs "
            "and returns user profile data without verifying the authenticated user owns the resource. "
            "This is an Insecure Direct Object Reference (IDOR) indicator."
        ),
        "impact": "Horizontal privilege escalation. Any authenticated user can read (and potentially modify) any other user's profile data.",
        "remediation": "Enforce authorization checks: verify authenticated user ID matches requested resource owner.",
        "evidence": {
            "type": "analysis",
            "pattern": "Sequential integer resource IDs in REST API",
            "observation": "ID increments by 1 (e.g. /api/users/123, /api/users/124)",
            "auth_check_observed": False,
            "tool": "manual_analysis",
            "demo": True,
            "note": "SYNTHETIC DEMO — Requires manual verification.",
        },
        "source_tool": "manual_analysis",
        "confidence": ConfidenceLevel.LOW,
        "validation_status": ValidationStatus.PENDING,
        "risk_score": 6.8,
        "risk_factors": {
            "severity": 3.0,
            "evidence_quality": 1.0,
            "asset_exposure": 2.0,
            "note": "DEMO — Low confidence indicator, manual verification required."
        },
        "needs_human_review": True,
        "remediation_data": {
            "root_cause": "Missing object-level authorization checks in API endpoint handler.",
            "recommendation": "Add ownership verification before returning any resource.",
            "secure_code_example": (
                "# FastAPI — enforce resource ownership\n"
                "@app.get('/api/users/{user_id}/profile')\n"
                "def get_user_profile(user_id: int, current_user = Depends(get_current_user)):\n"
                "    # Authorization check — must come BEFORE data retrieval\n"
                "    if current_user.id != user_id and current_user.role != 'admin':\n"
                "        raise HTTPException(status_code=403, detail='Forbidden')\n"
                "    return db.query(User).filter(User.id == user_id).first()"
            ),
            "code_language": "python",
            "verification_checklist": [
                "Attempt to access another user's profile with a different authenticated session",
                "Verify 403 is returned for cross-user access attempts",
                "Audit all object-level operations (read, update, delete) for ownership checks",
                "Consider using UUIDs instead of sequential integers to reduce guessability",
            ],
        },
    },
]

DEMO_ASSETS = [
    {"hostname": "app.bughawk-demo.local", "type": AssetType.SUBDOMAIN, "status": AssetStatus.LIVE, "http_status_code": 200, "title": "BugHawk Demo App"},
    {"hostname": "api.bughawk-demo.local", "type": AssetType.SUBDOMAIN, "status": AssetStatus.LIVE, "http_status_code": 200, "title": "BugHawk Demo API"},
    {"hostname": "admin.bughawk-demo.local", "type": AssetType.SUBDOMAIN, "status": AssetStatus.LIVE, "http_status_code": 403, "title": "Admin Panel"},
    {"hostname": "bughawk-demo.local", "type": AssetType.DOMAIN, "status": AssetStatus.LIVE, "http_status_code": 301, "title": "BugHawk Demo — Redirect"},
    {"hostname": "staging.bughawk-demo.local", "type": AssetType.SUBDOMAIN, "status": AssetStatus.DOWN, "http_status_code": None, "title": None},
]


def seed_demo():
    db = SessionLocal()
    try:
        print("🦅 BugHawk AI 2.0 — Demo Data Seeder")
        print("=" * 50)

        # Check for existing demo data
        existing = db.query(User).filter(User.email == "demo@bughawk.ai").first()
        if existing:
            print("⚠️  Demo data already exists. Skipping seed.")
            print("   To re-seed: DROP the database tables and run migrations again.")
            return

        # 1. Create demo user
        print("\n[1/6] Creating demo user...")
        if not settings.demo_admin_password:
            raise RuntimeError(
                "DEMO_ADMIN_PASSWORD is not set. Add it to the environment before seeding."
            )
        demo_user = User(
            id="demo-user-id",
            email=settings.demo_admin_email,
            hashed_password=hash_password(settings.demo_admin_password),
            full_name="BugHawk Demo User",
            role=UserRole.ADMIN,
            is_demo=True,
        )
        db.add(demo_user)
        db.flush()
        print(f"    ✓ User: demo@bughawk.ai")

        # 2. Create demo project
        print("\n[2/6] Creating demo project...")
        demo_project = Project(
            id="demo-project-id",
            owner_id="demo-user-id",
            name="BugHawk Demo Application",
            description=(
                "DEMO PROJECT — Synthetic security findings for demonstration purposes. "
                "No real scans were performed. All findings are examples of common vulnerability types."
            ),
            is_demo=True,
        )
        db.add(demo_project)
        db.flush()
        print(f"    ✓ Project: {demo_project.name}")

        # 3. Create authorized scopes
        print("\n[3/6] Creating authorized scopes...")
        scopes = [
            AuthorizedScope(
                project_id="demo-project-id",
                scope_value="bughawk-demo.local",
                is_wildcard=False,
                notes="Root domain — exact match only",
                authorized_by="Demo Authorization",
            ),
            AuthorizedScope(
                project_id="demo-project-id",
                scope_value="*.bughawk-demo.local",
                is_wildcard=True,
                notes="All subdomains — wildcard authorized",
                authorized_by="Demo Authorization",
            ),
        ]
        for scope in scopes:
            db.add(scope)
        db.flush()
        print(f"    ✓ {len(scopes)} scope rules added")

        # 4. Create demo assets
        print("\n[4/6] Creating demo assets...")
        asset_map = {}
        for a_data in DEMO_ASSETS:
            asset = Asset(
                project_id="demo-project-id",
                hostname=a_data["hostname"],
                asset_type=a_data["type"],
                status=a_data["status"],
                http_status_code=a_data["http_status_code"],
                title=a_data["title"],
                discovery_source="subfinder (DEMO)",
                is_in_scope=True,
                is_demo=True,
                technologies=["Python", "FastAPI", "PostgreSQL"] if "api" in a_data["hostname"] else ["React", "Nginx"],
                last_seen=datetime.now(timezone.utc),
            )
            db.add(asset)
            db.flush()
            asset_map[a_data["hostname"]] = asset.id
        print(f"    ✓ {len(DEMO_ASSETS)} assets created")

        # 5. Create demo scan job
        print("\n[5/6] Creating demo scan job...")
        scan_job = ScanJob(
            project_id="demo-project-id",
            name="Demo Automated Scan",
            target="*.bughawk-demo.local",
            modules=["subfinder", "httpx", "nuclei"],
            status=ScanStatus.COMPLETED,
            scope_validated=True,
            started_at=datetime.now(timezone.utc) - timedelta(hours=2),
            completed_at=datetime.now(timezone.utc) - timedelta(hours=1),
            findings_count=len(DEMO_FINDINGS),
            is_demo=True,
        )
        db.add(scan_job)
        db.flush()
        print(f"    ✓ Demo scan job created")

        # 6. Create findings + evidence + remediation
        print("\n[6/6] Creating demo findings...")
        for f_data in DEMO_FINDINGS:
            finding_hash = compute_hash(f_data["title"], f_data.get("endpoint", ""))
            asset_id = asset_map.get(
                "app.bughawk-demo.local" if "app" in f_data.get("endpoint", "") else "api.bughawk-demo.local"
            )

            finding = SecurityFinding(
                project_id="demo-project-id",
                asset_id=asset_id,
                scan_job_id=scan_job.id,
                title=f_data["title"],
                vulnerability_type=f_data["vulnerability_type"],
                scanner_severity=f_data["scanner_severity"],
                effective_severity=f_data["scanner_severity"],
                cwe_id=f_data.get("cwe_id"),
                endpoint=f_data.get("endpoint"),
                description=f_data["description"],
                impact=f_data.get("impact"),
                remediation=f_data.get("remediation"),
                evidence=f_data.get("evidence"),
                source_tool=f_data.get("source_tool"),
                confidence=f_data["confidence"],
                validation_status=f_data["validation_status"],
                risk_score=f_data.get("risk_score"),
                risk_factors=f_data.get("risk_factors"),
                finding_hash=finding_hash,
                needs_human_review=f_data.get("needs_human_review", False),
                is_demo=True,
            )
            db.add(finding)
            db.flush()

            # Evidence item
            ev_data = f_data.get("evidence", {})
            if ev_data:
                evidence_content = "\n".join(
                    f"{k}: {v}" for k, v in ev_data.items()
                    if k not in ("demo", "note")
                )
                evidence = FindingEvidence(
                    finding_id=finding.id,
                    evidence_type=ev_data.get("type", "observation"),
                    title=f"Scanner Evidence — {f_data['title']} [DEMO]",
                    content=evidence_content,
                )
                db.add(evidence)

            # Remediation suggestion
            rem_data = f_data.get("remediation_data", {})
            if rem_data:
                suggestion = RemediationSuggestion(
                    finding_id=finding.id,
                    root_cause=rem_data.get("root_cause"),
                    impact=f_data.get("impact"),
                    recommendation=rem_data.get("recommendation"),
                    secure_code_example=rem_data.get("secure_code_example"),
                    code_language=rem_data.get("code_language"),
                    verification_checklist=rem_data.get("verification_checklist"),
                    status=RemediationStatus.PENDING,
                    ai_generated=True,
                )
                db.add(suggestion)

            print(f"    ✓ [{f_data['scanner_severity'].value.upper()}] {f_data['title']}")

        # Update scan job findings count
        scan_job.findings_count = len(DEMO_FINDINGS)

        # Demo attack path
        attack_path = AttackPath(
            project_id="demo-project-id",
            name="Potential Web Application Attack Chain [DEMO]",
            description=(
                "DEMO — Hypothetical attack chain illustrating how multiple weaknesses "
                "could be combined. This is NOT a confirmed exploitation path."
            ),
            nodes=[
                {"id": "1", "type": "asset", "data": {"label": "app.bughawk-demo.local", "type": "entry"}, "position": {"x": 100, "y": 200}},
                {"id": "2", "type": "vulnerability", "data": {"label": "XSS Reflected", "severity": "high"}, "position": {"x": 300, "y": 100}},
                {"id": "3", "type": "vulnerability", "data": {"label": "Missing CSP", "severity": "medium"}, "position": {"x": 300, "y": 300}},
                {"id": "4", "type": "impact", "data": {"label": "Session Hijacking", "type": "impact"}, "position": {"x": 550, "y": 200}},
            ],
            edges=[
                {"id": "e1-2", "source": "1", "target": "2", "label": "attack vector"},
                {"id": "e2-4", "source": "2", "target": "4", "label": "enables (hypothetical)"},
                {"id": "e3-4", "source": "3", "target": "4", "label": "amplifies"},
            ],
            is_confirmed=False,
            severity=Severity.HIGH,
            is_demo=True,
        )
        db.add(attack_path)

        db.commit()
        print("\n" + "=" * 50)
        print("✅ Demo data seeded successfully!")
        print(f"\n📊 Summary:")
        print(f"   Project: BugHawk Demo Application (ID: demo-project-id)")
        print(f"   Login email: {settings.demo_admin_email}")
        print("   Password: value of DEMO_ADMIN_PASSWORD (not printed)")
        print(f"   Assets: {len(DEMO_ASSETS)}")
        print(f"   Findings: {len(DEMO_FINDINGS)}")
        print(f"   All findings clearly marked as DEMO DATA")

    except Exception as e:
        db.rollback()
        print(f"\n❌ Seed failed: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_demo()
