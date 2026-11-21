"""
BugHawk AI 2.0 — AI Agents API
Provides endpoints for AI analyst chat and finding analysis.
In demo mode, returns structured mock responses that demonstrate the system's capabilities.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.api.deps import get_current_user, require_owned_finding, require_owned_project
from app.database.session import get_db
from app.models import SecurityFinding, AgentExecution, AgentStatus, User
from app.schemas import (
    AgentChatRequest, AgentChatResponse,
    AgentAnalyzeRequest, AgentAnalyzeResponse
)
from app.config import settings

router = APIRouter()

# ---------------------------------------------------------------------------
# Demo mode responses
# ---------------------------------------------------------------------------

DEMO_ANALYSIS = {
    "Missing Security Headers": {
        "explanation": (
            "The target application does not return several critical HTTP security headers. "
            "These headers instruct browsers to enforce security policies that protect users from "
            "common attacks like XSS (Cross-Site Scripting) and clickjacking. "
            "Specifically, the following headers were absent: Content-Security-Policy, "
            "X-Frame-Options, and X-Content-Type-Options."
        ),
        "severity_assessment": (
            "MEDIUM — While the absence of security headers does not constitute an immediately "
            "exploitable vulnerability, it significantly increases the attack surface and removes "
            "defense-in-depth protections."
        ),
        "confidence": "HIGH — Deterministically identified from HTTP response headers. No false positive risk.",
        "impact": (
            "Without Content-Security-Policy, attackers who find an XSS vector can execute arbitrary "
            "JavaScript. Without X-Frame-Options, the application is susceptible to clickjacking. "
            "These headers are low-effort fixes with high security impact."
        ),
        "remediation_summary": (
            "Add the following HTTP response headers to your web server or application:\n"
            "• Content-Security-Policy: default-src 'self'\n"
            "• X-Frame-Options: DENY\n"
            "• X-Content-Type-Options: nosniff\n"
            "• Referrer-Policy: strict-origin-when-cross-origin\n"
            "• Permissions-Policy: geolocation=(), microphone=()"
        ),
        "verification_steps": [
            "Re-run the HTTP header check after deployment.",
            "Use securityheaders.com to validate the response headers.",
            "Check all subdomains and API endpoints as they may have separate configurations.",
            "Ensure headers are served on both HTTP and HTTPS responses.",
        ],
    },
    "SQL Injection Indicator": {
        "explanation": (
            "A potential SQL injection indicator was identified on the login endpoint. "
            "The application returned a database error message in the HTTP response body when "
            "a single-quote character (') was submitted as input. This suggests user input is "
            "being concatenated directly into a SQL query without parameterization. "
            "\n\nEvidence: HTTP 500 response containing 'You have an error in your SQL syntax'."
        ),
        "severity_assessment": (
            "CRITICAL — SQL injection is one of the most severe vulnerability classes. "
            "If confirmed, an attacker can read, modify, or delete database contents, "
            "bypass authentication, and potentially execute OS commands."
        ),
        "confidence": "MEDIUM — Error-based indicator observed. Manual confirmation required to rule out false positive.",
        "impact": (
            "Complete database compromise. Authentication bypass. Potential for remote code execution "
            "if the database user has FILE or xp_cmdshell privileges. Data exfiltration including "
            "user credentials, PII, and application secrets."
        ),
        "remediation_summary": (
            "IMMEDIATE ACTION REQUIRED:\n"
            "1. Use parameterized queries / prepared statements — never concatenate user input into SQL.\n"
            "2. Implement an ORM (SQLAlchemy, Hibernate, etc.) to abstract database interactions.\n"
            "3. Apply principle of least privilege to database accounts.\n"
            "4. Implement a WAF rule to block SQL metacharacters as a temporary mitigation.\n"
            "5. Rotate all database credentials immediately."
        ),
        "verification_steps": [
            "Submit a time-based blind injection payload: ' OR SLEEP(5)-- to confirm exploitability.",
            "Use sqlmap with --level=1 --risk=1 against the endpoint (only on authorized systems).",
            "Review all database query construction in the authentication module.",
            "Check application logs for similar error patterns on other endpoints.",
        ],
    },
}

DEMO_CHAT_RESPONSES = {
    "default": (
        "I'm the BugHawk AI Security Analyst. I can help you understand vulnerabilities, "
        "assess evidence quality, identify false positives, and recommend remediation strategies. "
        "Select a finding from the Vulnerability Intelligence panel to get context-aware analysis, "
        "or ask me a general security question."
    ),
    "false positive": (
        "To assess whether a finding is a false positive, I look at: "
        "(1) Evidence quality — is there actual proof-of-concept data like HTTP requests/responses? "
        "(2) Consistency — does the finding appear on multiple endpoints or only once? "
        "(3) Tool reliability — Nuclei template-based findings have lower FP rates than heuristic scanners. "
        "(4) Context — a 'SQL error' header without actual query reflection may be a false positive. "
        "Please share the specific finding and I'll assess it in detail."
    ),
    "fix": (
        "For remediation guidance, I need to know: the vulnerability type, the technology stack, "
        "and the affected component. I can then provide language-specific secure code examples, "
        "configuration fixes, and a verification checklist. "
        "Open a specific finding in the Remediation Center for complete remediation instructions."
    ),
}


def _get_demo_response(messages: List) -> str:
    """Generate a contextual demo response based on conversation."""
    if not messages:
        return DEMO_CHAT_RESPONSES["default"]

    last_msg = messages[-1].content.lower()

    if any(w in last_msg for w in ["false positive", "fp", "real", "confirmed"]):
        return DEMO_CHAT_RESPONSES["false positive"]
    elif any(w in last_msg for w in ["fix", "remediat", "patch", "repair", "solve"]):
        return DEMO_CHAT_RESPONSES["fix"]
    else:
        return (
            f"[DEMO MODE — No LLM configured] Based on your question about '{messages[-1].content[:80]}...', "
            "in a production deployment with an LLM configured, I would analyze the finding evidence, "
            "cross-reference CVE databases, assess exploitability in context, and provide a detailed response. "
            "To enable full AI analysis, set LLM_PROVIDER and the corresponding API key in your .env file."
        )


@router.post("/chat", response_model=AgentChatResponse)
def agent_chat(
    payload: AgentChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Conversational AI security analyst.
    Uses stored finding data as context.
    In demo mode, returns structured mock responses.
    """
    require_owned_project(payload.project_id, db, current_user)
    finding_context = None

    # Load finding context if provided
    if payload.finding_id:
        finding = require_owned_finding(payload.finding_id, db, current_user)
        if finding.project_id != payload.project_id:
            raise HTTPException(status_code=403, detail="Finding is not in this project")
        if finding:
            finding_context = {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.effective_severity.value if finding.effective_severity else "unknown",
                "endpoint": finding.endpoint,
                "description": finding.description,
                "source_tool": finding.source_tool,
                "confidence": finding.confidence.value if finding.confidence else "unverified",
                "validation_status": finding.validation_status.value if finding.validation_status else "pending",
            }

    # Record agent execution
    execution = AgentExecution(
        project_id=payload.project_id,
        finding_id=payload.finding_id,
        agent_name="analyst_agent",
        status=AgentStatus.RUNNING,
        input_data={"messages": [m.model_dump() for m in payload.messages]},
    )
    db.add(execution)
    db.flush()

    # Demo mode: return structured mock response
    if settings.is_demo:
        response_text = _get_demo_response(payload.messages)
        execution.status = AgentStatus.COMPLETED
        execution.output_data = {"response": response_text}
        db.commit()

        return AgentChatResponse(
            response=response_text,
            finding_context=finding_context,
            agent_execution_id=execution.id,
            is_demo=True,
        )

    # Production: would call LangGraph agent (implemented in Milestone 4)
    execution.status = AgentStatus.FAILED
    execution.error_message = "LLM provider not configured. Set LLM_PROVIDER in environment."
    db.commit()
    raise HTTPException(
        status_code=503,
        detail="AI analysis requires LLM configuration. See .env.example for setup instructions."
    )


@router.post("/analyze/{finding_id}", response_model=AgentAnalyzeResponse)
def analyze_finding(
    finding_id: str,
    payload: AgentAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Deep AI analysis of a specific finding.
    Returns structured analysis including explanation, severity assessment, and remediation.
    """
    require_owned_project(payload.project_id, db, current_user)
    finding = require_owned_finding(finding_id, db, current_user)
    if finding.project_id != payload.project_id:
        raise HTTPException(status_code=403, detail="Finding is not in this project")

    # Record execution
    execution = AgentExecution(
        project_id=payload.project_id,
        finding_id=finding_id,
        agent_name="analyst_agent",
        status=AgentStatus.RUNNING,
        input_data={"finding_id": finding_id},
    )
    db.add(execution)
    db.flush()

    if settings.is_demo:
        # Return demo analysis based on finding title
        demo_key = None
        for key in DEMO_ANALYSIS:
            if key.lower() in (finding.title or "").lower():
                demo_key = key
                break

        if demo_key and demo_key in DEMO_ANALYSIS:
            analysis = DEMO_ANALYSIS[demo_key]
        else:
            analysis = {
                "explanation": f"[DEMO] Analysis for: {finding.title}. Configure an LLM provider for full AI-powered analysis.",
                "severity_assessment": f"Scanner-reported severity: {finding.scanner_severity.value if finding.scanner_severity else 'unknown'}",
                "confidence": "DEMO — Not AI-assessed",
                "impact": "Configure LLM provider to receive impact assessment.",
                "remediation_summary": "Configure LLM provider to receive remediation recommendations.",
                "verification_steps": ["Configure LLM provider", "Re-run analysis"],
            }

        # Update finding with demo analysis
        finding.ai_explanation = analysis["explanation"]
        finding.ai_analyzed_at = datetime.now(timezone.utc)
        execution.status = AgentStatus.COMPLETED
        execution.output_data = analysis
        db.commit()

        return AgentAnalyzeResponse(
            finding_id=finding_id,
            execution_id=execution.id,
            status="completed",
            explanation=analysis["explanation"],
            severity_assessment=analysis["severity_assessment"],
            confidence=analysis["confidence"],
            impact=analysis["impact"],
            remediation_summary=analysis["remediation_summary"],
            verification_steps=analysis["verification_steps"],
            is_demo=True,
        )

    execution.status = AgentStatus.FAILED
    execution.error_message = "LLM provider not configured."
    db.commit()
    raise HTTPException(
        status_code=503,
        detail="AI analysis requires LLM configuration."
    )
