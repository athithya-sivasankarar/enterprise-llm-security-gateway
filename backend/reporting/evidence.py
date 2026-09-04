import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.db.models import (
    SecurityTestResultModel,
    SecurityTestFindingModel,
    SecurityTestRunModel,
    SecurityCampaignRunModel,
    SecurityRegressionModel,
    SecurityAlertModel,
    AuditLog,
    SecurityPolicyModel
)
from backend.reporting.models import EvidenceItem, ReportFinding
from backend.reporting.sanitizer import sanitize_evidence_item, sanitize_text
from backend.observability.metrics import record_evidence_item_metric

logger = logging.getLogger(__name__)

# Map test categories to primary security controls
CATEGORY_CONTROL_MAP = {
    "AUTHENTICATION": "API Key & Identity Verifier",
    "RBAC": "Role-Based Access Control Enforcer",
    "RATE_LIMITING": "Sliding-Window Rate Limiter",
    "INPUT_DLP": "Input Data Loss Prevention (Presidio/RegEx)",
    "PROMPT_INJECTION": "Prompt Injection Heuristic Filter",
    "JAILBREAK": "Adversarial Jailbreak Detection Engine",
    "SYSTEM_PROMPT_EXTRACTION": "System Prompt Extraction Protector",
    "SECRET_LEAKAGE": "Secret & Credential Leakage Guard",
    "UNSAFE_RESPONSE": "Response Safety & Threat Classifier",
    "RESPONSE_PII": "Response PII Sanitizer & Redactor",
    "PROVIDER_AUTHORIZATION": "Provider Access Controller",
    "CACHE_ISOLATION": "Redis Semantic Cache Tenant Isolator",
    "POLICY_ENFORCEMENT": "Dynamic Security Policy Evaluator",
    "AUDIT_LOGGING": "Structured JSON Audit Logger",
    "OBSERVABILITY": "Prometheus & OpenTelemetry Telemetry"
}


async def collect_evidence_for_run(
    db: AsyncSession,
    run_id: str,
    policy_version: str = "1.0.0"
) -> List[EvidenceItem]:
    """
    Extract, normalize, and sanitize security evidence from a specific validation test run.
    """
    stmt = (
        select(SecurityTestResultModel)
        .where(SecurityTestResultModel.run_id == run_id)
        .order_by(SecurityTestResultModel.category, SecurityTestResultModel.test_id)
    )
    res = await db.execute(stmt)
    results = res.scalars().all()

    evidence_items: List[EvidenceItem] = []

    for r in results:
        raw_cat = (r.category or "UNKNOWN").upper()
        control_name = CATEGORY_CONTROL_MAP.get(raw_cat, "Gateway Security Control")

        exp_behavior = sanitize_text(
            f"Expected {control_name} to enforce security assertion for test '{r.test_id}' and return status {r.expected_status}."
        )
        act_behavior = sanitize_text(
            f"Observed gateway execution status {r.actual_status} (Latency: {round(r.latency_ms, 2)}ms). {r.error_message or 'No errors recorded.'}"
        )


        item_dict = {
            "evidence_id": f"ev-{uuid.uuid4().hex[:12]}",
            "test_id": r.test_id,
            "category": raw_cat,
            "severity": (r.severity or "MEDIUM").upper(),
            "evidence_type": "AUTOMATED_SECURITY_TEST",
            "expected_behavior": exp_behavior,
            "actual_behavior": act_behavior,
            "security_control": control_name,
            "endpoint": "/api/chat",
            "status": (r.status or "UNKNOWN").upper(),
            "policy_version": policy_version,
            "timestamp": r.created_at or datetime.now(timezone.utc)
        }

        clean_dict = sanitize_evidence_item(item_dict)
        evidence_items.append(EvidenceItem(**clean_dict))
        record_evidence_item_metric(clean_dict["category"], clean_dict["severity"])

    return evidence_items


async def collect_findings_for_run(
    db: AsyncSession,
    run_id: str,
    policy_version: str = "1.0.0"
) -> List[ReportFinding]:
    """
    Extract and sanitize persisted security findings for a test run.
    """
    stmt = (
        select(SecurityTestFindingModel)
        .where(SecurityTestFindingModel.run_id == run_id)
        .order_by(desc(SecurityTestFindingModel.created_at))
    )
    res = await db.execute(stmt)
    findings = res.scalars().all()

    report_findings: List[ReportFinding] = []
    for f in findings:
        clean_finding = ReportFinding(
            finding_id=f.finding_id,
            test_id=f.test_id,
            category=f.category,
            severity=f.severity,
            title=sanitize_text(f.title),
            description=sanitize_text(f.description),
            expected_behavior=sanitize_text(f"Expected {f.category} control to mitigate risk."),
            actual_behavior=sanitize_text(f"Control failure detected with severity {f.severity}."),
            endpoint="/api/chat",
            policy_version=policy_version,
            timestamp=f.created_at or datetime.now(timezone.utc)
        )
        report_findings.append(clean_finding)

    return report_findings


async def collect_regressions_for_campaign_run(
    db: AsyncSession,
    campaign_run_id: str
) -> List[Dict[str, Any]]:
    """
    Extract sanitized regression records for a campaign run.
    """
    stmt = (
        select(SecurityRegressionModel)
        .where(SecurityRegressionModel.campaign_run_id == campaign_run_id)
        .order_by(desc(SecurityRegressionModel.created_at))
    )
    res = await db.execute(stmt)
    regressions = res.scalars().all()

    clean_regs = []
    for reg in regressions:
        clean_regs.append({
            "regression_id": reg.regression_id,
            "test_id": reg.test_id,
            "category": reg.category,
            "severity": reg.severity,
            "previous_status": reg.previous_status,
            "current_status": reg.current_status,
            "score_delta": reg.score_delta,
            "description": sanitize_text(reg.description),
            "policy_version": reg.policy_version,
            "created_at": reg.created_at.isoformat() if reg.created_at else None
        })
    return clean_regs


async def collect_open_alerts_for_campaign(
    db: AsyncSession,
    campaign_id: Optional[str] = None
) -> int:
    """
    Count active open alerts for the campaign or entire gateway.
    """
    stmt = select(SecurityAlertModel).where(SecurityAlertModel.status == "OPEN")
    if campaign_id:
        stmt = stmt.where(SecurityAlertModel.campaign_id == campaign_id)
    res = await db.execute(stmt)
    return len(res.scalars().all())
