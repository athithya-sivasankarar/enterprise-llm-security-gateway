import json
import uuid
import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from fastapi import HTTPException, status

from backend.db.models import (
    SecurityCampaignModel,
    SecurityCampaignRunModel,
    SecurityTestRunModel,
    SecurityTestResultModel,
    SecurityPolicyModel
)
from backend.reporting.models import (
    ReportType,
    ReportStatus,
    SecurityReport,
    ExecutiveSummary,
    CategoryResult,
    ReportFinding,
    EvidenceItem,
    ComplianceMapping
)
from backend.reporting.sanitizer import sanitize_text, sanitize_metadata
from backend.reporting.evidence import (
    collect_evidence_for_run,
    collect_findings_for_run,
    collect_regressions_for_campaign_run,
    collect_open_alerts_for_campaign
)
from backend.reporting.scoring import (
    calculate_overall_score,
    calculate_category_results,
    determine_security_posture
)
from backend.reporting.compliance import generate_compliance_mappings, COMPLIANCE_DISCLAIMER
from backend.services.policy_service import get_active_policy

logger = logging.getLogger(__name__)

REPORT_VERSION = "1.0.0"
METHODOLOGY_NOTE = (
    "Security assessments are executed deterministically in safe mock environments "
    "using synthetic, non-destructive test vectors across 14 security control domains. "
    "Real external LLMs and sensitive production credentials are never invoked."
)
LIMITATIONS_NOTE = (
    "Assessments reflect the configured security policies and rule thresholds active at generation time. "
    "Synthetic validation results provide high-assurance verification of gateway controls but do not replace "
    "comprehensive third-party penetration testing or human threat modeling."
)


def calculate_report_hash(report_data: Dict[str, Any]) -> str:
    """
    Compute a deterministic SHA-256 hash over the canonical sanitized report representation.
    Excludes mutable timestamps and hash fields to enable post-generation integrity verification.
    """
    canonical_repr = {
        "report_type": report_data.get("report_type"),
        "title": report_data.get("title"),
        "executive_summary": {
            "security_score": report_data.get("executive_summary", {}).get("security_score"),
            "baseline_score": report_data.get("executive_summary", {}).get("baseline_score"),
            "score_delta": report_data.get("executive_summary", {}).get("score_delta"),
            "security_posture": report_data.get("executive_summary", {}).get("security_posture"),
            "total_tests": report_data.get("executive_summary", {}).get("total_tests"),
            "passed_tests": report_data.get("executive_summary", {}).get("passed_tests"),
            "failed_tests": report_data.get("executive_summary", {}).get("failed_tests"),
            "error_tests": report_data.get("executive_summary", {}).get("error_tests"),
            "critical_findings": report_data.get("executive_summary", {}).get("critical_findings"),
            "high_findings": report_data.get("executive_summary", {}).get("high_findings"),
            "regression_count": report_data.get("executive_summary", {}).get("regression_count"),
            "policy_version": report_data.get("executive_summary", {}).get("policy_version")
        },
        "category_results": sorted(
            [
                {
                    "category": cr.get("category"),
                    "score": cr.get("score"),
                    "status": cr.get("status"),
                    "total_tests": cr.get("total_tests"),
                    "passed_tests": cr.get("passed_tests")
                }
                for cr in report_data.get("category_results", [])
            ],
            key=lambda x: x.get("category", "")
        ),
        "findings": sorted(
            [
                {
                    "test_id": f.get("test_id"),
                    "category": f.get("category"),
                    "severity": f.get("severity"),
                    "title": f.get("title")
                }
                for f in report_data.get("findings", [])
            ],
            key=lambda x: (x.get("test_id", ""), x.get("category", ""))
        ),
        "regressions": sorted(
            [
                {
                    "test_id": r.get("test_id"),
                    "category": r.get("category"),
                    "severity": r.get("severity")
                }
                for r in report_data.get("regressions", [])
            ],
            key=lambda x: x.get("test_id", "")
        ),
        "compliance_mappings": sorted(
            [
                {
                    "control_id": cm.get("control_id"),
                    "coverage_status": cm.get("coverage_status"),
                    "evidence_count": cm.get("evidence_count")
                }
                for cm in report_data.get("compliance_mappings", [])
            ],
            key=lambda x: x.get("control_id", "")
        ),
        "evidence_count": report_data.get("evidence_count", 0),
        "policy_version": report_data.get("policy_version", "1.0.0"),
        "report_version": report_data.get("report_version", REPORT_VERSION)
    }

    raw_json = json.dumps(canonical_repr, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(raw_json.encode("utf-8")).hexdigest()


def verify_report_integrity(report_dict: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Verify report integrity by recomputing the canonical hash and matching against persisted hash.
    """
    persisted_hash = report_dict.get("report_hash")
    if not persisted_hash:
        return False, "Report does not contain an integrity hash."

    computed_hash = calculate_report_hash(report_dict)
    if computed_hash == persisted_hash:
        return True, "Report integrity verified successfully (SHA-256 match)."
    else:
        return False, f"Integrity verification failed: computed hash {computed_hash[:12]}... does not match {persisted_hash[:12]}..."


async def generate_campaign_report(
    db: AsyncSession,
    campaign_id: str,
    campaign_run_id: Optional[str] = None,
    user: str = "security-lead",
    custom_title: Optional[str] = None,
    custom_description: Optional[str] = None
) -> Tuple[SecurityReport, List[EvidenceItem]]:
    """
    Generate comprehensive assessment report for a security campaign.
    """
    # 1. Fetch Campaign
    stmt_camp = select(SecurityCampaignModel).where(SecurityCampaignModel.campaign_id == campaign_id)
    res_camp = await db.execute(stmt_camp)
    campaign = res_camp.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security campaign '{campaign_id}' not found."
        )

    # 2. Fetch Target Campaign Run
    if campaign_run_id:
        stmt_crun = select(SecurityCampaignRunModel).where(SecurityCampaignRunModel.campaign_run_id == campaign_run_id)
    else:
        stmt_crun = (
            select(SecurityCampaignRunModel)
            .where(SecurityCampaignRunModel.campaign_id == campaign_id)
            .order_by(desc(SecurityCampaignRunModel.started_at))
            .limit(1)
        )
    res_crun = await db.execute(stmt_crun)
    crun_row = res_crun.scalar_one_or_none()

    if not crun_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No campaign runs found for campaign '{campaign_id}' to generate report."
        )

    target_crun_id = crun_row.campaign_run_id
    target_val_run_id = crun_row.run_id
    pol_version = crun_row.policy_version or "1.0.0"

    # 3. Collect Evidence & Findings
    evidence_items = await collect_evidence_for_run(db, target_val_run_id, pol_version)
    findings = await collect_findings_for_run(db, target_val_run_id, pol_version)
    regressions = await collect_regressions_for_campaign_run(db, target_crun_id)
    open_alerts_count = await collect_open_alerts_for_campaign(db, campaign_id)

    # 4. Calculate Category Results & Scores
    stmt_results = select(SecurityTestResultModel).where(SecurityTestResultModel.run_id == target_val_run_id)
    res_results = await db.execute(stmt_results)
    raw_results = res_results.scalars().all()
    category_results = calculate_category_results(raw_results)

    crit_findings = sum(1 for f in findings if f.severity.upper() == "CRITICAL")
    high_findings = sum(1 for f in findings if f.severity.upper() == "HIGH")
    med_findings = sum(1 for f in findings if f.severity.upper() == "MEDIUM")
    low_findings = sum(1 for f in findings if f.severity.upper() == "LOW")

    posture = determine_security_posture(
        score=crun_row.security_score,
        critical_findings=crit_findings,
        high_findings=high_findings,
        critical_alerts=0,
        high_alerts=0
    )

    # 5. Generate Compliance Mappings
    compliance_mappings = generate_compliance_mappings(evidence_items)

    # 6. Build Executive Summary
    now = datetime.now(timezone.utc)
    exec_summary = ExecutiveSummary(
        security_score=crun_row.security_score,
        baseline_score=crun_row.baseline_score,
        score_delta=crun_row.score_delta,
        security_posture=posture,
        total_tests=crun_row.total_tests,
        passed_tests=crun_row.passed_tests,
        failed_tests=crun_row.failed_tests,
        error_tests=crun_row.error_tests,
        skipped_tests=crun_row.skipped_tests,
        critical_findings=crit_findings,
        high_findings=high_findings,
        medium_findings=med_findings,
        low_findings=low_findings,
        regression_count=len(regressions),
        open_alerts_count=open_alerts_count,
        policy_version=pol_version,
        generated_at=now
    )

    report_id = f"rep-{uuid.uuid4().hex[:12]}"
    title = custom_title or f"Security Assessment Report: {campaign.name}"
    description = custom_description or f"Automated campaign assessment and regression verification for campaign '{campaign_id}'."

    report_dict = {
        "report_id": report_id,
        "report_type": ReportType.CAMPAIGN.value,
        "title": sanitize_text(title),
        "description": sanitize_text(description),
        "status": ReportStatus.COMPLETED.value,
        "created_by": user,
        "created_at": now.isoformat(),
        "completed_at": now.isoformat(),
        "campaign_id": campaign_id,
        "campaign_run_id": target_crun_id,
        "executive_summary": exec_summary.model_dump(),
        "category_results": [cr.model_dump() for cr in category_results],
        "findings": [f.model_dump() for f in findings],
        "regressions": regressions,
        "compliance_mappings": [cm.model_dump() for cm in compliance_mappings],
        "evidence_count": len(evidence_items),
        "policy_version": pol_version,
        "report_version": REPORT_VERSION,
        "methodology": METHODOLOGY_NOTE,
        "limitations": LIMITATIONS_NOTE,
        "compliance_disclaimer": COMPLIANCE_DISCLAIMER
    }

    # Clean & Hash
    report_dict = sanitize_metadata(report_dict)
    rep_hash = calculate_report_hash(report_dict)
    report_dict["report_hash"] = rep_hash

    report_obj = SecurityReport(
        report_id=report_id,
        report_type=ReportType.CAMPAIGN.value,
        title=report_dict["title"],
        description=report_dict["description"],
        status=ReportStatus.COMPLETED.value,
        created_by=user,
        created_at=now,
        completed_at=now,
        campaign_id=campaign_id,
        campaign_run_id=target_crun_id,
        executive_summary=exec_summary,
        category_results=category_results,
        findings=findings,
        regressions=regressions,
        compliance_mappings=compliance_mappings,
        evidence_count=len(evidence_items),
        policy_version=pol_version,
        report_version=REPORT_VERSION,
        report_hash=rep_hash,
        methodology=METHODOLOGY_NOTE,
        limitations=LIMITATIONS_NOTE,
        compliance_disclaimer=COMPLIANCE_DISCLAIMER
    )

    return report_obj, evidence_items


async def generate_security_validation_report(
    db: AsyncSession,
    run_id: str,
    user: str = "security-lead",
    custom_title: Optional[str] = None,
    custom_description: Optional[str] = None
) -> Tuple[SecurityReport, List[EvidenceItem]]:
    """
    Generate assessment report from an isolated validation test run.
    """
    stmt_run = select(SecurityTestRunModel).where(SecurityTestRunModel.run_id == run_id)
    res_run = await db.execute(stmt_run)
    run_row = res_run.scalar_one_or_none()

    if not run_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security test run '{run_id}' not found."
        )

    pol_version = run_row.policy_version or "1.0.0"
    evidence_items = await collect_evidence_for_run(db, run_id, pol_version)
    findings = await collect_findings_for_run(db, run_id, pol_version)

    stmt_results = select(SecurityTestResultModel).where(SecurityTestResultModel.run_id == run_id)
    res_results = await db.execute(stmt_results)
    raw_results = res_results.scalars().all()
    category_results = calculate_category_results(raw_results)

    crit_findings = sum(1 for f in findings if f.severity.upper() == "CRITICAL")
    high_findings = sum(1 for f in findings if f.severity.upper() == "HIGH")
    med_findings = sum(1 for f in findings if f.severity.upper() == "MEDIUM")
    low_findings = sum(1 for f in findings if f.severity.upper() == "LOW")

    posture = determine_security_posture(
        score=run_row.security_score,
        critical_findings=crit_findings,
        high_findings=high_findings
    )

    compliance_mappings = generate_compliance_mappings(evidence_items)

    now = datetime.now(timezone.utc)
    exec_summary = ExecutiveSummary(
        security_score=run_row.security_score,
        baseline_score=None,
        score_delta=None,
        security_posture=posture,
        total_tests=run_row.total_tests,
        passed_tests=run_row.passed_tests,
        failed_tests=run_row.failed_tests,
        error_tests=run_row.error_tests,
        skipped_tests=run_row.skipped_tests,
        critical_findings=crit_findings,
        high_findings=high_findings,
        medium_findings=med_findings,
        low_findings=low_findings,
        regression_count=0,
        open_alerts_count=0,
        policy_version=pol_version,
        generated_at=now
    )

    report_id = f"rep-{uuid.uuid4().hex[:12]}"
    title = custom_title or f"Red-Team Security Validation Report: {run_id}"
    description = custom_description or f"Automated adversarial red-team validation run across gateway security controls."

    report_dict = {
        "report_id": report_id,
        "report_type": ReportType.SECURITY_VALIDATION.value,
        "title": sanitize_text(title),
        "description": sanitize_text(description),
        "status": ReportStatus.COMPLETED.value,
        "created_by": user,
        "created_at": now.isoformat(),
        "completed_at": now.isoformat(),
        "campaign_id": None,
        "campaign_run_id": None,
        "executive_summary": exec_summary.model_dump(),
        "category_results": [cr.model_dump() for cr in category_results],
        "findings": [f.model_dump() for f in findings],
        "regressions": [],
        "compliance_mappings": [cm.model_dump() for cm in compliance_mappings],
        "evidence_count": len(evidence_items),
        "policy_version": pol_version,
        "report_version": REPORT_VERSION,
        "methodology": METHODOLOGY_NOTE,
        "limitations": LIMITATIONS_NOTE,
        "compliance_disclaimer": COMPLIANCE_DISCLAIMER
    }

    report_dict = sanitize_metadata(report_dict)
    rep_hash = calculate_report_hash(report_dict)

    report_obj = SecurityReport(
        report_id=report_id,
        report_type=ReportType.SECURITY_VALIDATION.value,
        title=report_dict["title"],
        description=report_dict["description"],
        status=ReportStatus.COMPLETED.value,
        created_by=user,
        created_at=now,
        completed_at=now,
        campaign_id=None,
        campaign_run_id=None,
        executive_summary=exec_summary,
        category_results=category_results,
        findings=findings,
        regressions=[],
        compliance_mappings=compliance_mappings,
        evidence_count=len(evidence_items),
        policy_version=pol_version,
        report_version=REPORT_VERSION,
        report_hash=rep_hash,
        methodology=METHODOLOGY_NOTE,
        limitations=LIMITATIONS_NOTE,
        compliance_disclaimer=COMPLIANCE_DISCLAIMER
    )

    return report_obj, evidence_items


async def generate_executive_report(
    db: AsyncSession,
    user: str = "security-lead",
    custom_title: Optional[str] = None
) -> Tuple[SecurityReport, List[EvidenceItem]]:
    """
    Generate high-level executive security posture report.
    """
    # Fetch latest validation run
    stmt_run = select(SecurityTestRunModel).order_by(desc(SecurityTestRunModel.started_at)).limit(1)
    res_run = await db.execute(stmt_run)
    latest_run = res_run.scalar_one_or_none()

    run_id = latest_run.run_id if latest_run else None
    if run_id:
        report_obj, evidence = await generate_security_validation_report(
            db, run_id, user,
            custom_title=custom_title or "Executive Security Posture & Risk Report",
            custom_description="Executive-level overview of AI gateway security posture, control coverage, and risk indicators."
        )
        report_obj.report_type = ReportType.EXECUTIVE.value
        return report_obj, evidence
    else:
        # Fallback if no runs exist
        now = datetime.now(timezone.utc)
        exec_summary = ExecutiveSummary(
            security_score=100.0,
            baseline_score=100.0,
            score_delta=0.0,
            security_posture="SECURE",
            total_tests=0,
            passed_tests=0,
            failed_tests=0,
            error_tests=0,
            skipped_tests=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
            regression_count=0,
            open_alerts_count=0,
            policy_version="1.0.0",
            generated_at=now
        )
        report_id = f"rep-{uuid.uuid4().hex[:12]}"
        report_dict = {
            "report_id": report_id,
            "report_type": ReportType.EXECUTIVE.value,
            "title": custom_title or "Executive Security Posture & Risk Report",
            "description": "Executive summary of AI security gateway health.",
            "status": ReportStatus.COMPLETED.value,
            "created_by": user,
            "created_at": now.isoformat(),
            "completed_at": now.isoformat(),
            "campaign_id": None,
            "campaign_run_id": None,
            "executive_summary": exec_summary.model_dump(),
            "category_results": [],
            "findings": [],
            "regressions": [],
            "compliance_mappings": generate_compliance_mappings([]),
            "evidence_count": 0,
            "policy_version": "1.0.0",
            "report_version": REPORT_VERSION,
            "methodology": METHODOLOGY_NOTE,
            "limitations": LIMITATIONS_NOTE,
            "compliance_disclaimer": COMPLIANCE_DISCLAIMER
        }
        rep_hash = calculate_report_hash(report_dict)
        report_obj = SecurityReport(
            report_id=report_id,
            report_type=ReportType.EXECUTIVE.value,
            title=report_dict["title"],
            description=report_dict["description"],
            status=ReportStatus.COMPLETED.value,
            created_by=user,
            created_at=now,
            completed_at=now,
            campaign_id=None,
            campaign_run_id=None,
            executive_summary=exec_summary,
            category_results=[],
            findings=[],
            regressions=[],
            compliance_mappings=report_dict["compliance_mappings"],
            evidence_count=0,
            policy_version="1.0.0",
            report_version=REPORT_VERSION,
            report_hash=rep_hash,
            methodology=METHODOLOGY_NOTE,
            limitations=LIMITATIONS_NOTE,
            compliance_disclaimer=COMPLIANCE_DISCLAIMER
        )
        return report_obj, []


async def generate_governance_report(
    db: AsyncSession,
    user: str = "security-officer",
    custom_title: Optional[str] = None,
    custom_description: Optional[str] = None
) -> Tuple[SecurityReport, List[EvidenceItem]]:
    """
    Generate an Executive Governance, Risk Acceptance & Control Assurance Report.
    """
    from backend.services.governance_service import get_governance_summary, get_governance_risk
    from backend.db.models import SecurityRiskExceptionModel, SecurityControlAssuranceModel

    gov_summary = await get_governance_summary(db)
    gov_risk = await get_governance_risk(db)

    # Fetch recent test runs for evidence
    stmt_run = select(SecurityTestRunModel).order_by(desc(SecurityTestRunModel.started_at)).limit(1)
    res_run = await db.execute(stmt_run)
    latest_run = res_run.scalar_one_or_none()

    pol_version = gov_summary.policy_version or "1.0.0"
    if latest_run:
        evidence_items = await collect_evidence_for_run(db, latest_run.run_id, pol_version)
        findings = await collect_findings_for_run(db, latest_run.run_id, pol_version)
        stmt_results = select(SecurityTestResultModel).where(SecurityTestResultModel.run_id == latest_run.run_id)
        res_results = await db.execute(stmt_results)
        raw_results = res_results.scalars().all()
        category_results = calculate_category_results(raw_results)
    else:
        evidence_items = []
        findings = []
        category_results = []

    compliance_mappings = generate_compliance_mappings(evidence_items)

    now = datetime.now(timezone.utc)
    exec_summary = ExecutiveSummary(
        security_score=gov_summary.control_assurance_score,
        baseline_score=100.0,
        score_delta=round(gov_summary.control_assurance_score - 100.0, 1),
        security_posture="SECURE" if gov_summary.governance_risk_score < 30 else ("DEGRADED" if gov_summary.governance_risk_score < 80 else "CRITICAL"),
        total_tests=sum(cr.total_tests for cr in category_results),
        passed_tests=sum(cr.passed_tests for cr in category_results),
        failed_tests=sum(cr.failed_tests for cr in category_results),
        error_tests=sum(cr.error_tests for cr in category_results),
        skipped_tests=0,
        critical_findings=gov_summary.critical_exposures,
        high_findings=gov_summary.open_incidents,
        medium_findings=gov_summary.open_exceptions,
        low_findings=gov_summary.overdue_exceptions,
        regression_count=gov_summary.active_regressions,
        open_alerts_count=gov_summary.overdue_exceptions,
        policy_version=pol_version,
        generated_at=now
    )

    report_id = f"rep-{uuid.uuid4().hex[:12]}"
    title = custom_title or "Security Governance, Risk Acceptance & Control Assurance Report"
    description = custom_description or (
        f"Executive governance assessment. Governance Risk Score: {gov_summary.governance_risk_score}/100 "
        f"({gov_summary.governance_risk_level}), Control Assurance: {gov_summary.control_assurance_score:.1f}%, "
        f"Active Exceptions: {gov_summary.open_exceptions} ({gov_summary.overdue_exceptions} overdue)."
    )

    report_dict = {
        "report_id": report_id,
        "report_type": ReportType.GOVERNANCE.value,
        "title": sanitize_text(title),
        "description": sanitize_text(description),
        "status": ReportStatus.COMPLETED.value,
        "created_by": user,
        "created_at": now.isoformat(),
        "completed_at": now.isoformat(),
        "campaign_id": None,
        "campaign_run_id": None,
        "executive_summary": exec_summary.model_dump(),
        "category_results": [cr.model_dump() for cr in category_results],
        "findings": [f.model_dump() for f in findings],
        "regressions": [],
        "compliance_mappings": [cm.model_dump() for cm in compliance_mappings],
        "evidence_count": len(evidence_items),
        "policy_version": pol_version,
        "report_version": REPORT_VERSION,
        "methodology": METHODOLOGY_NOTE,
        "limitations": LIMITATIONS_NOTE,
        "compliance_disclaimer": COMPLIANCE_DISCLAIMER
    }

    report_dict = sanitize_metadata(report_dict)
    rep_hash = calculate_report_hash(report_dict)
    report_dict["report_hash"] = rep_hash

    report_obj = SecurityReport(
        report_id=report_id,
        report_type=ReportType.GOVERNANCE.value,
        title=report_dict["title"],
        description=report_dict["description"],
        status=ReportStatus.COMPLETED.value,
        created_by=user,
        created_at=now,
        completed_at=now,
        campaign_id=None,
        campaign_run_id=None,
        executive_summary=exec_summary,
        category_results=category_results,
        findings=findings,
        regressions=[],
        compliance_mappings=compliance_mappings,
        evidence_count=len(evidence_items),
        policy_version=pol_version,
        report_version=REPORT_VERSION,
        report_hash=rep_hash,
        methodology=METHODOLOGY_NOTE,
        limitations=LIMITATIONS_NOTE,
        compliance_disclaimer=COMPLIANCE_DISCLAIMER
    )

    return report_obj, evidence_items

