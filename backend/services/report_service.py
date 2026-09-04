import uuid
import time
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, delete

from backend.db.models import (
    SecurityReportModel,
    SecurityEvidenceModel,
    SecurityCampaignModel,
    SecurityCampaignRunModel,
    SecurityTestRunModel
)
from backend.reporting.models import (
    ReportType,
    ReportStatus,
    ReportCreateRequest,
    ReportSummary,
    SecurityReport,
    EvidenceItem
)
from backend.reporting.generator import (
    generate_campaign_report,
    generate_security_validation_report,
    generate_executive_report,
    calculate_report_hash,
    verify_report_integrity
)
from backend.reporting.exporters import (
    export_json,
    export_markdown,
    export_csv,
    export_pdf
)
from backend.observability.metrics import (
    record_report_generated_metric,
    record_report_failed_metric,
    record_report_export_metric,
    record_report_integrity_failure_metric
)
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)


async def create_report(
    db: AsyncSession,
    req: ReportCreateRequest,
    user: str
) -> ReportSummary:
    """
    Create and immediately generate an auditable security assessment report.
    """
    start_time = time.time()
    rep_type = req.report_type.upper() if req.report_type else ReportType.CAMPAIGN.value

    try:
        if rep_type == ReportType.CAMPAIGN.value or rep_type == ReportType.REGRESSION.value:
            if not req.campaign_id:
                # Find most recent active campaign
                stmt_camp = select(SecurityCampaignModel).order_by(desc(SecurityCampaignModel.created_at)).limit(1)
                res_camp = await db.execute(stmt_camp)
                camp_row = res_camp.scalar_one_or_none()
                if not camp_row:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="campaign_id is required or an existing campaign must be present to generate a campaign report."
                    )
                target_camp_id = camp_row.campaign_id
            else:
                target_camp_id = req.campaign_id

            report_obj, evidence_items = await generate_campaign_report(
                db=db,
                campaign_id=target_camp_id,
                campaign_run_id=req.campaign_run_id,
                user=user,
                custom_title=req.title,
                custom_description=req.description
            )
            if rep_type == ReportType.REGRESSION.value:
                report_obj.report_type = ReportType.REGRESSION.value

        elif rep_type == ReportType.SECURITY_VALIDATION.value:
            if not req.run_id:
                stmt_run = select(SecurityTestRunModel).order_by(desc(SecurityTestRunModel.started_at)).limit(1)
                res_run = await db.execute(stmt_run)
                run_row = res_run.scalar_one_or_none()
                if not run_row:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="run_id is required or a validation test run must exist to generate a validation report."
                    )
                target_run_id = run_row.run_id
            else:
                target_run_id = req.run_id

            report_obj, evidence_items = await generate_security_validation_report(
                db=db,
                run_id=target_run_id,
                user=user,
                custom_title=req.title,
                custom_description=req.description
            )

        elif rep_type == ReportType.EXECUTIVE.value:
            report_obj, evidence_items = await generate_executive_report(
                db=db,
                user=user,
                custom_title=req.title
            )

        elif rep_type == ReportType.COMPLIANCE.value:
            # Generate compliance-focused report from latest campaign or validation
            stmt_camp = select(SecurityCampaignModel).order_by(desc(SecurityCampaignModel.created_at)).limit(1)
            res_camp = await db.execute(stmt_camp)
            camp_row = res_camp.scalar_one_or_none()

            if camp_row and (req.campaign_id or not req.run_id):
                report_obj, evidence_items = await generate_campaign_report(
                    db=db,
                    campaign_id=req.campaign_id or camp_row.campaign_id,
                    user=user,
                    custom_title=req.title or "Comprehensive Compliance & Control Evidence Report",
                    custom_description="Detailed assessment evidence mapped to OWASP, MITRE ATLAS, and NIST AI RMF frameworks."
                )
            else:
                stmt_run = select(SecurityTestRunModel).order_by(desc(SecurityTestRunModel.started_at)).limit(1)
                res_run = await db.execute(stmt_run)
                run_row = res_run.scalar_one_or_none()
                if not run_row:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="No validation runs or campaigns available for compliance reporting."
                    )
                report_obj, evidence_items = await generate_security_validation_report(
                    db=db,
                    run_id=run_row.run_id,
                    user=user,
                    custom_title=req.title or "Comprehensive Compliance & Control Evidence Report"
                )
            report_obj.report_type = ReportType.COMPLIANCE.value

        elif rep_type == ReportType.GOVERNANCE.value:
            from backend.reporting.generator import generate_governance_report
            report_obj, evidence_items = await generate_governance_report(
                db=db,
                user=user,
                custom_title=req.title,
                custom_description=req.description
            )

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported report_type '{req.report_type}'."
            )

        # Persist SecurityReportModel
        es = report_obj.executive_summary
        model = SecurityReportModel(
            report_id=report_obj.report_id,
            report_type=report_obj.report_type,
            title=report_obj.title,
            description=report_obj.description,
            status=ReportStatus.COMPLETED.value,
            created_by=user,
            created_at=report_obj.created_at,
            completed_at=report_obj.completed_at,
            campaign_id=report_obj.campaign_id,
            campaign_run_id=report_obj.campaign_run_id,
            security_score=es.security_score,
            baseline_score=es.baseline_score,
            score_delta=es.score_delta,
            regression_count=es.regression_count,
            critical_findings=es.critical_findings,
            high_findings=es.high_findings,
            medium_findings=es.medium_findings,
            low_findings=es.low_findings,
            policy_version=report_obj.policy_version,
            report_version=report_obj.report_version,
            report_hash=report_obj.report_hash,
            report_data=report_obj.model_dump(mode="json")
        )
        db.add(model)

        # Persist Evidence Items
        for ev in evidence_items:
            ev_row = SecurityEvidenceModel(
                evidence_id=ev.evidence_id,
                report_id=report_obj.report_id,
                campaign_run_id=report_obj.campaign_run_id,
                test_id=ev.test_id,
                category=ev.category,
                severity=ev.severity,
                evidence_type=ev.evidence_type,
                expected_behavior=ev.expected_behavior,
                actual_behavior=ev.actual_behavior,
                security_control=ev.security_control,
                endpoint=ev.endpoint,
                status=ev.status,
                policy_version=ev.policy_version,
                created_at=ev.timestamp
            )
            db.add(ev_row)

        await db.commit()
        await db.refresh(model)

        duration = time.time() - start_time
        record_report_generated_metric(report_obj.report_type, "COMPLETED", duration)

        log_security_event(
            event_type="SECURITY_REPORT_GENERATED",
            request_id=f"rep-gen-{report_obj.report_id}",
            action="ALLOW",
            response_status=201,
            user=user,
            role="security-lead",
            threat_type=report_obj.report_type
        )

        return _to_report_summary(model)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate security report: {e}", exc_info=True)
        record_report_failed_metric(rep_type, "GENERATION_ERROR")
        log_security_event(
            event_type="SECURITY_REPORT_GENERATION_ERROR",
            request_id=f"rep-err-{uuid.uuid4().hex[:8]}",
            action="BLOCK",
            response_status=500,
            user=user,
            role="security-lead",
            threat_type=rep_type
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)}"
        )


async def get_report(db: AsyncSession, report_id: str) -> SecurityReport:
    """
    Retrieve full security report document by report_id.
    """
    stmt = select(SecurityReportModel).where(SecurityReportModel.report_id == report_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security report '{report_id}' not found."
        )

    if row.report_data:
        if isinstance(row.report_data, dict):
            return SecurityReport.model_validate(row.report_data)
        elif isinstance(row.report_data, str):
            return SecurityReport.model_validate_json(row.report_data)

    # Fallback reconstruction if report_data missing
    return SecurityReport(
        report_id=row.report_id,
        report_type=row.report_type,
        title=row.title,
        description=row.description,
        status=row.status,
        created_by=row.created_by,
        created_at=row.created_at,
        completed_at=row.completed_at,
        campaign_id=row.campaign_id,
        campaign_run_id=row.campaign_run_id,
        executive_summary={
            "security_score": row.security_score,
            "baseline_score": row.baseline_score,
            "score_delta": row.score_delta,
            "security_posture": "SECURE" if row.security_score >= 90 else "DEGRADED" if row.security_score >= 70 else "CRITICAL",
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "error_tests": 0,
            "skipped_tests": 0,
            "critical_findings": row.critical_findings,
            "high_findings": row.high_findings,
            "medium_findings": row.medium_findings,
            "low_findings": row.low_findings,
            "regression_count": row.regression_count,
            "open_alerts_count": 0,
            "policy_version": row.policy_version or "1.0.0",
            "generated_at": row.created_at
        },
        policy_version=row.policy_version or "1.0.0",
        report_version=row.report_version or "1.0.0",
        report_hash=row.report_hash,
        methodology="Automated synthetic validation",
        limitations="Mock provider enclave",
        compliance_disclaimer="Compliance mappings provide security-control evidence and assessment coverage only. They do not constitute certification, legal compliance, or an independent audit."
    )


async def list_reports(
    db: AsyncSession,
    report_type: Optional[str] = None,
    status_filter: Optional[str] = None,
    limit: int = 50
) -> List[ReportSummary]:
    """
    List security assessment report summaries.
    """
    query = select(SecurityReportModel).order_by(desc(SecurityReportModel.created_at))
    if report_type:
        query = query.where(SecurityReportModel.report_type == report_type.upper())
    if status_filter:
        query = query.where(SecurityReportModel.status == status_filter.upper())

    query = query.limit(limit)
    res = await db.execute(query)
    rows = res.scalars().all()
    return [_to_report_summary(r) for r in rows]


async def get_report_evidence(
    db: AsyncSession,
    report_id: str,
    limit: int = 100
) -> List[EvidenceItem]:
    """
    Retrieve normalized, sanitized evidence items for a report.
    """
    stmt = (
        select(SecurityEvidenceModel)
        .where(SecurityEvidenceModel.report_id == report_id)
        .order_by(SecurityEvidenceModel.category, SecurityEvidenceModel.test_id)
        .limit(limit)
    )
    res = await db.execute(stmt)
    rows = res.scalars().all()

    return [
        EvidenceItem(
            evidence_id=r.evidence_id,
            test_id=r.test_id,
            category=r.category,
            severity=r.severity,
            evidence_type=r.evidence_type,
            expected_behavior=r.expected_behavior,
            actual_behavior=r.actual_behavior,
            security_control=r.security_control,
            endpoint=r.endpoint,
            status=r.status,
            policy_version=r.policy_version or "1.0.0",
            timestamp=r.created_at
        )
        for r in rows
    ]


async def export_report(
    db: AsyncSession,
    report_id: str,
    export_format: str = "json"
) -> Tuple[Any, str, str]:
    """
    Export security report in requested format: json, markdown, csv, or pdf.
    Returns (payload, media_type, filename).
    """
    report = await get_report(db, report_id)
    evidence = await get_report_evidence(db, report_id, limit=200)

    fmt = export_format.lower()
    record_report_export_metric(fmt)

    log_security_event(
        event_type="SECURITY_REPORT_EXPORT",
        request_id=f"rep-exp-{report_id}",
        action="ALLOW",
        response_status=200,
        user="report-exporter",
        role="security-lead",
        threat_type=fmt
    )

    if fmt == "json":
        content = export_json(report)
        return content, "application/json", f"{report_id}.json"
    elif fmt in ("markdown", "md"):
        content = export_markdown(report)
        return content, "text/markdown", f"{report_id}.md"
    elif fmt == "csv":
        content = export_csv(report, evidence)
        return content, "text/csv", f"{report_id}.csv"
    elif fmt == "pdf":
        content_bytes = export_pdf(report, evidence)
        return content_bytes, "application/pdf", f"{report_id}.pdf"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported export format '{export_format}'. Supported: json, markdown, csv, pdf."
        )


async def verify_report_integrity_service(db: AsyncSession, report_id: str) -> Dict[str, Any]:
    """
    Verify report tamper protection and SHA-256 integrity hash.
    """
    stmt = select(SecurityReportModel).where(SecurityReportModel.report_id == report_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security report '{report_id}' not found."
        )

    if not row.report_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report data snapshot not found for integrity verification."
        )

    valid, message = verify_report_integrity(row.report_data)

    if not valid:
        record_report_integrity_failure_metric(row.report_type)
        log_security_event(
            event_type="SECURITY_REPORT_INTEGRITY_FAILURE",
            request_id=f"rep-int-{report_id}",
            action="BLOCK",
            response_status=400,
            user="integrity-verifier",
            role="security-lead",
            threat_type=row.report_type,
            risk_score=90
        )

    return {
        "report_id": report_id,
        "valid": valid,
        "persisted_hash": row.report_hash,
        "message": message,
        "verified_at": datetime.now(timezone.utc).isoformat()
    }


async def delete_report(db: AsyncSession, report_id: str, user: str) -> Dict[str, Any]:
    """
    Delete a security report and its linked evidence records.
    """
    stmt = select(SecurityReportModel).where(SecurityReportModel.report_id == report_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security report '{report_id}' not found."
        )

    # Delete evidence
    await db.execute(delete(SecurityEvidenceModel).where(SecurityEvidenceModel.report_id == report_id))
    await db.delete(row)
    await db.commit()

    return {"status": "deleted", "report_id": report_id}


def _to_report_summary(row: SecurityReportModel) -> ReportSummary:
    return ReportSummary(
        report_id=row.report_id,
        report_type=row.report_type,
        title=row.title,
        description=row.description,
        status=row.status,
        created_by=row.created_by,
        created_at=row.created_at,
        completed_at=row.completed_at,
        campaign_id=row.campaign_id,
        campaign_run_id=row.campaign_run_id,
        security_score=row.security_score,
        baseline_score=row.baseline_score,
        score_delta=row.score_delta,
        regression_count=row.regression_count,
        critical_findings=row.critical_findings,
        high_findings=row.high_findings,
        medium_findings=row.medium_findings,
        low_findings=row.low_findings,
        policy_version=row.policy_version or "1.0.0",
        report_version=row.report_version or "1.0.0",
        report_hash=row.report_hash
    )
