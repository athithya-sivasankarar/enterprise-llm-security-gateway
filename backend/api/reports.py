import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.security.rbac import require_dashboard_access
from backend.reporting.models import (
    ReportCreateRequest,
    ReportSummary,
    SecurityReport,
    EvidenceItem
)
from backend.services.report_service import (
    create_report as svc_create_report,
    get_report as svc_get_report,
    list_reports as svc_list_reports,
    delete_report as svc_delete_report,
    get_report_evidence as svc_get_report_evidence,
    export_report as svc_export_report,
    verify_report_integrity_service as svc_verify_report_integrity
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["Security Assessment Reports & Evidence"])


@router.post("", response_model=ReportSummary, status_code=status.HTTP_201_CREATED)
async def create_report(
    req: ReportCreateRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Create and generate an auditable security assessment report.
    Restricted to Admin and Analyst roles (Developer receives HTTP 403).
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_create_report(db, req, username)


@router.get("", response_model=List[ReportSummary])
async def list_reports(
    report_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    List generated security reports.
    """
    return await svc_list_reports(db, report_type, status, limit)


@router.get("/{report_id}", response_model=SecurityReport)
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve full security assessment report document.
    """
    return await svc_get_report(db, report_id)


@router.post("/{report_id}/generate", response_model=ReportSummary)
async def regenerate_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Regenerate report data from underlying source runs.
    """
    username = user_data.get("user", "authenticated-user")
    rep = await svc_get_report(db, report_id)
    req = ReportCreateRequest(
        report_type=rep.report_type,
        title=rep.title,
        description=rep.description,
        campaign_id=rep.campaign_id,
        campaign_run_id=rep.campaign_run_id
    )
    return await svc_create_report(db, req, username)


@router.get("/{report_id}/evidence", response_model=List[EvidenceItem])
async def get_report_evidence(
    report_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve normalized, sanitized evidence items associated with a report.
    """
    return await svc_get_report_evidence(db, report_id, limit)


@router.get("/{report_id}/export")
async def export_report(
    report_id: str,
    format: str = Query(default="json", description="json, markdown, csv, pdf"),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Export security report in requested format: json, markdown, csv, or pdf.
    """
    content, media_type, filename = await svc_export_report(db, report_id, format)

    if isinstance(content, bytes):
        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    else:
        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )


@router.get("/{report_id}/verify")
async def verify_report_integrity(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Verify report SHA-256 tamper-protection integrity.
    """
    return await svc_verify_report_integrity(db, report_id)


@router.delete("/{report_id}")
async def delete_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Delete a security report and linked evidence.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_delete_report(db, report_id, username)
