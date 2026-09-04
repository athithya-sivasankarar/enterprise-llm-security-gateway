import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.security.rbac import require_dashboard_access
from backend.alerts.models import (
    SecurityAlert,
    AlertSummary,
    AlertUpdateRequest
)
from backend.services.alert_service import (
    list_alerts as svc_list_alerts,
    get_alert as svc_get_alert,
    get_open_alerts as svc_get_open_alerts,
    get_alert_summary as svc_get_alert_summary,
    acknowledge_alert as svc_acknowledge_alert,
    resolve_alert as svc_resolve_alert
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alerts", tags=["Security Alerts & Incident Response"])


@router.get("", response_model=List[SecurityAlert])
async def list_alerts(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    List security alerts with optional filtering by status and severity.
    """
    return await svc_list_alerts(db, status, severity, limit)


@router.get("/summary", response_model=AlertSummary)
async def get_alert_summary(
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve aggregated alert metrics across severities and statuses.
    """
    return await svc_get_alert_summary(db)


@router.get("/open", response_model=List[SecurityAlert])
async def get_open_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve active open security alerts requiring SOC analyst attention.
    """
    return await svc_get_open_alerts(db, limit)


@router.get("/{alert_id}", response_model=SecurityAlert)
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Get detailed information for a specific alert.
    """
    return await svc_get_alert(db, alert_id)


@router.post("/{alert_id}/acknowledge", response_model=SecurityAlert)
async def acknowledge_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Acknowledge an active security alert.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_acknowledge_alert(db, alert_id, username)


@router.post("/{alert_id}/resolve", response_model=SecurityAlert)
async def resolve_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Mark a security alert as resolved.
    """
    username = user_data.get("user", "authenticated-user")
    return await svc_resolve_alert(db, alert_id, username)
