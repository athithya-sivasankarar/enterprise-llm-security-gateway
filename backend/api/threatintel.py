import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.security.rbac import require_dashboard_access
from backend.threatintel.models import (
    ThreatIntelItem,
    ThreatIntelCreateRequest,
    ThreatIntelSummary,
    ThreatIntelMatch,
    ThreatIntelMatchRequest
)
from backend.services.threatintel_service import (
    create_intelligence,
    get_intelligence,
    list_intelligence,
    get_threatintel_summary,
    match_intelligence_for_target
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threat-intelligence", tags=["Threat Intelligence"])


@router.post("", response_model=ThreatIntelItem, status_code=status.HTTP_201_CREATED)
async def create_intelligence_endpoint(
    req: ThreatIntelCreateRequest,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Ingest a new threat intelligence indicator (Admin/Analyst).
    """
    user = caller.get("username", "security-analyst")
    return await create_intelligence(db, req, user)


@router.get("", response_model=List[ThreatIntelItem])
async def list_intelligence_endpoint(
    category: Optional[str] = Query(None, description="Filter by security category"),
    indicator_type: Optional[str] = Query(None, description="Filter by indicator type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    List threat intelligence indicators from catalog and ingested feeds.
    """
    return await list_intelligence(db, category=category, indicator_type=indicator_type, severity=severity, limit=limit)


@router.get("/summary", response_model=ThreatIntelSummary)
async def get_threatintel_summary_endpoint(
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Get summary of active threat indicators and sources.
    """
    return await get_threatintel_summary(db)


@router.post("/match", response_model=List[ThreatIntelMatch])
async def match_intelligence_endpoint(
    req: ThreatIntelMatchRequest,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Deterministically match threat intelligence indicators to a category, test, finding, or incident.
    """
    user = caller.get("username", "security-analyst")
    return await match_intelligence_for_target(db, req, user)


@router.get("/{intel_id}", response_model=ThreatIntelItem)
async def get_intelligence_endpoint(
    intel_id: str,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Get threat intelligence indicator details.
    """
    return await get_intelligence(db, intel_id)
