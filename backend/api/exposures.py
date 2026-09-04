import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.security.rbac import require_dashboard_access
from backend.services.exposure_service import (
    SecurityExposureItem,
    ExposureCreateRequest,
    ExposureResolveRequest,
    ExposureSummary,
    create_exposure,
    list_exposures,
    get_exposure,
    resolve_exposure,
    get_exposure_summary
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/exposures", tags=["Exposure Management"])


@router.post("", response_model=SecurityExposureItem, status_code=status.HTTP_201_CREATED)
async def create_exposure_endpoint(
    req: ExposureCreateRequest,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Create a new security exposure entry.
    """
    user = caller.get("username", "security-analyst")
    return await create_exposure(db, req, user)


@router.get("", response_model=List[SecurityExposureItem])
async def list_exposures_endpoint(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    asset_id: Optional[str] = Query(None, description="Filter by asset ID"),
    category: Optional[str] = Query(None, description="Filter by category"),
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    List security exposures with optional filters.
    """
    return await list_exposures(db, status_filter=status_filter, severity=severity, asset_id=asset_id, category=category)


@router.get("/summary", response_model=ExposureSummary)
async def get_exposure_summary_endpoint(
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Get enterprise exposure statistics and overall risk score.
    """
    return await get_exposure_summary(db)


@router.get("/{exposure_id}", response_model=SecurityExposureItem)
async def get_exposure_endpoint(
    exposure_id: str,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Get details of a specific security exposure.
    """
    return await get_exposure(db, exposure_id)


@router.post("/{exposure_id}/resolve", response_model=SecurityExposureItem)
async def resolve_exposure_endpoint(
    exposure_id: str,
    req: ExposureResolveRequest,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Mark a security exposure resolved.
    """
    user = caller.get("username", "security-analyst")
    return await resolve_exposure(db, exposure_id, req, user)
