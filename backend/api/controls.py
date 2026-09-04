import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.security.rbac import require_dashboard_access
from backend.control_coverage.models import (
    SecurityControlItem,
    ControlCoverageSummary,
    ControlGapItem
)
from backend.services.control_service import (
    list_controls,
    get_control,
    get_control_coverage,
    get_control_gaps
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/controls", tags=["Security Control Coverage"])


@router.get("", response_model=List[SecurityControlItem])
async def list_controls_endpoint(
    domain: Optional[str] = Query(None, description="Filter by control domain"),
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    List all inventoried security controls.
    """
    return await list_controls(db, domain=domain)


@router.get("/coverage", response_model=ControlCoverageSummary)
async def get_control_coverage_endpoint(
    run_id: Optional[str] = Query(None, description="Optional security test run ID to scope coverage"),
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Calculate overall security control coverage, pass percentage, and matrix.
    """
    return await get_control_coverage(db, run_id=run_id)


@router.get("/gaps", response_model=List[ControlGapItem])
async def get_control_gaps_endpoint(
    run_id: Optional[str] = Query(None, description="Optional security test run ID"),
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    List detected security control gaps with actionable recommendations.
    """
    return await get_control_gaps(db, run_id=run_id)


@router.get("/{control_id}", response_model=SecurityControlItem)
async def get_control_endpoint(
    control_id: str,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Get details for a specific security control.
    """
    return await get_control(db, control_id)
