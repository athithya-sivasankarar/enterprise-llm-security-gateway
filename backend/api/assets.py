import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.security.rbac import require_dashboard_access
from backend.attack_surface.models import (
    SecurityAsset,
    AssetCreateRequest,
    AssetUpdateRequest,
    AssetSummary,
    AssetCoverageDetail,
    AttackSurfaceGraph
)
from backend.services.asset_service import (
    register_asset,
    get_asset,
    list_assets,
    update_asset,
    get_asset_coverage,
    get_asset_summary,
    get_attack_surface_graph
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/assets", tags=["Attack Surface & Asset Inventory"])


@router.post("", response_model=SecurityAsset, status_code=status.HTTP_201_CREATED)
async def create_asset_endpoint(
    req: AssetCreateRequest,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Register a new AI/LLM asset or gateway component into inventory.
    """
    user = caller.get("username", "security-analyst")
    return await register_asset(db, req, user)


@router.get("", response_model=List[SecurityAsset])
async def list_assets_endpoint(
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    criticality: Optional[str] = Query(None, description="Filter by criticality"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    List inventoried assets with optional filters.
    """
    return await list_assets(db, asset_type=asset_type, criticality=criticality, status_filter=status_filter)


@router.get("/summary", response_model=AssetSummary)
async def get_asset_summary_endpoint(
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Get aggregated asset inventory counts and risk averages.
    """
    return await get_asset_summary(db)


@router.get("/attack-surface", response_model=AttackSurfaceGraph)
async def get_attack_surface_graph_endpoint(
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Retrieve logical attack surface dataflow graph.
    """
    return await get_attack_surface_graph(db)


@router.get("/{asset_id}", response_model=SecurityAsset)
async def get_asset_endpoint(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Get details for an inventoried asset.
    """
    return await get_asset(db, asset_id)


@router.put("/{asset_id}", response_model=SecurityAsset)
async def update_asset_endpoint(
    asset_id: str,
    req: AssetUpdateRequest,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Update metadata or criticality for an inventoried asset.
    """
    user = caller.get("username", "security-analyst")
    return await update_asset(db, asset_id, req, user)


@router.get("/{asset_id}/coverage", response_model=AssetCoverageDetail)
async def get_asset_coverage_endpoint(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    caller: dict = Depends(require_dashboard_access)
):
    """
    Calculate multidimensional test and control coverage for an asset.
    """
    return await get_asset_coverage(db, asset_id)
