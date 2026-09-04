import pytest
from backend.db.database import AsyncSessionLocal
from backend.services.asset_service import (
    register_asset,
    get_asset,
    list_assets,
    update_asset,
    get_asset_coverage,
    get_asset_summary
)
from backend.attack_surface.models import (
    AssetCreateRequest,
    AssetUpdateRequest
)


@pytest.mark.asyncio
async def test_asset_service_lifecycle():
    async with AsyncSessionLocal() as session:
        # Register
        req = AssetCreateRequest(
            asset_type="LLM_MODEL",
            name="Synthetic Test LLM",
            description="Integration test asset",
            environment="staging",
            endpoint="/api/chat",
            provider="mock",
            model="mock-test",
            criticality="CRITICAL"
        )
        asset = await register_asset(session, req, user="admin")
        assert asset.asset_id.startswith("ast-")
        assert asset.criticality == "CRITICAL"

        # Get
        fetched = await get_asset(session, asset.asset_id)
        assert fetched.asset_id == asset.asset_id

        # Update
        updated = await update_asset(
            session,
            asset.asset_id,
            AssetUpdateRequest(name="Updated Synthetic LLM", criticality="HIGH"),
            user="admin"
        )
        assert updated.name == "Updated Synthetic LLM"
        assert updated.criticality == "HIGH"

        # List
        assets = await list_assets(session, asset_type="LLM_MODEL")
        assert len(assets) >= 1

        # Summary
        summary = await get_asset_summary(session)
        assert summary.total_assets >= 1
        assert summary.critical_assets >= 1

        # Coverage
        cov = await get_asset_coverage(session, asset.asset_id)
        assert len(cov.controls_mapped) >= 1
        assert len(cov.tests_mapped) >= 1
