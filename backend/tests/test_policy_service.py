import pytest
from backend.policy.models import PolicyCreateRequest
from backend.policy.defaults import get_default_policy
from backend.services.policy_service import (
    get_active_policy,
    create_policy,
    activate_policy,
    get_policy_history
)
from backend.db.database import AsyncSessionLocal


@pytest.mark.asyncio
async def test_get_active_policy_fail_safe():
    """Verify get_active_policy always returns a valid, secure policy object."""
    policy = await get_active_policy()
    assert policy is not None
    assert policy.policy_version is not None
    assert policy.rate_limit.requests >= 1
    assert policy.input_security.block_threshold >= 60


@pytest.mark.asyncio
async def test_policy_crud_and_activation_flow():
    """Test full cycle: create policy -> activate -> verify active -> rollback."""
    async with AsyncSessionLocal() as session:
        # 1. Create Policy 2.0.0
        custom_pol = get_default_policy()
        custom_pol.policy_version = "2.0.0"
        custom_pol.rate_limit.requests = 25

        create_req = PolicyCreateRequest(
            policy_version="2.0.0",
            name="High Throughput Policy",
            description="Policy with 25 req/min",
            policy=custom_pol
        )

        try:
            created = await create_policy(session, create_req, user="test-admin")
            assert created.policy_version == "2.0.0"
        except Exception as e:
            # If already exists from prior test runs, continue
            if "already exists" not in str(e):
                raise e

        # 2. Activate Policy 2.0.0
        activated = await activate_policy(session, "2.0.0", user="test-admin")
        assert activated.policy_version == "2.0.0"

        # 3. Check active policy
        active = await get_active_policy()
        assert active.policy_version == "2.0.0"
        assert active.rate_limit.requests == 25

        # 4. Rollback to 1.0.0
        rollback_pol = get_default_policy()
        rollback_req = PolicyCreateRequest(
            policy_version="1.0.0",
            name="Default Policy",
            description="Baseline default",
            policy=rollback_pol
        )
        try:
            await create_policy(session, rollback_req, user="test-admin")
        except Exception:
            pass

        reverted = await activate_policy(session, "1.0.0", user="test-admin")
        assert reverted.policy_version == "1.0.0"

        active_reverted = await get_active_policy()
        assert active_reverted.policy_version == "1.0.0"
        assert active_reverted.rate_limit.requests == 10
