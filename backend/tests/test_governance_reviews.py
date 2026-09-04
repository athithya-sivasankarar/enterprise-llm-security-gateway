import pytest
from backend.db.database import AsyncSessionLocal
from backend.governance.models import (
    GovernanceReviewCreateRequest,
    GovernanceReviewType,
    GovernanceReviewStatus
)
from backend.governance.reviews import (
    create_governance_review,
    get_governance_review,
    list_governance_reviews
)


@pytest.mark.asyncio
async def test_create_and_list_governance_reviews():
    async with AsyncSessionLocal() as session:
        for rev_type in GovernanceReviewType:
            req = GovernanceReviewCreateRequest(
                review_type=rev_type,
                scope="enterprise-wide",
                reviewer="chief-security-officer",
                notes="Formal quarterly governance review test"
            )
            review = await create_governance_review(session, req, reviewer="chief-security-officer")
            assert review.review_id.startswith("REV-")
            assert review.review_type == rev_type.value
            assert review.status == GovernanceReviewStatus.COMPLETED.value
            assert 0.0 <= review.overall_score <= 100.0
            assert "Security Governance Review" in review.summary

            fetched = await get_governance_review(session, review.review_id)
            assert fetched is not None
            assert fetched.review_id == review.review_id

        all_revs = await list_governance_reviews(session, limit=20)
        assert len(all_revs) >= 5
