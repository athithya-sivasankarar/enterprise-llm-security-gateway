import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from backend.db.database import AsyncSessionLocal
from backend.db.models import (
    SecurityRiskExceptionModel,
    SecurityGovernanceReviewModel,
    SecurityControlAssuranceModel,
    SecurityGovernanceEventModel
)


@pytest.mark.asyncio
async def test_governance_models_persistence():
    async with AsyncSessionLocal() as session:
        now = datetime.now(timezone.utc)
        future = now + timedelta(days=30)
        uid = uuid.uuid4().hex[:8].upper()

        exc_id = f"EXC-PERSIST-{uid}"
        rev_id = f"REV-PERSIST-{uid}"
        asr_id = f"ASR-PERSIST-{uid}"
        evt_id = f"GEVT-PERSIST-{uid}"

        # 1. Persist Risk Exception
        exc = SecurityRiskExceptionModel(
            exception_id=exc_id,
            title="Persistence Test Exception",
            description="Testing DB model persistence and fields",
            risk_type="DLP",
            severity="HIGH",
            status="APPROVED",
            business_justification="Valid justification string",
            owner="db-tester",
            requested_by="tester",
            approved_by="admin",
            requested_at=now,
            approved_at=now,
            effective_from=now,
            expires_at=future,
            risk_score=60,
            policy_version="1.0.0",
            created_at=now,
            updated_at=now
        )
        session.add(exc)

        # 2. Persist Governance Review
        rev = SecurityGovernanceReviewModel(
            review_id=rev_id,
            review_type="CONTROL_EFFECTIVENESS",
            scope="enterprise",
            status="COMPLETED",
            started_at=now,
            completed_at=now,
            reviewer="persister",
            overall_score=95.0,
            control_coverage=100.0,
            open_exceptions=1,
            overdue_exceptions=0,
            critical_exposures=0,
            open_incidents=0,
            policy_version="1.0.0",
            summary="Review persistence validation",
            created_at=now
        )
        session.add(rev)

        # 3. Persist Control Assurance
        asr = SecurityControlAssuranceModel(
            assurance_id=asr_id,
            control_id="AUTHENTICATION",
            assessment_period="current",
            test_count=10,
            passed_tests=10,
            failed_tests=0,
            coverage_percentage=100.0,
            effectiveness_score=100.0,
            gap_count=0,
            regression_count=0,
            last_tested_at=now,
            last_status="PASS",
            risk_score=0,
            policy_version="1.0.0",
            created_at=now,
            updated_at=now
        )
        session.add(asr)

        # 4. Persist Governance Event
        evt = SecurityGovernanceEventModel(
            event_id=evt_id,
            event_type="SECURITY_RISK_EXCEPTION_CREATED",
            entity_type="EXCEPTION",
            entity_id=exc_id,
            actor="tester",
            description="Audit persistence test",
            metadata_json={"test_key": "safe_value"},
            created_at=now
        )
        session.add(evt)

        await session.commit()

        # Query back and verify
        res_exc = await session.execute(select(SecurityRiskExceptionModel).where(SecurityRiskExceptionModel.exception_id == exc_id))
        assert res_exc.scalar_one_or_none() is not None

        res_rev = await session.execute(select(SecurityGovernanceReviewModel).where(SecurityGovernanceReviewModel.review_id == rev_id))
        assert res_rev.scalar_one_or_none() is not None

        res_asr = await session.execute(select(SecurityControlAssuranceModel).where(SecurityControlAssuranceModel.assurance_id == asr_id))
        assert res_asr.scalar_one_or_none() is not None

        res_evt = await session.execute(select(SecurityGovernanceEventModel).where(SecurityGovernanceEventModel.event_id == evt_id))
        assert res_evt.scalar_one_or_none() is not None
