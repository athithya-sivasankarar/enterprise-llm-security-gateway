import pytest
from datetime import datetime, timezone
from sqlalchemy import select
from backend.db.database import AsyncSessionLocal
from backend.db.models import (
    SecurityIncidentModel,
    SecurityIncidentEventModel,
    SecurityIncidentEvidenceModel,
    SecurityIncidentNoteModel,
    SecurityIncidentActionModel
)


@pytest.mark.asyncio
async def test_incident_persistence_models():
    async with AsyncSessionLocal() as session:
        inc_id = f"inc-persist-{int(datetime.now().timestamp())}"
        now = datetime.now(timezone.utc)

        # 1. Incident Model
        inc = SecurityIncidentModel(
            incident_id=inc_id,
            title="Persistence Model Test",
            description="Testing DB columns and indexes",
            incident_type="SECURITY_REGRESSION",
            severity="CRITICAL",
            status="OPEN",
            priority="P1",
            created_at=now,
            updated_at=now,
            detected_at=now,
            created_by="test-user",
            risk_score=85
        )
        session.add(inc)

        # 2. Event Model
        event = SecurityIncidentEventModel(
            event_id=f"ev-{inc_id}",
            incident_id=inc_id,
            event_type="TEST_EVENT",
            event_timestamp=now,
            source_type="TEST",
            severity="INFO",
            description="Persisted test event",
            metadata_json={"key": "value"},
            created_at=now
        )
        session.add(event)

        # 3. Evidence Model
        evidence = SecurityIncidentEvidenceModel(
            evidence_id=f"evd-{inc_id}",
            incident_id=inc_id,
            evidence_type="FINDING",
            description="Persisted test evidence",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            created_at=now,
            created_by="test-user"
        )
        session.add(evidence)

        # 4. Note Model
        note = SecurityIncidentNoteModel(
            note_id=f"note-{inc_id}",
            incident_id=inc_id,
            author="test-analyst",
            note="Persisted test note",
            created_at=now
        )
        session.add(note)

        # 5. Action Model
        action = SecurityIncidentActionModel(
            action_id=f"act-{inc_id}",
            incident_id=inc_id,
            action_type="REQUEST_POLICY_REVIEW",
            requested_by="test-analyst",
            approved_by="test-admin",
            status="COMPLETED",
            description="Persisted action",
            created_at=now,
            completed_at=now
        )
        session.add(action)

        await session.commit()

        # Query and verify
        stmt = select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == inc_id)
        res = await session.execute(stmt)
        row = res.scalar_one_or_none()
        assert row is not None
        assert row.risk_score == 85
        assert row.severity == "CRITICAL"
