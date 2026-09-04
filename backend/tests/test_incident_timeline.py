import pytest
from datetime import datetime, timezone
from backend.db.database import AsyncSessionLocal
from backend.services.incident_service import (
    create_incident,
    add_incident_note,
    attach_evidence,
    record_response_action,
    change_incident_status,
    get_incident_timeline
)
from backend.incidents.models import IncidentCreateRequest


@pytest.mark.asyncio
async def test_incident_timeline_chronological_assembly():
    async with AsyncSessionLocal() as session:
        # 1. Create incident
        inc = await create_incident(
            session,
            IncidentCreateRequest(
                title="Timeline Validation Incident",
                description="Testing chronological timeline construction",
                severity="HIGH"
            ),
            user="security-analyst"
        )

        # 2. Add analyst note
        await add_incident_note(
            session,
            inc.incident_id,
            "Initial observation: elevated risk on endpoint",
            author="lead-analyst"
        )

        # 3. Attach evidence
        await attach_evidence(
            session,
            inc.incident_id,
            evidence_type="SECURITY_TEST_RESULT",
            description="Sanitized test finding artifact",
            user="security-analyst"
        )

        # 4. Record action
        await record_response_action(
            session,
            inc.incident_id,
            action_type="REQUEST_POLICY_REVIEW",
            description="Submitted policy review request",
            requested_by="security-analyst"
        )

        # 5. Change status
        await change_incident_status(
            session,
            inc.incident_id,
            "INVESTIGATING",
            user="security-analyst",
            reason="Investigation in progress"
        )

        # 6. Retrieve timeline
        timeline = await get_incident_timeline(session, inc.incident_id)

        assert len(timeline) >= 4

        # Verify strictly chronological ordering
        for i in range(len(timeline) - 1):
            assert timeline[i].timestamp <= timeline[i + 1].timestamp

        event_types = [ev.event_type for ev in timeline]
        assert "INCIDENT_CREATED" in event_types
        assert "ANALYST_NOTE_ADDED" in event_types
        assert "EVIDENCE_ATTACHED" in event_types
        assert "ACTION_REQUEST_POLICY_REVIEW" in event_types
