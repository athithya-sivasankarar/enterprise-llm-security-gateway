import pytest
from backend.db.database import AsyncSessionLocal
from backend.services.incident_service import (
    create_incident,
    get_incident,
    list_incidents,
    get_incident_summary,
    update_incident,
    assign_incident,
    change_incident_status,
    add_incident_note,
    attach_evidence,
    record_response_action,
    get_incident_detail
)
from backend.incidents.models import (
    IncidentCreateRequest,
    IncidentUpdateRequest,
    IncidentStatus
)


@pytest.mark.asyncio
async def test_incident_service_crud_and_lifecycle():
    async with AsyncSessionLocal() as session:
        # Create
        inc = await create_incident(
            session,
            IncidentCreateRequest(
                title="Service Lifecycle Incident",
                description="Testing full service lifecycle",
                severity="HIGH",
                priority="P1"
            ),
            user="admin"
        )
        assert inc.incident_id.startswith("inc-")
        assert inc.severity == "HIGH"
        assert inc.status == "OPEN"

        # Get
        fetched = await get_incident(session, inc.incident_id)
        assert fetched.incident_id == inc.incident_id

        # Update
        updated = await update_incident(
            session,
            inc.incident_id,
            IncidentUpdateRequest(title="Updated Title", priority="P2"),
            user="admin"
        )
        assert updated.title == "Updated Title"
        assert updated.priority == "P2"

        # Assign
        assigned = await assign_incident(session, inc.incident_id, "analyst-alice", "admin")
        assert assigned.assigned_to == "analyst-alice"
        assert assigned.status == "INVESTIGATING"

        # Status transition
        status_updated = await change_incident_status(
            session,
            inc.incident_id,
            "RESOLVED",
            user="analyst-alice",
            reason="Mitigated through policy update"
        )
        assert status_updated.status == "RESOLVED"
        assert status_updated.resolved_at is not None

        # Summary
        summary = await get_incident_summary(session)
        assert summary.total_incidents >= 1
        assert summary.resolved_incidents >= 1

        # Deep detail response
        detail = await get_incident_detail(session, inc.incident_id)
        assert detail.incident.incident_id == inc.incident_id
        assert len(detail.timeline) >= 1
