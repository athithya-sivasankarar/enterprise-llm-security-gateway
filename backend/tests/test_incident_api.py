import pytest
import httpx
from backend.main import app

ADMIN_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"


@pytest.mark.asyncio
async def test_incident_api_full_endpoints():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        headers = {"X-API-Key": ANALYST_API_KEY}

        # 1. Create Incident
        r_create = await client.post(
            "/api/incidents",
            headers=headers,
            json={
                "title": "API Test Security Incident",
                "description": "Integration testing incident endpoints",
                "severity": "HIGH",
                "priority": "P2"
            }
        )
        assert r_create.status_code == 201
        data = r_create.json()
        inc_id = data["incident_id"]
        assert inc_id.startswith("inc-")
        assert data["severity"] == "HIGH"

        # 2. Get Incident Detail
        r_get = await client.get(f"/api/incidents/{inc_id}", headers=headers)
        assert r_get.status_code == 200
        detail = r_get.json()
        assert detail["incident"]["incident_id"] == inc_id
        assert len(detail["timeline"]) >= 1

        # 3. Update Incident
        r_up = await client.put(
            f"/api/incidents/{inc_id}",
            headers=headers,
            json={"title": "Updated API Test Incident", "priority": "P1"}
        )
        assert r_up.status_code == 200
        assert r_up.json()["title"] == "Updated API Test Incident"
        assert r_up.json()["priority"] == "P1"

        # 4. Assign Incident
        r_assign = await client.post(
            f"/api/incidents/{inc_id}/assign",
            headers=headers,
            json={"assigned_to": "tier2-analyst"}
        )
        assert r_assign.status_code == 200
        assert r_assign.json()["assigned_to"] == "tier2-analyst"
        assert r_assign.json()["status"] == "INVESTIGATING"

        # 5. Add Note
        r_note = await client.post(
            f"/api/incidents/{inc_id}/notes",
            headers=headers,
            json={"note": "Investigating potential egress leak on port 443"}
        )
        assert r_note.status_code == 200
        assert r_note.json()["author"] == "security-analyst"

        # 6. Attach Evidence
        r_ev = await client.post(
            f"/api/incidents/{inc_id}/evidence",
            headers=headers,
            json={
                "evidence_type": "AUDIT_METADATA",
                "description": "Audit event log correlation artifact"
            }
        )
        assert r_ev.status_code == 200
        assert "sha256_hash" in r_ev.json()

        # 7. Get Evidence List
        r_ev_list = await client.get(f"/api/incidents/{inc_id}/evidence", headers=headers)
        assert r_ev_list.status_code == 200
        assert len(r_ev_list.json()) >= 1

        # 8. Record Response Action
        r_act = await client.post(
            f"/api/incidents/{inc_id}/actions",
            headers=headers,
            json={
                "action_type": "REQUEST_POLICY_REVIEW",
                "description": "Triggered automated policy review request"
            }
        )
        assert r_act.status_code == 200
        assert r_act.json()["action_type"] == "REQUEST_POLICY_REVIEW"

        # 9. Get Timeline
        r_time = await client.get(f"/api/incidents/{inc_id}/timeline", headers=headers)
        assert r_time.status_code == 200
        assert len(r_time.json()) >= 3

        # 10. Change Status
        r_st = await client.post(
            f"/api/incidents/{inc_id}/status",
            headers=headers,
            json={"status": "CONTAINED", "reason": "Threat contained"}
        )
        assert r_st.status_code == 200
        assert r_st.json()["status"] == "CONTAINED"

        # 11. Resolve Incident
        r_res = await client.post(
            f"/api/incidents/{inc_id}/resolve",
            headers=headers,
            json={"reason": "Remediated"}
        )
        assert r_res.status_code == 200
        assert r_res.json()["status"] == "RESOLVED"

        # 12. List & Summary
        r_list = await client.get("/api/incidents", headers=headers)
        assert r_list.status_code == 200
        assert len(r_list.json()) >= 1

        r_sum = await client.get("/api/incidents/summary", headers=headers)
        assert r_sum.status_code == 200
        assert r_sum.json()["resolved_incidents"] >= 1
