import pytest
import httpx
from backend.main import app

ADMIN_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"
DEVELOPER_API_KEY = "dev-user-key-54321"


@pytest.mark.asyncio
async def test_reports_api_rbac_and_endpoints_flow():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # Create a campaign and run it first
        r_camp = await client.post(
            "/api/campaigns",
            headers={"X-API-Key": ADMIN_API_KEY},
            json={"name": "Reports API Test Campaign", "category_filter": ["AUTHENTICATION"]}
        )
        camp_id = r_camp.json()["campaign_id"]
        await client.post(f"/api/campaigns/{camp_id}/execute", headers={"X-API-Key": ADMIN_API_KEY})

        # 1. Unauthenticated create -> 401
        r_unauth = await client.post("/api/reports", json={"report_type": "CAMPAIGN", "campaign_id": camp_id})
        assert r_unauth.status_code == 401

        # 2. Developer create -> 403
        r_dev = await client.post(
            "/api/reports",
            headers={"X-API-Key": DEVELOPER_API_KEY},
            json={"report_type": "CAMPAIGN", "campaign_id": camp_id}
        )
        assert r_dev.status_code == 403

        # 3. Analyst create -> 201
        r_create = await client.post(
            "/api/reports",
            headers={"X-API-Key": ANALYST_API_KEY},
            json={"report_type": "CAMPAIGN", "campaign_id": camp_id, "title": "Analyst Report"}
        )
        assert r_create.status_code == 201
        rep_id = r_create.json()["report_id"]

        # 4. List reports
        r_list = await client.get("/api/reports", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_list.status_code == 200
        assert any(r["report_id"] == rep_id for r in r_list.json())

        # 5. Get report details
        r_get = await client.get(f"/api/reports/{rep_id}", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_get.status_code == 200
        assert r_get.json()["report_id"] == rep_id

        # 6. Get evidence
        r_ev = await client.get(f"/api/reports/{rep_id}/evidence", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_ev.status_code == 200
        assert isinstance(r_ev.json(), list)

        # 7. Exports (JSON, Markdown, CSV, PDF)
        r_exp_json = await client.get(f"/api/reports/{rep_id}/export?format=json", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_exp_json.status_code == 200

        r_exp_md = await client.get(f"/api/reports/{rep_id}/export?format=markdown", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_exp_md.status_code == 200

        r_exp_csv = await client.get(f"/api/reports/{rep_id}/export?format=csv", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_exp_csv.status_code == 200

        r_exp_pdf = await client.get(f"/api/reports/{rep_id}/export?format=pdf", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_exp_pdf.status_code == 200
        assert r_exp_pdf.content.startswith(b"%PDF-")

        # 8. Verify Integrity
        r_verify = await client.get(f"/api/reports/{rep_id}/verify", headers={"X-API-Key": ANALYST_API_KEY})
        assert r_verify.status_code == 200
        assert r_verify.json()["valid"] is True

        # 9. Developer cannot export or verify -> 403
        r_dev_exp = await client.get(f"/api/reports/{rep_id}/export?format=json", headers={"X-API-Key": DEVELOPER_API_KEY})
        assert r_dev_exp.status_code == 403

        # 10. Admin delete report -> 200
        r_del = await client.delete(f"/api/reports/{rep_id}", headers={"X-API-Key": ADMIN_API_KEY})
        assert r_del.status_code == 200
