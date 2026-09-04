import pytest
import httpx
from datetime import datetime, timezone, timedelta
from backend.main import app

ADMIN_API_KEY = "dev-key-12345"
ANALYST_API_KEY = "test-key-67890"


@pytest.mark.asyncio
async def test_governance_api_endpoints_full_lifecycle():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        headers = {"X-API-Key": ADMIN_API_KEY}

        # 1. Summary & Risk
        r_sum = await client.get("/api/governance/summary", headers=headers)
        assert r_sum.status_code == 200
        assert "governance_risk_score" in r_sum.json()

        r_risk = await client.get("/api/governance/risk", headers=headers)
        assert r_risk.status_code == 200
        assert "overall_risk_score" in r_risk.json()

        # 2. Controls & Assurance
        r_ctrls = await client.get("/api/governance/controls", headers=headers)
        assert r_ctrls.status_code == 200
        assert len(r_ctrls.json()) == 14

        r_eval = await client.post("/api/governance/assurance/run", headers=headers)
        assert r_eval.status_code == 200
        assert len(r_eval.json()) == 14

        # 3. Create Exception
        future_exp = (datetime.now(timezone.utc) + timedelta(days=45)).isoformat()
        r_create = await client.post(
            "/api/governance/exceptions",
            headers=headers,
            json={
                "title": "API Exception Management Test",
                "description": "Validating full REST API lifecycle for governance exceptions",
                "severity": "HIGH",
                "business_justification": "Temporary risk acceptance for staging load test",
                "owner": "api-testing-team",
                "expires_at": future_exp
            }
        )
        assert r_create.status_code == 201
        exc_id = r_create.json()["exception_id"]

        # 4. Get Exception Detail
        r_get = await client.get(f"/api/governance/exceptions/{exc_id}", headers=headers)
        assert r_get.status_code == 200
        assert r_get.json()["exception_id"] == exc_id

        # 5. Update Exception
        r_put = await client.put(
            f"/api/governance/exceptions/{exc_id}",
            headers=headers,
            json={"title": "Updated API Exception Title"}
        )
        assert r_put.status_code == 200
        assert r_put.json()["title"] == "Updated API Exception Title"

        # 6. Submit for Approval
        r_sub = await client.post(f"/api/governance/exceptions/{exc_id}/submit", headers=headers)
        assert r_sub.status_code == 200
        assert r_sub.json()["status"] == "PENDING_APPROVAL"

        # 7. Approve
        r_app = await client.post(
            f"/api/governance/exceptions/{exc_id}/approve",
            headers=headers,
            json={"decision": "APPROVE", "notes": "Approved via test suite"}
        )
        assert r_app.status_code == 200
        assert r_app.json()["status"] == "APPROVED"

        # 8. Renew
        new_exp = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        r_ren = await client.post(
            f"/api/governance/exceptions/{exc_id}/renew",
            headers=headers,
            json={"new_expires_at": new_exp, "renewal_justification": "Extending risk window for Q2 tests"}
        )
        assert r_ren.status_code == 200
        assert r_ren.json()["status"] == "APPROVED"

        # 9. List Exceptions
        r_list = await client.get("/api/governance/exceptions", headers=headers)
        assert r_list.status_code == 200
        assert len(r_list.json()) >= 1

        # 10. Overdue Exceptions
        r_over = await client.get("/api/governance/exceptions/overdue", headers=headers)
        assert r_over.status_code == 200

        # 11. Create & Get Governance Review
        r_rev_post = await client.post(
            "/api/governance/reviews",
            headers=headers,
            json={
                "review_type": "EXECUTIVE_SECURITY_REVIEW",
                "scope": "enterprise",
                "reviewer": "test-ciso",
                "notes": "API test executive review"
            }
        )
        assert r_rev_post.status_code == 201
        rev_id = r_rev_post.json()["review_id"]

        r_rev_get = await client.get(f"/api/governance/reviews/{rev_id}", headers=headers)
        assert r_rev_get.status_code == 200
        assert r_rev_get.json()["review_id"] == rev_id

        # 12. Governance Events
        r_evts = await client.get("/api/governance/events", headers=headers)
        assert r_evts.status_code == 200
        assert len(r_evts.json()) >= 1
