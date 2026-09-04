import pytest
import httpx
from backend.main import app

ANALYST_API_KEY = "test-key-67890"


@pytest.mark.asyncio
async def test_threatintel_api_endpoints():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        headers = {"X-API-Key": ANALYST_API_KEY}

        # 1. Create Indicator
        r_create = await client.post(
            "/api/threat-intelligence",
            headers=headers,
            json={
                "source": "COMMUNITY",
                "indicator_type": "CVE",
                "indicator": "CVE-2024-9999",
                "category": "PROMPT_INJECTION",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "description": "API Test Threat Indicator for prompt injection"
            }
        )
        assert r_create.status_code == 201
        intel_id = r_create.json()["intel_id"]

        # 2. Get Detail
        r_get = await client.get(f"/api/threat-intelligence/{intel_id}", headers=headers)
        assert r_get.status_code == 200
        assert r_get.json()["indicator"] == "CVE-2024-9999"

        # 3. List
        r_list = await client.get("/api/threat-intelligence", headers=headers)
        assert r_list.status_code == 200
        assert len(r_list.json()) >= 1

        # 4. Summary
        r_sum = await client.get("/api/threat-intelligence/summary", headers=headers)
        assert r_sum.status_code == 200
        assert r_sum.json()["total_indicators"] >= 1

        # 5. Match
        r_match = await client.post(
            "/api/threat-intelligence/match",
            headers=headers,
            json={"category": "PROMPT_INJECTION"}
        )
        assert r_match.status_code == 200
        assert len(r_match.json()) >= 1
