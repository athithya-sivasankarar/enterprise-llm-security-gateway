import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app


@pytest.mark.asyncio
async def test_security_tests_api_rbac_enforcement():
    """Verify that only admin and analyst roles can trigger tests, while developers get 403."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Developer: Denied 403
        dev_res = await client.post(
            "/api/security-tests/run",
            json={"categories": ["AUTHENTICATION"]},
            headers={"X-API-Key": "dev-user-key-54321"}
        )
        assert dev_res.status_code == 403

        # Unauthenticated: Denied 401
        noauth_res = await client.post(
            "/api/security-tests/run",
            json={"categories": ["AUTHENTICATION"]}
        )
        assert noauth_res.status_code == 401

        # Analyst: Allowed 200
        analyst_res = await client.post(
            "/api/security-tests/run",
            json={"categories": ["AUTHENTICATION"]},
            headers={"X-API-Key": "test-key-67890"}
        )
        assert analyst_res.status_code == 200
        analyst_data = analyst_res.json()
        assert "run_id" in analyst_data
        assert analyst_data["security_score"] == 100.0

        # Admin: Allowed 200
        admin_res = await client.post(
            "/api/security-tests/run",
            json={"categories": ["AUTHENTICATION"]},
            headers={"X-API-Key": "dev-key-12345"}
        )
        assert admin_res.status_code == 200
        assert "run_id" in admin_res.json()


@pytest.mark.asyncio
async def test_security_tests_api_invalid_category_rejection():
    """Verify that an invalid category name returns HTTP 400 Bad Request."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/security-tests/run",
            json={"categories": ["NON_EXISTENT_CATEGORY_XYZ"]},
            headers={"X-API-Key": "dev-key-12345"}
        )
        assert res.status_code == 400
        assert "Invalid category" in res.json().get("detail", "")


@pytest.mark.asyncio
async def test_security_tests_api_catalog_endpoint():
    """Verify /api/security-tests/catalog returns all available tests and categories."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/api/security-tests/catalog",
            headers={"X-API-Key": "test-key-67890"}
        )
        assert res.status_code == 200
        data = res.json()
        assert "total" in data
        assert data["total"] >= 14
        assert "categories" in data
        assert "AUTHENTICATION" in data["categories"]
        assert "tests" in data


@pytest.mark.asyncio
async def test_security_tests_api_runs_and_reports_flow():
    """Verify listing runs and fetching reports."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-API-Key": "dev-key-12345"}

        # 1. Run tests
        run_res = await client.post(
            "/api/security-tests/run",
            json={"categories": ["AUTHENTICATION"]},
            headers=headers
        )
        assert run_res.status_code == 200
        run_id = run_res.json()["run_id"]

        # 2. List runs
        runs_res = await client.get("/api/security-tests/runs", headers=headers)
        assert runs_res.status_code == 200
        runs = runs_res.json()
        assert any(r["run_id"] == run_id for r in runs)

        # 3. Get single run
        single_res = await client.get(f"/api/security-tests/runs/{run_id}", headers=headers)
        assert single_res.status_code == 200
        assert single_res.json()["run_id"] == run_id

        # 4. Get full report
        rep_res = await client.get(f"/api/security-tests/runs/{run_id}/report", headers=headers)
        assert rep_res.status_code == 200
        rep = rep_res.json()
        assert rep["run_id"] == run_id
        assert len(rep["test_results"]) == 3
