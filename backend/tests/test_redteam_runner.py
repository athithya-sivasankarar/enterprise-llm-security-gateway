import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.redteam.runner import run_security_validation_suite
from backend.redteam.reporter import format_text_report
from backend.redteam.categories import TestCategory, TestStatus


@pytest.mark.asyncio
async def test_redteam_runner_full_suite_execution():
    """Verify that the runner executes the full deterministic validation suite and passes."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        report = await run_security_validation_suite(
            created_by="pytest-runner",
            custom_client=client
        )

        assert report is not None
        assert report.run_id.startswith("run-")
        assert report.status in ("COMPLETED", "COMPLETED_WITH_FAILURES", "COMPLETED_WITH_ERRORS")
        assert report.security_score >= 80.0
        assert len(report.test_results) >= 14
        assert len(report.category_summaries) >= 14

        # Check summary breakdown
        summary = report.summary
        assert summary["total_tests"] == len(report.test_results)
        assert summary["passed_tests"] > 0
        assert summary["error_tests"] == 0

        # Verify text report generation
        text_rep = format_text_report(report)
        assert "SECURITY VALIDATION REPORT" in text_rep
        assert report.run_id in text_rep


@pytest.mark.asyncio
async def test_redteam_runner_category_filtered_run():
    """Verify executing only a specific category works with deterministic score calculation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        report = await run_security_validation_suite(
            categories=["AUTHENTICATION"],
            created_by="pytest-auth-runner",
            custom_client=client
        )

        assert len(report.test_results) == 3
        assert all(r.category == "AUTHENTICATION" for r in report.test_results)
        assert report.security_score == 100.0


@pytest.mark.asyncio
async def test_redteam_runner_dlp_and_injection_categories():
    """Verify DLP and Prompt Injection validation assertions."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        report = await run_security_validation_suite(
            categories=["INPUT_DLP", "PROMPT_INJECTION"],
            created_by="pytest-dlp-inj-runner",
            custom_client=client
        )

        assert len(report.test_results) >= 6
        assert report.security_score == 100.0
        for r in report.test_results:
            assert r.status == TestStatus.PASS.value
