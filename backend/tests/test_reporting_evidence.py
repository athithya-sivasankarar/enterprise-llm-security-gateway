import pytest
from backend.db.database import AsyncSessionLocal
from backend.db.models import SecurityTestRunModel, SecurityTestResultModel
from backend.reporting.evidence import collect_evidence_for_run, collect_findings_for_run
import uuid
from datetime import datetime, timezone


@pytest.mark.asyncio
async def test_evidence_collection_and_sanitization():
    async with AsyncSessionLocal() as session:
        run_id = f"test-run-{uuid.uuid4().hex[:8]}"

        # Insert sample test run header
        run_row = SecurityTestRunModel(
            run_id=run_id,
            status="COMPLETED",
            total_tests=2,
            passed_tests=1,
            failed_tests=1,
            error_tests=0,
            skipped_tests=0,
            security_score=50.0,
            created_by="evidence-tester",
            policy_version="1.0.0"
        )
        session.add(run_row)

        # Insert sample test results with potential sensitive payload text
        res1 = SecurityTestResultModel(
            run_id=run_id,
            test_id="INJ-001",
            category="PROMPT_INJECTION",
            severity="CRITICAL",
            status="PASS",
            expected_action="BLOCK",
            actual_action="BLOCK",
            expected_status=400,
            actual_status=400,
            latency_ms=12.5,
            error_message="Blocked with sk-12345678901234567890 key check",
            created_at=datetime.now(timezone.utc)
        )
        res2 = SecurityTestResultModel(
            run_id=run_id,
            test_id="DLP-001",
            category="INPUT_DLP",
            severity="HIGH",
            status="FAIL",
            expected_action="BLOCK",
            actual_action="ALLOW",
            expected_status=400,
            actual_status=200,
            latency_ms=15.0,
            error_message="User SSN 123-45-6789 was not intercepted",
            created_at=datetime.now(timezone.utc)
        )
        session.add_all([res1, res2])



        await session.commit()

        # Collect evidence
        evidence_items = await collect_evidence_for_run(session, run_id, "1.0.0")

        assert len(evidence_items) == 2
        for ev in evidence_items:
            # Check structure
            assert ev.evidence_id.startswith("ev-")
            assert ev.test_id in ("INJ-001", "DLP-001")
            assert ev.security_control != ""
            assert ev.policy_version == "1.0.0"

            # Check strict sanitization: no raw secrets or PII
            assert "sk-12345678901234567890" not in ev.actual_behavior
            assert "123-45-6789" not in ev.actual_behavior
