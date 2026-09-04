import pytest
from backend.reporting.sanitizer import sanitize_text, sanitize_metadata
from backend.reporting.models import SecurityReport, ExecutiveSummary, CategoryResult, ReportFinding
from backend.reporting.exporters import export_json, export_markdown, export_csv
from datetime import datetime, timezone


def test_synthetic_leakage_protection_in_all_exporters():
    sensitive_test_string = (
        "Found AWS key AKIA1234567890EXAMPLE and OpenAI key sk-1234567890abcdef1234567890. "
        "User email: leak.target@company.internal with SSN: 987-65-4321 and password=SuperPass987!"
    )

    clean_text = sanitize_text(sensitive_test_string)

    # Verify all synthetic secrets are completely scrubbed
    assert "AKIA1234567890EXAMPLE" not in clean_text
    assert "sk-1234567890abcdef1234567890" not in clean_text
    assert "leak.target@company.internal" not in clean_text
    assert "987-65-4321" not in clean_text
    assert "SuperPass987!" not in clean_text

    now = datetime.now(timezone.utc)
    rep = SecurityReport(
        report_id="rep-leak-check",
        report_type="CAMPAIGN",
        title=clean_text,
        description=clean_text,
        status="COMPLETED",
        created_by="tester",
        created_at=now,
        completed_at=now,
        executive_summary=ExecutiveSummary(
            security_score=100.0,
            security_posture="SECURE",
            total_tests=1,
            passed_tests=1,
            failed_tests=0,
            error_tests=0,
            skipped_tests=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
            regression_count=0,
            open_alerts_count=0,
            policy_version="1.0.0",
            generated_at=now
        ),
        category_results=[],
        findings=[
            ReportFinding(
                finding_id="find-leak-1",
                test_id="INJ-001",
                category="PROMPT_INJECTION",
                severity="HIGH",
                title=clean_text,
                description=clean_text,
                expected_behavior=clean_text,
                actual_behavior=clean_text,
                endpoint="/api/chat",
                policy_version="1.0.0",
                timestamp=now
            )
        ],
        regressions=[],
        compliance_mappings=[],
        evidence_count=1,
        policy_version="1.0.0",
        report_version="1.0.0",
        report_hash="b"*64,
        methodology=clean_text,
        limitations=clean_text,
        compliance_disclaimer="Compliance mappings provide security-control evidence and assessment coverage only."
    )

    json_exp = export_json(rep)
    md_exp = export_markdown(rep)
    csv_exp = export_csv(rep)

    for export_content in [json_exp, md_exp, csv_exp]:
        assert "AKIA1234567890EXAMPLE" not in export_content
        assert "sk-1234567890abcdef1234567890" not in export_content
        assert "leak.target@company.internal" not in export_content
        assert "987-65-4321" not in export_content
        assert "SuperPass987!" not in export_content
