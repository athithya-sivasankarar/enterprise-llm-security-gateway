import json
import pytest
from datetime import datetime, timezone

from backend.reporting.models import (
    SecurityReport,
    ExecutiveSummary,
    CategoryResult,
    ReportFinding,
    EvidenceItem,
    ComplianceMapping
)
from backend.reporting.exporters import (
    export_json,
    export_markdown,
    export_csv,
    export_pdf
)


@pytest.fixture
def sample_security_report():
    now = datetime.now(timezone.utc)
    es = ExecutiveSummary(
        security_score=90.0,
        baseline_score=95.0,
        score_delta=-5.0,
        security_posture="DEGRADED",
        total_tests=10,
        passed_tests=9,
        failed_tests=1,
        error_tests=0,
        skipped_tests=0,
        critical_findings=0,
        high_findings=1,
        medium_findings=0,
        low_findings=0,
        regression_count=1,
        open_alerts_count=1,
        policy_version="1.0.0",
        generated_at=now
    )
    findings = [
        ReportFinding(
            finding_id="find-1",
            test_id="INJ-002",
            category="PROMPT_INJECTION",
            severity="HIGH",
            title="Prompt Injection Bypass",
            description="Payload bypassed regex filter.",
            expected_behavior="Expected block",
            actual_behavior="Allowed with 200",
            endpoint="/api/chat",
            policy_version="1.0.0",
            timestamp=now
        )
    ]
    return SecurityReport(
        report_id="rep-sample-001",
        report_type="CAMPAIGN",
        title="Sample Security Assessment Report",
        description="Verification assessment.",
        status="COMPLETED",
        created_by="test-analyst",
        created_at=now,
        completed_at=now,
        campaign_id="camp-sample",
        campaign_run_id="crun-sample",
        executive_summary=es,
        category_results=[
            CategoryResult(category="PROMPT_INJECTION", total_tests=5, passed_tests=4, failed_tests=1, error_tests=0, score=80.0, status="DEGRADED")
        ],
        findings=findings,
        regressions=[{"test_id": "INJ-002", "category": "PROMPT_INJECTION", "severity": "HIGH", "description": "Regressed from PASS"}],
        compliance_mappings=[
            ComplianceMapping(
                framework="OWASP LLM Top 10",
                control_id="LLM01",
                control_name="Prompt Injection",
                gateway_controls=["Prompt Injection Filter"],
                evidence_count=5,
                coverage_status="Control evidence available"
            )
        ],
        evidence_count=10,
        policy_version="1.0.0",
        report_version="1.0.0",
        report_hash="a"*64,
        methodology="Automated synthetic validation",
        limitations="Mock provider enclave",
        compliance_disclaimer="Compliance mappings provide security-control evidence and assessment coverage only. They do not constitute certification, legal compliance, or an independent audit."
    )


def test_export_json_format(sample_security_report):
    json_str = export_json(sample_security_report)
    parsed = json.loads(json_str)
    assert parsed["report_id"] == "rep-sample-001"
    assert parsed["executive_summary"]["security_score"] == 90.0


def test_export_markdown_format(sample_security_report):
    md_str = export_markdown(sample_security_report)
    assert "# Sample Security Assessment Report" in md_str
    assert "90.0%" in md_str
    assert "OWASP LLM Top 10" in md_str
    assert "Compliance mappings provide security-control evidence" in md_str


def test_export_csv_format(sample_security_report):
    csv_str = export_csv(sample_security_report)
    assert "FINDING_ID" in csv_str
    assert "INJ-002" in csv_str
    assert "PROMPT_INJECTION" in csv_str


def test_export_pdf_format(sample_security_report):
    pdf_bytes = export_pdf(sample_security_report)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF-")  # Valid PDF binary signature
