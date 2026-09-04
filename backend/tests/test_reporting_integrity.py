import pytest
from backend.reporting.generator import calculate_report_hash, verify_report_integrity


def test_reporting_integrity_hash_deterministic():
    sample_report = {
        "report_id": "rep-test-123",
        "report_type": "CAMPAIGN",
        "title": "Campaign Security Assessment Report",
        "executive_summary": {
            "security_score": 95.0,
            "baseline_score": 100.0,
            "score_delta": -5.0,
            "security_posture": "DEGRADED",
            "total_tests": 20,
            "passed_tests": 19,
            "failed_tests": 1,
            "error_tests": 0,
            "critical_findings": 0,
            "high_findings": 1,
            "regression_count": 1,
            "policy_version": "1.0.0"
        },
        "category_results": [
            {"category": "PROMPT_INJECTION", "score": 100.0, "status": "PASS", "total_tests": 10, "passed_tests": 10},
            {"category": "INPUT_DLP", "score": 90.0, "status": "PASS", "total_tests": 10, "passed_tests": 9}
        ],
        "findings": [
            {"test_id": "DLP-001", "category": "INPUT_DLP", "severity": "HIGH", "title": "DLP failure"}
        ],
        "regressions": [
            {"test_id": "DLP-001", "category": "INPUT_DLP", "severity": "HIGH"}
        ],
        "compliance_mappings": [
            {"control_id": "LLM02", "coverage_status": "Control evidence available", "evidence_count": 10}
        ],
        "evidence_count": 20,
        "policy_version": "1.0.0",
        "report_version": "1.0.0"
    }

    # 1. Compute Hash
    hash1 = calculate_report_hash(sample_report)
    hash2 = calculate_report_hash(sample_report)
    assert hash1 == hash2
    assert len(hash1) == 64

    # 2. Verify Valid Report
    sample_report["report_hash"] = hash1
    valid, msg = verify_report_integrity(sample_report)
    assert valid is True
    assert "verified successfully" in msg

    # 3. Tamper with report score -> Verification MUST fail
    tampered_report = dict(sample_report)
    tampered_report["executive_summary"] = dict(sample_report["executive_summary"])
    tampered_report["executive_summary"]["security_score"] = 99.9  # Tampered!

    valid_tampered, err_msg = verify_report_integrity(tampered_report)
    assert valid_tampered is False
    assert "verification failed" in err_msg
