import pytest
from dataclasses import dataclass
from backend.reporting.scoring import (
    calculate_overall_score,
    calculate_category_results,
    determine_security_posture
)


@dataclass
class MockTestResult:
    category: str
    status: str


def test_scoring_overall_and_categories():
    # 1. Overall Score
    assert calculate_overall_score(10, 10) == 100.0
    assert calculate_overall_score(8, 10) == 80.0
    assert calculate_overall_score(0, 5) == 0.0
    assert calculate_overall_score(0, 0) == 100.0  # Empty baseline

    # 2. Category Breakdown
    results = [
        MockTestResult(category="PROMPT_INJECTION", status="PASS"),
        MockTestResult(category="PROMPT_INJECTION", status="PASS"),
        MockTestResult(category="INPUT_DLP", status="PASS"),
        MockTestResult(category="INPUT_DLP", status="FAIL"),
        MockTestResult(category="AUTHENTICATION", status="PASS"),
    ]

    cat_results = calculate_category_results(results)
    assert len(cat_results) == 3

    inj = next(cr for cr in cat_results if cr.category == "PROMPT_INJECTION")
    assert inj.score == 100.0
    assert inj.status == "PASS"

    dlp = next(cr for cr in cat_results if cr.category == "INPUT_DLP")
    assert dlp.score == 50.0
    assert dlp.status == "FAIL"


def test_scoring_posture_classification():
    # SECURE: >= 90% and 0 critical/high
    assert determine_security_posture(95.0, critical_findings=0, high_findings=0) == "SECURE"

    # DEGRADED: 70-89% OR high findings > 0
    assert determine_security_posture(85.0, critical_findings=0, high_findings=0) == "DEGRADED"
    assert determine_security_posture(95.0, critical_findings=0, high_findings=1) == "DEGRADED"

    # CRITICAL: < 70% OR critical findings > 0
    assert determine_security_posture(65.0, critical_findings=0, high_findings=0) == "CRITICAL"
    assert determine_security_posture(95.0, critical_findings=1, high_findings=0) == "CRITICAL"
