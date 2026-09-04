import pytest
from dataclasses import dataclass
from typing import Optional

from backend.campaign.comparator import compare_runs_with_baseline


@dataclass
class MockTestResult:
    test_id: str
    category: str
    severity: str
    status: str
    error_message: Optional[str] = None


def test_comparator_initial_run_without_baseline():
    curr_results = [
        MockTestResult(test_id="AUTH-001", category="AUTHENTICATION", severity="CRITICAL", status="PASS"),
        MockTestResult(test_id="INJ-001", category="PROMPT_INJECTION", severity="HIGH", status="PASS"),
        MockTestResult(test_id="DLP-001", category="INPUT_DLP", severity="HIGH", status="PASS")
    ]
    res = compare_runs_with_baseline(
        campaign_id="camp-123",
        campaign_run_id="crun-123",
        current_run_id="run-curr",
        current_results=curr_results,
        current_score=100.0,
        baseline_run_id=None,
        baseline_results=None
    )

    assert res.campaign_id == "camp-123"
    assert res.baseline_run_id is None
    assert res.regression_detected is False
    assert res.score_delta == 0.0
    assert len(res.regressions) == 0
    assert len(res.added_tests) == 3


def test_comparator_stable_run_no_regressions():
    base_results = [
        MockTestResult(test_id="AUTH-001", category="AUTHENTICATION", severity="CRITICAL", status="PASS"),
        MockTestResult(test_id="INJ-001", category="PROMPT_INJECTION", severity="HIGH", status="PASS"),
        MockTestResult(test_id="DLP-001", category="INPUT_DLP", severity="HIGH", status="PASS")
    ]
    curr_results = [
        MockTestResult(test_id="AUTH-001", category="AUTHENTICATION", severity="CRITICAL", status="PASS"),
        MockTestResult(test_id="INJ-001", category="PROMPT_INJECTION", severity="HIGH", status="PASS"),
        MockTestResult(test_id="DLP-001", category="INPUT_DLP", severity="HIGH", status="PASS")
    ]

    res = compare_runs_with_baseline(
        campaign_id="camp-123",
        campaign_run_id="crun-123",
        current_run_id="run-curr",
        current_results=curr_results,
        current_score=100.0,
        baseline_run_id="run-base",
        baseline_results=base_results,
        baseline_score=100.0
    )

    assert res.regression_detected is False
    assert res.score_delta == 0.0
    assert len(res.regressions) == 0
    assert len(res.new_failures) == 0
    assert len(res.resolved_failures) == 0


def test_comparator_detects_individual_test_regression():
    base_results = [
        MockTestResult(test_id="AUTH-001", category="AUTHENTICATION", severity="CRITICAL", status="PASS"),
        MockTestResult(test_id="INJ-001", category="PROMPT_INJECTION", severity="HIGH", status="PASS"),
        MockTestResult(test_id="INJ-002", category="PROMPT_INJECTION", severity="HIGH", status="PASS"),
        MockTestResult(test_id="DLP-001", category="INPUT_DLP", severity="HIGH", status="PASS")
    ]
    # INJ-002 regressed from PASS to FAIL
    curr_results = [
        MockTestResult(test_id="AUTH-001", category="AUTHENTICATION", severity="CRITICAL", status="PASS"),
        MockTestResult(test_id="INJ-001", category="PROMPT_INJECTION", severity="HIGH", status="PASS"),
        MockTestResult(test_id="INJ-002", category="PROMPT_INJECTION", severity="HIGH", status="FAIL", error_message="Bypass allowed"),
        MockTestResult(test_id="DLP-001", category="INPUT_DLP", severity="HIGH", status="PASS")
    ]

    res = compare_runs_with_baseline(
        campaign_id="camp-123",
        campaign_run_id="crun-123",
        current_run_id="run-curr",
        current_results=curr_results,
        current_score=75.0,
        baseline_run_id="run-base",
        baseline_results=base_results,
        baseline_score=100.0
    )

    assert res.regression_detected is True
    assert res.score_delta == -25.0
    assert "INJ-002" in res.new_failures
    assert "PROMPT_INJECTION" in res.categories_regressed
    assert len(res.regressions) == 1

    reg = res.regressions[0]
    assert reg.test_id == "INJ-002"
    assert reg.category == "PROMPT_INJECTION"
    assert reg.previous_status == "PASS"
    assert reg.current_status == "FAIL"
    assert reg.previous_score == 100.0
    assert reg.current_score == 75.0
    assert reg.score_delta == -25.0
    assert "Bypass allowed" in reg.description


def test_comparator_detects_resolved_failures_and_catalog_changes():
    base_results = [
        MockTestResult(test_id="AUTH-001", category="AUTHENTICATION", severity="CRITICAL", status="FAIL"),
        MockTestResult(test_id="OLD-001", category="LEGACY", severity="LOW", status="PASS")
    ]
    curr_results = [
        MockTestResult(test_id="AUTH-001", category="AUTHENTICATION", severity="CRITICAL", status="PASS"),
        MockTestResult(test_id="NEW-001", category="INPUT_DLP", severity="HIGH", status="PASS")
    ]

    res = compare_runs_with_baseline(
        campaign_id="camp-123",
        campaign_run_id="crun-123",
        current_run_id="run-curr",
        current_results=curr_results,
        current_score=100.0,
        baseline_run_id="run-base",
        baseline_results=base_results,
        baseline_score=50.0
    )

    assert res.regression_detected is False
    assert res.score_delta == 50.0
    assert "AUTH-001" in res.resolved_failures
    assert "NEW-001" in res.added_tests
    assert "OLD-001" in res.removed_tests
