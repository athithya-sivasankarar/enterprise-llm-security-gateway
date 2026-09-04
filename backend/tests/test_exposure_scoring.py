import pytest
from backend.services.exposure_service import (
    calculate_exposure_risk,
    classify_exposure_risk
)


def test_exposure_scoring_formula():
    # Base CRITICAL (40) + HIGH asset (10) = 50 (MEDIUM)
    score1 = calculate_exposure_risk(
        base_severity="CRITICAL",
        asset_criticality="HIGH"
    )
    assert score1 == 50
    assert classify_exposure_risk(score1) == "MEDIUM"

    # Base CRITICAL (40) + CRITICAL asset (20) + Regression (15) + Incident (15) + Gap (10) + Intel (10) = 110 -> clamped to 100 (CRITICAL)
    score2 = calculate_exposure_risk(
        base_severity="CRITICAL",
        asset_criticality="CRITICAL",
        has_active_regression=True,
        has_open_incident=True,
        has_control_gap=True,
        threat_intel_confidence=1.0
    )
    assert score2 == 100
    assert classify_exposure_risk(score2) == "CRITICAL"

    # Low severity (5) + Low asset (0) = 5 (LOW)
    score3 = calculate_exposure_risk(
        base_severity="LOW",
        asset_criticality="LOW"
    )
    assert score3 == 5
    assert classify_exposure_risk(score3) == "LOW"
