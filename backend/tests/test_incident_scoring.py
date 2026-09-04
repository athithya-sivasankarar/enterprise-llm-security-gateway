import pytest
from backend.incidents.scoring import calculate_incident_risk, classify_incident_severity


def test_scoring_finding_weights():
    # CRITICAL finding (+40)
    score_crit = calculate_incident_risk(findings_severities=["CRITICAL"])
    assert score_crit == 40
    assert classify_incident_severity(score_crit) == "MEDIUM"

    # HIGH finding (+25)
    score_high = calculate_incident_risk(findings_severities=["HIGH"])
    assert score_high == 25
    assert classify_incident_severity(score_high) == "LOW"

    # MEDIUM finding (+10)
    score_med = calculate_incident_risk(findings_severities=["MEDIUM"])
    assert score_med == 10

    # LOW finding (+5)
    score_low = calculate_incident_risk(findings_severities=["LOW"])
    assert score_low == 5


def test_scoring_additive_factors():
    # CRITICAL finding (+40) + Regression (+15) + Posture degraded (+15) + Repeated (+10) + Multiple domains (+10) = 90
    score = calculate_incident_risk(
        findings_severities=["CRITICAL"],
        has_regressions=True,
        is_posture_degraded=True,
        is_repeated_event=True,
        categories=["PROMPT_INJECTION", "SECRET_LEAKAGE"]
    )
    assert score == 90
    assert classify_incident_severity(score) == "CRITICAL"


def test_scoring_clamping():
    # Many critical findings should clamp to 100 max
    score_over = calculate_incident_risk(
        findings_severities=["CRITICAL", "CRITICAL", "CRITICAL", "HIGH", "HIGH"],
        has_regressions=True,
        is_posture_degraded=True,
        is_repeated_event=True,
        categories=["CAT1", "CAT2", "CAT3"]
    )
    assert score_over == 100
    assert classify_incident_severity(score_over) == "CRITICAL"

    # Empty factors should be 0
    score_zero = calculate_incident_risk(findings_severities=[])
    assert score_zero == 0
    assert classify_incident_severity(score_zero) == "LOW"


def test_scoring_severity_classification():
    assert classify_incident_severity(0) == "LOW"
    assert classify_incident_severity(29) == "LOW"
    assert classify_incident_severity(30) == "MEDIUM"
    assert classify_incident_severity(59) == "MEDIUM"
    assert classify_incident_severity(60) == "HIGH"
    assert classify_incident_severity(79) == "HIGH"
    assert classify_incident_severity(80) == "CRITICAL"
    assert classify_incident_severity(100) == "CRITICAL"
