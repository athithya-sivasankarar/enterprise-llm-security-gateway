import pytest
from datetime import datetime, timezone
from backend.governance.risk import (
    calculate_governance_risk,
    WEIGHT_CRITICAL_EXPOSURE,
    WEIGHT_HIGH_EXPOSURE,
    WEIGHT_OPEN_CRITICAL_INCIDENT,
    WEIGHT_OPEN_HIGH_INCIDENT,
    WEIGHT_CONTROL_GAP,
    WEIGHT_ACTIVE_REGRESSION,
    WEIGHT_OVERDUE_EXCEPTION,
    WEIGHT_MULTIPLE_DOMAINS,
    WEIGHT_THREAT_INTEL_MATCH
)


def test_governance_risk_clean_baseline():
    breakdown = calculate_governance_risk()
    assert breakdown.overall_risk_score == 0
    assert breakdown.classification == "LOW"
    assert len(breakdown.factors) == 0
    assert breakdown.raw_weighted_score == 0


def test_governance_risk_weights_and_deduplication():
    # Duplicate entries in critical exposures and high exposures
    breakdown = calculate_governance_risk(
        critical_exposures=["EXP-01", "EXP-01", "EXP-02"],
        high_exposures=["EXP-03", "EXP-03", "EXP-01"], # EXP-01 should be deduplicated from high
        critical_incidents=["INC-01"],
        high_incidents=["INC-02", "INC-02"],
        control_gaps=["INPUT_DLP"],
        active_regressions=["REG-01"],
        overdue_exceptions=["EXC-01"],
        affected_domains=["INPUT_DLP", "SECRET_LEAKAGE"],
        threat_intel_matches=["AML.T0054"]
    )

    # 2 crit exp (50) + 1 high exp (15) + 1 crit inc (20) + 1 high inc (10) + 1 ctrl gap (15)
    # + 1 reg (10) + 1 overdue exc (15) + multiple domains (10) + 1 threat (10)
    # raw score = 50 + 15 + 20 + 10 + 15 + 10 + 15 + 10 + 10 = 155 -> Clamped to 100
    assert breakdown.raw_weighted_score == 155
    assert breakdown.overall_risk_score == 100
    assert breakdown.classification == "CRITICAL"


def test_governance_risk_classifications():
    # LOW (0-29)
    low_res = calculate_governance_risk(high_incidents=["INC-01"], active_regressions=["REG-01"]) # 10 + 10 = 20
    assert low_res.overall_risk_score == 20
    assert low_res.classification == "LOW"

    # MEDIUM (30-59)
    med_res = calculate_governance_risk(critical_exposures=["EXP-01"], control_gaps=["GAP-01"]) # 25 + 15 = 40
    assert med_res.overall_risk_score == 40
    assert med_res.classification == "MEDIUM"

    # HIGH (60-79)
    high_res = calculate_governance_risk(
        critical_exposures=["EXP-01", "EXP-02"], # 50
        critical_incidents=["INC-01"] # 20 -> 70
    )
    assert high_res.overall_risk_score == 70
    assert high_res.classification == "HIGH"

    # CRITICAL (80-100)
    crit_res = calculate_governance_risk(
        critical_exposures=["EXP-01", "EXP-02", "EXP-03"], # 75
        control_gaps=["GAP-01"] # 15 -> 90
    )
    assert crit_res.overall_risk_score == 90
    assert crit_res.classification == "CRITICAL"
