import pytest
from backend.threatintel.matcher import match_threat_intel_for_category
from backend.threatintel.catalog import BUILTIN_THREAT_INTEL_CATALOG
from backend.threatintel.scoring import calculate_threat_relevance_score


def test_calculate_threat_relevance_score_factors():
    # Base CRITICAL (40) * 1.0 = 40
    score_base = calculate_threat_relevance_score("CRITICAL", 1.0)
    assert score_base == 40

    # With regression (+20), incident (+20), critical asset (+15), control gap (+15)
    score_full = calculate_threat_relevance_score(
        severity="CRITICAL",
        confidence=1.0,
        has_active_regression=True,
        has_active_incident=True,
        is_critical_asset=True,
        has_control_gap=True
    )
    # 40 + 20 + 20 + 15 + 15 = 110 -> clamped to 100
    assert score_full == 100


def test_match_threat_intel_prompt_injection():
    matches = match_threat_intel_for_category(
        category="PROMPT_INJECTION",
        intel_items=BUILTIN_THREAT_INTEL_CATALOG,
        target_type="TEST",
        target_id="PI-001",
        has_active_regression=True,
        is_critical_asset=True
    )

    assert len(matches) >= 2
    indicators = [m.indicator for m in matches]
    assert "AML.T0054" in indicators
    assert "LLM01" in indicators
    assert matches[0].relevance_score >= 50
