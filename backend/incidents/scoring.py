import logging
from typing import List, Optional, Set, Dict, Any

logger = logging.getLogger(__name__)

# Weight multipliers for risk scoring
CRITICAL_FINDING_WEIGHT = 40
HIGH_FINDING_WEIGHT = 25
MEDIUM_FINDING_WEIGHT = 10
LOW_FINDING_WEIGHT = 5
REGRESSION_WEIGHT = 15
POSTURE_DEGRADED_WEIGHT = 15
REPEATED_EVENT_WEIGHT = 10
MULTIPLE_DOMAINS_WEIGHT = 10


def classify_incident_severity(risk_score: int) -> str:
    """
    Classify severity tier based on deterministic 0-100 risk score.
    """
    if risk_score >= 80:
        return "CRITICAL"
    elif risk_score >= 60:
        return "HIGH"
    elif risk_score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_incident_risk(
    findings_severities: Optional[List[str]] = None,
    has_regressions: bool = False,
    is_posture_degraded: bool = False,
    is_repeated_event: bool = False,
    categories: Optional[List[str]] = None,
    base_severity: Optional[str] = None
) -> int:
    """
    Deterministically calculate an incident risk score clamped between 0 and 100.
    
    Factors:
    - CRITICAL finding = +40
    - HIGH finding = +25
    - MEDIUM finding = +10
    - LOW finding = +5
    - Regression = +15
    - Posture degraded = +15
    - Repeated event = +10
    - Multiple domains (2+ distinct security categories) = +10
    """
    score = 0

    if findings_severities:
        for sev in findings_severities:
            norm_sev = str(sev).strip().upper()
            if norm_sev == "CRITICAL":
                score += CRITICAL_FINDING_WEIGHT
            elif norm_sev == "HIGH":
                score += HIGH_FINDING_WEIGHT
            elif norm_sev == "MEDIUM":
                score += MEDIUM_FINDING_WEIGHT
            elif norm_sev == "LOW":
                score += LOW_FINDING_WEIGHT

    if has_regressions:
        score += REGRESSION_WEIGHT

    if is_posture_degraded:
        score += POSTURE_DEGRADED_WEIGHT

    if is_repeated_event:
        score += REPEATED_EVENT_WEIGHT

    if categories:
        unique_cats = {str(c).strip().upper() for c in categories if c}
        if len(unique_cats) > 1:
            score += MULTIPLE_DOMAINS_WEIGHT

    # If no findings were explicitly passed, infer from base severity
    if not findings_severities and base_severity:
        norm_base = str(base_severity).strip().upper()
        if norm_base == "CRITICAL":
            score += CRITICAL_FINDING_WEIGHT
        elif norm_base == "HIGH":
            score += HIGH_FINDING_WEIGHT
        elif norm_base == "MEDIUM":
            score += MEDIUM_FINDING_WEIGHT
        elif norm_base == "LOW":
            score += LOW_FINDING_WEIGHT

    # Clamp to [0, 100]
    return max(0, min(100, score))
