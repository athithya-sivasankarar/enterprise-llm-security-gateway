import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
from backend.governance.models import (
    GovernanceRiskBreakdown,
    GovernanceRiskFactor
)

logger = logging.getLogger(__name__)

# Weight definitions for deterministic governance risk calculation
WEIGHT_CRITICAL_EXPOSURE = 25
WEIGHT_HIGH_EXPOSURE = 15
WEIGHT_OPEN_CRITICAL_INCIDENT = 20
WEIGHT_OPEN_HIGH_INCIDENT = 10
WEIGHT_CONTROL_GAP = 15
WEIGHT_ACTIVE_REGRESSION = 10
WEIGHT_OVERDUE_EXCEPTION = 15
WEIGHT_MULTIPLE_DOMAINS = 10
WEIGHT_THREAT_INTEL_MATCH = 10


def calculate_governance_risk(
    critical_exposures: Optional[List[str]] = None,
    high_exposures: Optional[List[str]] = None,
    critical_incidents: Optional[List[str]] = None,
    high_incidents: Optional[List[str]] = None,
    control_gaps: Optional[List[str]] = None,
    active_regressions: Optional[List[str]] = None,
    overdue_exceptions: Optional[List[str]] = None,
    affected_domains: Optional[List[str]] = None,
    threat_intel_matches: Optional[List[str]] = None,
    now: Optional[datetime] = None
) -> GovernanceRiskBreakdown:
    """
    Deterministically calculate enterprise governance risk score (0-100) and factors.
    Guarantees no double-counting of identical source records and strict clamping.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    # Deduplicate source lists
    crit_exp_set: Set[str] = set(critical_exposures or [])
    high_exp_set: Set[str] = set(high_exposures or []) - crit_exp_set  # Prevent overlap
    crit_inc_set: Set[str] = set(critical_incidents or [])
    high_inc_set: Set[str] = set(high_incidents or []) - crit_inc_set  # Prevent overlap
    ctrl_gap_set: Set[str] = set(control_gaps or [])
    reg_set: Set[str] = set(active_regressions or [])
    overdue_exc_set: Set[str] = set(overdue_exceptions or [])
    domains_set: Set[str] = {d.strip().upper() for d in (affected_domains or []) if d and d.strip()}
    threat_set: Set[str] = set(threat_intel_matches or [])

    factors: List[GovernanceRiskFactor] = []
    raw_score = 0

    # 1. Critical Exposures (+25 each, up to 100)
    if crit_exp_set:
        contrib = len(crit_exp_set) * WEIGHT_CRITICAL_EXPOSURE
        raw_score += contrib
        factors.append(GovernanceRiskFactor(
            factor="CRITICAL_EXPOSURE",
            weight=WEIGHT_CRITICAL_EXPOSURE,
            count=len(crit_exp_set),
            contribution=contrib,
            source_ids=sorted(list(crit_exp_set)),
            description="Unmitigated critical security exposures on enterprise AI assets"
        ))

    # 2. High Exposures (+15 each)
    if high_exp_set:
        contrib = len(high_exp_set) * WEIGHT_HIGH_EXPOSURE
        raw_score += contrib
        factors.append(GovernanceRiskFactor(
            factor="HIGH_EXPOSURE",
            weight=WEIGHT_HIGH_EXPOSURE,
            count=len(high_exp_set),
            contribution=contrib,
            source_ids=sorted(list(high_exp_set)),
            description="High-severity unmitigated security exposures"
        ))

    # 3. Open Critical Incidents (+20 each)
    if crit_inc_set:
        contrib = len(crit_inc_set) * WEIGHT_OPEN_CRITICAL_INCIDENT
        raw_score += contrib
        factors.append(GovernanceRiskFactor(
            factor="OPEN_CRITICAL_INCIDENT",
            weight=WEIGHT_OPEN_CRITICAL_INCIDENT,
            count=len(crit_inc_set),
            contribution=contrib,
            source_ids=sorted(list(crit_inc_set)),
            description="Active, unresolved critical security incidents under SOC investigation"
        ))

    # 4. Open High Incidents (+10 each)
    if high_inc_set:
        contrib = len(high_inc_set) * WEIGHT_OPEN_HIGH_INCIDENT
        raw_score += contrib
        factors.append(GovernanceRiskFactor(
            factor="OPEN_HIGH_INCIDENT",
            weight=WEIGHT_OPEN_HIGH_INCIDENT,
            count=len(high_inc_set),
            contribution=contrib,
            source_ids=sorted(list(high_inc_set)),
            description="Active, unresolved high-severity security incidents"
        ))

    # 5. Control Coverage Gaps (+15 each)
    if ctrl_gap_set:
        contrib = len(ctrl_gap_set) * WEIGHT_CONTROL_GAP
        raw_score += contrib
        factors.append(GovernanceRiskFactor(
            factor="CONTROL_COVERAGE_GAP",
            weight=WEIGHT_CONTROL_GAP,
            count=len(ctrl_gap_set),
            contribution=contrib,
            source_ids=sorted(list(ctrl_gap_set)),
            description="Core security control domains lacking test validation or implementation"
        ))

    # 6. Active Regressions (+10 each)
    if reg_set:
        contrib = len(reg_set) * WEIGHT_ACTIVE_REGRESSION
        raw_score += contrib
        factors.append(GovernanceRiskFactor(
            factor="ACTIVE_REGRESSION",
            weight=WEIGHT_ACTIVE_REGRESSION,
            count=len(reg_set),
            contribution=contrib,
            source_ids=sorted(list(reg_set)),
            description="Detected security test regressions from automated campaign runs"
        ))

    # 7. Overdue Risk Exceptions (+15 each)
    if overdue_exc_set:
        contrib = len(overdue_exc_set) * WEIGHT_OVERDUE_EXCEPTION
        raw_score += contrib
        factors.append(GovernanceRiskFactor(
            factor="OVERDUE_EXCEPTION",
            weight=WEIGHT_OVERDUE_EXCEPTION,
            count=len(overdue_exc_set),
            contribution=contrib,
            source_ids=sorted(list(overdue_exc_set)),
            description="Risk exceptions past their remediation due date or expired without renewal"
        ))

    # 8. Multiple Affected Domains (+10 if >= 2 domains affected)
    if len(domains_set) >= 2:
        contrib = WEIGHT_MULTIPLE_DOMAINS
        raw_score += contrib
        factors.append(GovernanceRiskFactor(
            factor="MULTIPLE_AFFECTED_DOMAINS",
            weight=WEIGHT_MULTIPLE_DOMAINS,
            count=len(domains_set),
            contribution=contrib,
            source_ids=sorted(list(domains_set)),
            description="Cross-domain security vulnerability impact spanning multiple controls"
        ))

    # 9. Threat Intelligence Match (+10 each)
    if threat_set:
        contrib = len(threat_set) * WEIGHT_THREAT_INTEL_MATCH
        raw_score += contrib
        factors.append(GovernanceRiskFactor(
            factor="THREAT_INTELLIGENCE_MATCH",
            weight=WEIGHT_THREAT_INTEL_MATCH,
            count=len(threat_set),
            contribution=contrib,
            source_ids=sorted(list(threat_set)),
            description="Active MITRE ATLAS, OWASP LLM, or CVE threat intelligence indicators matched"
        ))

    # Clamping 0-100
    clamped_score = max(0, min(100, raw_score))

    # Classification
    if clamped_score >= 80:
        classification = "CRITICAL"
    elif clamped_score >= 60:
        classification = "HIGH"
    elif clamped_score >= 30:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    return GovernanceRiskBreakdown(
        overall_risk_score=clamped_score,
        classification=classification,
        factors=factors,
        raw_weighted_score=raw_score,
        calculated_at=now
    )
