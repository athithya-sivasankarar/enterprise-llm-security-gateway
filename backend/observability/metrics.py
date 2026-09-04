import time
import logging
from typing import List, Optional
# pyrefly: ignore [missing-import]
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
    REGISTRY
)


logger = logging.getLogger(__name__)

# =============================================================================
# 1. Gateway Request Metrics (Low-Cardinality Labels)
# =============================================================================
gateway_requests_total = Counter(
    "gateway_requests_total",
    "Total number of HTTP requests processed by the AI security gateway",
    ["method", "route", "status", "action"]
)

gateway_request_duration_seconds = Histogram(
    "gateway_request_duration_seconds",
    "End-to-end request duration across the security gateway in seconds",
    ["method", "route", "status"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
)

# =============================================================================
# 2. Security Decision & Threat Metrics
# =============================================================================
gateway_blocked_requests_total = Counter(
    "gateway_blocked_requests_total",
    "Total number of requests blocked by security policies",
    ["threat_type", "role"]
)

gateway_pii_detections_total = Counter(
    "gateway_pii_detections_total",
    "Total number of PII entity detections during input/output inspection",
    ["entity_type"]
)

gateway_prompt_injection_total = Counter(
    "gateway_prompt_injection_total",
    "Total number of prompt injection and jailbreak detections",
    ["threat_type"]
)

gateway_response_blocks_total = Counter(
    "gateway_response_blocks_total",
    "Total number of LLM responses blocked by output security filters",
    ["threat_type"]
)

gateway_secret_leakage_total = Counter(
    "gateway_secret_leakage_total",
    "Total number of secret or credential leakage attempts blocked in LLM responses",
    ["threat_type"]
)

gateway_unsafe_content_total = Counter(
    "gateway_unsafe_content_total",
    "Total number of unsafe or malicious content responses blocked",
    ["threat_type"]
)

gateway_model_access_denied_total = Counter(
    "gateway_model_access_denied_total",
    "Total number of model requests denied due to RBAC policy",
    ["role"]
)

# =============================================================================
# 3. Multi-Provider Metrics
# =============================================================================
gateway_provider_requests_total = Counter(
    "gateway_provider_requests_total",
    "Total number of upstream LLM provider requests",
    ["provider", "model", "status"]
)

gateway_provider_errors_total = Counter(
    "gateway_provider_errors_total",
    "Total number of upstream LLM provider invocation errors",
    ["provider", "model"]
)

gateway_provider_duration_seconds = Histogram(
    "gateway_provider_duration_seconds",
    "Upstream LLM provider response latency in seconds",
    ["provider", "model"],
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0]
)

# =============================================================================
# 4. Redis Semantic Cache Metrics
# =============================================================================
gateway_cache_hits_total = Counter(
    "gateway_cache_hits_total",
    "Total number of semantic cache hits",
    ["provider"]
)

gateway_cache_misses_total = Counter(
    "gateway_cache_misses_total",
    "Total number of semantic cache misses",
    ["provider"]
)

gateway_cache_errors_total = Counter(
    "gateway_cache_errors_total",
    "Total number of semantic cache operation errors (fail-safe bypasses)",
    ["provider"]
)

# =============================================================================
# 5. Rate Limiting & Authentication Metrics
# =============================================================================
gateway_rate_limit_blocks_total = Counter(
    "gateway_rate_limit_blocks_total",
    "Total number of requests blocked by rate limiting",
    ["role"]
)

gateway_auth_success_total = Counter(
    "gateway_auth_success_total",
    "Total number of successful API key authentications",
    ["role"]
)

gateway_auth_failure_total = Counter(
    "gateway_auth_failure_total",
    "Total number of failed API key authentications"
)

# =============================================================================
# 6. Central Policy Engine Metrics
# =============================================================================
gateway_policy_evaluations_total = Counter(
    "gateway_policy_evaluations_total",
    "Total number of security policy evaluations",
    ["result"]
)

gateway_policy_fallback_total = Counter(
    "gateway_policy_fallback_total",
    "Total number of policy evaluation fallbacks to default policy",
    ["reason"]
)

gateway_policy_validation_failures_total = Counter(
    "gateway_policy_validation_failures_total",
    "Total number of policy validation rejections"
)

gateway_policy_activation_total = Counter(
    "gateway_policy_activation_total",
    "Total number of policy activation actions",
    ["status"]
)

# =============================================================================
# 7. Automated Security Validation & Red-Team Metrics (Low-Cardinality Labels)
# =============================================================================
gateway_security_tests_total = Counter(
    "gateway_security_tests_total",
    "Total number of security validation tests executed",
    ["category", "status"]
)

gateway_security_tests_passed_total = Counter(
    "gateway_security_tests_passed_total",
    "Total number of security validation tests passed",
    ["category"]
)

gateway_security_tests_failed_total = Counter(
    "gateway_security_tests_failed_total",
    "Total number of security validation tests failed",
    ["category"]
)

gateway_security_test_duration_seconds = Histogram(
    "gateway_security_test_duration_seconds",
    "Duration of individual security validation test execution in seconds",
    ["category"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

gateway_security_findings_total = Counter(
    "gateway_security_findings_total",
    "Total number of security findings recorded from validation failures",
    ["category", "severity"]
)

# =============================================================================
# 8. Security Assessment Campaigns & Regression Metrics (Low-Cardinality Labels)
# =============================================================================
gateway_campaign_runs_total = Counter(
    "gateway_campaign_runs_total",
    "Total number of security assessment campaign executions",
    ["status"]
)

gateway_regressions_detected_total = Counter(
    "gateway_regressions_detected_total",
    "Total number of security control regressions detected against baseline",
    ["category", "severity"]
)

gateway_campaign_score_delta = Histogram(
    "gateway_campaign_score_delta",
    "Score delta in percentage points between current campaign run and baseline",
    buckets=[-50.0, -25.0, -10.0, -5.0, -2.0, -1.0, 0.0, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0]
)

# =============================================================================
# 9. Campaign Scheduling, Alerting & Security Posture Metrics
# =============================================================================
gateway_scheduled_campaigns_total = Gauge(
    "gateway_scheduled_campaigns_total",
    "Total configured scheduled campaigns by enabled state",
    ["enabled"]
)

gateway_scheduled_campaign_runs_total = Counter(
    "gateway_scheduled_campaign_runs_total",
    "Total automated scheduled campaign executions",
    ["campaign_id", "status"]
)

gateway_scheduler_errors_total = Counter(
    "gateway_scheduler_errors_total",
    "Total scheduler execution errors",
    ["campaign_id", "error_type"]
)

gateway_security_alerts_total = Counter(
    "gateway_security_alerts_total",
    "Total generated security alerts",
    ["alert_type", "severity"]
)

gateway_security_alerts_open = Gauge(
    "gateway_security_alerts_open",
    "Current number of open security alerts by severity",
    ["severity"]
)

gateway_security_score = Gauge(
    "gateway_security_score",
    "Latest recorded campaign security score",
    ["campaign_id"]
)

gateway_security_score_delta = Gauge(
    "gateway_security_score_delta",
    "Latest security score delta against baseline",
    ["campaign_id"]
)

# =============================================================================
# 10. Security Assessment Reporting & Evidence Metrics (Step 18)
# =============================================================================
gateway_reports_generated_total = Counter(
    "gateway_reports_generated_total",
    "Total security assessment reports generated",
    ["report_type", "status"]
)

gateway_reports_failed_total = Counter(
    "gateway_reports_failed_total",
    "Total security report generation failures",
    ["report_type", "error_type"]
)

gateway_report_generation_duration_seconds = Histogram(
    "gateway_report_generation_duration_seconds",
    "Report generation latency in seconds",
    ["report_type"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

gateway_report_exports_total = Counter(
    "gateway_report_exports_total",
    "Total report exports by format",
    ["format"]
)

gateway_report_integrity_failures_total = Counter(
    "gateway_report_integrity_failures_total",
    "Total report SHA-256 integrity verification failures",
    ["report_type"]
)

gateway_evidence_items_total = Counter(
    "gateway_evidence_items_total",
    "Total evidence items collected and normalized",
    ["category", "severity"]
)


# =============================================================================
# Fail-Safe Helper Functions (Observability Never Crashes Gateway)
# =============================================================================



def record_request_metric(method: str, route: str, status: int, action: str, duration_s: float) -> None:
    try:
        gateway_requests_total.labels(
            method=method.upper(),
            route=route,
            status=str(status),
            action=action.upper()
        ).inc()
        gateway_request_duration_seconds.labels(
            method=method.upper(),
            route=route,
            status=str(status)
        ).observe(duration_s)
    except Exception as e:
        logger.debug(f"Failed to record request metric: {e}")


def record_auth_metric(success: bool, role: Optional[str] = None) -> None:
    try:
        if success:
            gateway_auth_success_total.labels(role=role or "unknown").inc()
        else:
            gateway_auth_failure_total.inc()
    except Exception as e:
        logger.debug(f"Failed to record auth metric: {e}")


def record_rate_limit_blocked(role: Optional[str] = None) -> None:
    try:
        gateway_rate_limit_blocks_total.labels(role=role or "unknown").inc()
        gateway_blocked_requests_total.labels(threat_type="RATE_LIMIT_EXCEEDED", role=role or "unknown").inc()
    except Exception as e:
        logger.debug(f"Failed to record rate limit metric: {e}")


def record_model_denied(role: str) -> None:
    try:
        gateway_model_access_denied_total.labels(role=role).inc()
        gateway_blocked_requests_total.labels(threat_type="MODEL_ACCESS_DENIED", role=role).inc()
    except Exception as e:
        logger.debug(f"Failed to record model denied metric: {e}")


def record_pii_detected(entity_types: List[str]) -> None:
    try:
        for entity in entity_types:
            # Low cardinality sanitization
            safe_entity = entity.strip().upper() if entity else "UNKNOWN"
            gateway_pii_detections_total.labels(entity_type=safe_entity).inc()
    except Exception as e:
        logger.debug(f"Failed to record PII metric: {e}")


def record_prompt_injection(threat_type: str, role: Optional[str] = None) -> None:
    try:
        safe_threat = threat_type or "PROMPT_INJECTION"
        gateway_prompt_injection_total.labels(threat_type=safe_threat).inc()
        gateway_blocked_requests_total.labels(threat_type=safe_threat, role=role or "unknown").inc()
    except Exception as e:
        logger.debug(f"Failed to record prompt injection metric: {e}")


def record_provider_metric(provider: str, model: str, status: str, duration_s: float, is_error: bool = False) -> None:
    try:
        safe_provider = provider.lower() if provider else "unknown"
        safe_model = model.lower() if model else "unknown"
        gateway_provider_requests_total.labels(provider=safe_provider, model=safe_model, status=status).inc()
        gateway_provider_duration_seconds.labels(provider=safe_provider, model=safe_model).observe(duration_s)
        if is_error:
            gateway_provider_errors_total.labels(provider=safe_provider, model=safe_model).inc()
    except Exception as e:
        logger.debug(f"Failed to record provider metric: {e}")


def record_response_security_metric(action: str, threat_type: Optional[str] = None, role: Optional[str] = None) -> None:
    try:
        if action == "BLOCK":
            safe_threat = threat_type or "UNSAFE_RESPONSE"
            gateway_response_blocks_total.labels(threat_type=safe_threat).inc()
            gateway_blocked_requests_total.labels(threat_type=safe_threat, role=role or "unknown").inc()
            if threat_type == "SECRET_LEAKAGE":
                gateway_secret_leakage_total.labels(threat_type="SECRET_LEAKAGE").inc()
            elif threat_type == "UNSAFE_CONTENT":
                gateway_unsafe_content_total.labels(threat_type="UNSAFE_CONTENT").inc()
    except Exception as e:
        logger.debug(f"Failed to record response security metric: {e}")


def record_cache_metric(provider: str, hit: bool, error: bool = False) -> None:
    try:
        safe_provider = provider.lower() if provider else "mock"
        if error:
            gateway_cache_errors_total.labels(provider=safe_provider).inc()
        elif hit:
            gateway_cache_hits_total.labels(provider=safe_provider).inc()
        else:
            gateway_cache_misses_total.labels(provider=safe_provider).inc()
    except Exception as e:
        logger.debug(f"Failed to record cache metric: {e}")


def record_policy_eval_metric(result: str = "success") -> None:
    try:
        gateway_policy_evaluations_total.labels(result=result).inc()
    except Exception as e:
        logger.debug(f"Failed to record policy eval metric: {e}")


def record_policy_fallback_metric(reason: str = "unavailable") -> None:
    try:
        gateway_policy_fallback_total.labels(reason=reason).inc()
    except Exception as e:
        logger.debug(f"Failed to record policy fallback metric: {e}")


def record_policy_validation_failure() -> None:
    try:
        gateway_policy_validation_failures_total.inc()
    except Exception as e:
        logger.debug(f"Failed to record policy validation failure: {e}")


def record_policy_activation(status: str = "success") -> None:
    try:
        gateway_policy_activation_total.labels(status=status).inc()
    except Exception as e:
        logger.debug(f"Failed to record policy activation: {e}")


def record_security_test_metric(category: str, status: str, duration_s: float) -> None:
    """
    Record Prometheus metrics for an executed security test assertion.
    Uses safe, low-cardinality labels only.
    """
    try:
        safe_cat = category.strip().upper() if category else "UNKNOWN"
        safe_stat = status.strip().upper() if status else "UNKNOWN"
        gateway_security_tests_total.labels(category=safe_cat, status=safe_stat).inc()
        gateway_security_test_duration_seconds.labels(category=safe_cat).observe(duration_s)
        if safe_stat == "PASS":
            gateway_security_tests_passed_total.labels(category=safe_cat).inc()
        elif safe_stat in ("FAIL", "ERROR"):
            gateway_security_tests_failed_total.labels(category=safe_cat).inc()
    except Exception as e:
        logger.debug(f"Failed to record security test metric: {e}")


def record_security_finding_metric(category: str, severity: str) -> None:
    """
    Record Prometheus metrics for a newly generated security finding.
    Uses safe, low-cardinality labels only.
    """
    try:
        safe_cat = category.strip().upper() if category else "UNKNOWN"
        safe_sev = severity.strip().upper() if severity else "UNKNOWN"
        gateway_security_findings_total.labels(category=safe_cat, severity=safe_sev).inc()
    except Exception as e:
        logger.debug(f"Failed to record security finding metric: {e}")


def record_campaign_run_metric(status: str) -> None:
    """
    Record Prometheus metrics for assessment campaign executions.
    """
    try:
        safe_stat = status.strip().upper() if status else "UNKNOWN"
        gateway_campaign_runs_total.labels(status=safe_stat).inc()
    except Exception as e:
        logger.debug(f"Failed to record campaign run metric: {e}")


def record_regression_detected_metric(category: str, severity: str) -> None:
    """
    Record Prometheus metrics for detected security control regressions.
    """
    try:
        safe_cat = category.strip().upper() if category else "UNKNOWN"
        safe_sev = severity.strip().upper() if severity else "UNKNOWN"
        gateway_regressions_detected_total.labels(category=safe_cat, severity=safe_sev).inc()
    except Exception as e:
        logger.debug(f"Failed to record regression detected metric: {e}")


def record_campaign_score_delta_metric(delta: float) -> None:
    """
    Record histogram metric for campaign score delta compared to baseline.
    """
    try:
        gateway_campaign_score_delta.observe(delta)
    except Exception as e:
        logger.debug(f"Failed to record campaign score delta metric: {e}")


def record_scheduled_campaigns_metric(enabled_count: int, disabled_count: int) -> None:
    """
    Update gauges for total scheduled campaigns by state.
    """
    try:
        gateway_scheduled_campaigns_total.labels(enabled="true").set(enabled_count)
        gateway_scheduled_campaigns_total.labels(enabled="false").set(disabled_count)
    except Exception as e:
        logger.debug(f"Failed to record scheduled campaigns gauge: {e}")


def record_scheduled_campaign_run_metric(campaign_id: str, status: str) -> None:
    """
    Record an automated scheduled campaign run execution.
    """
    try:
        safe_cid = campaign_id.strip() if campaign_id else "unknown"
        safe_stat = status.strip().upper() if status else "UNKNOWN"
        gateway_scheduled_campaign_runs_total.labels(campaign_id=safe_cid, status=safe_stat).inc()
    except Exception as e:
        logger.debug(f"Failed to record scheduled campaign run metric: {e}")


def record_scheduler_error_metric(campaign_id: str, error_type: str) -> None:
    """
    Record a scheduler error occurrence.
    """
    try:
        safe_cid = campaign_id.strip() if campaign_id else "unknown"
        safe_err = error_type.strip().upper() if error_type else "UNKNOWN"
        gateway_scheduler_errors_total.labels(campaign_id=safe_cid, error_type=safe_err).inc()
    except Exception as e:
        logger.debug(f"Failed to record scheduler error metric: {e}")


def record_security_alert_metric(alert_type: str, severity: str) -> None:
    """
    Record a newly generated security alert.
    """
    try:
        safe_type = alert_type.strip().upper() if alert_type else "UNKNOWN"
        safe_sev = severity.strip().upper() if severity else "UNKNOWN"
        gateway_security_alerts_total.labels(alert_type=safe_type, severity=safe_sev).inc()
    except Exception as e:
        logger.debug(f"Failed to record security alert metric: {e}")


def set_security_alerts_open_metric(severity: str, count: int) -> None:
    """
    Update gauge for open security alerts count by severity.
    """
    try:
        safe_sev = severity.strip().upper() if severity else "UNKNOWN"
        gateway_security_alerts_open.labels(severity=safe_sev).set(count)
    except Exception as e:
        logger.debug(f"Failed to set open alerts gauge: {e}")


def set_campaign_security_score_metrics(campaign_id: str, score: float, delta: float) -> None:
    """
    Update latest campaign score and score delta gauges.
    """
    try:
        safe_cid = campaign_id.strip() if campaign_id else "unknown"
        gateway_security_score.labels(campaign_id=safe_cid).set(score)
        gateway_security_score_delta.labels(campaign_id=safe_cid).set(delta)
    except Exception as e:
        logger.debug(f"Failed to set campaign security score gauges: {e}")


def record_report_generated_metric(report_type: str, status: str, duration_s: float = 0.0) -> None:
    """
    Record metrics for a generated security assessment report.
    """
    try:
        safe_type = report_type.strip().upper() if report_type else "UNKNOWN"
        safe_stat = status.strip().upper() if status else "UNKNOWN"
        gateway_reports_generated_total.labels(report_type=safe_type, status=safe_stat).inc()
        if duration_s > 0:
            gateway_report_generation_duration_seconds.labels(report_type=safe_type).observe(duration_s)
    except Exception as e:
        logger.debug(f"Failed to record report generated metric: {e}")


def record_report_failed_metric(report_type: str, error_type: str) -> None:
    """
    Record a security report generation failure.
    """
    try:
        safe_type = report_type.strip().upper() if report_type else "UNKNOWN"
        safe_err = error_type.strip().upper() if error_type else "UNKNOWN"
        gateway_reports_failed_total.labels(report_type=safe_type, error_type=safe_err).inc()
    except Exception as e:
        logger.debug(f"Failed to record report failure metric: {e}")


def record_report_export_metric(export_format: str) -> None:
    """
    Record a report export action.
    """
    try:
        safe_fmt = export_format.strip().lower() if export_format else "unknown"
        gateway_report_exports_total.labels(format=safe_fmt).inc()
    except Exception as e:
        logger.debug(f"Failed to record report export metric: {e}")


def record_report_integrity_failure_metric(report_type: str) -> None:
    """
    Record a report SHA-256 integrity verification failure.
    """
    try:
        safe_type = report_type.strip().upper() if report_type else "UNKNOWN"
        gateway_report_integrity_failures_total.labels(report_type=safe_type).inc()
    except Exception as e:
        logger.debug(f"Failed to record report integrity failure metric: {e}")


def record_evidence_item_metric(category: str, severity: str) -> None:
    """
    Record evidence collection item.
    """
    try:
        safe_cat = category.strip().upper() if category else "UNKNOWN"
        safe_sev = severity.strip().upper() if severity else "UNKNOWN"
        gateway_evidence_items_total.labels(category=safe_cat, severity=safe_sev).inc()
    except Exception as e:
        logger.debug(f"Failed to record evidence item metric: {e}")


# =============================================================================
# 11. Security Incident Investigation & Case Management Metrics (Step 19)
# =============================================================================
gateway_incidents_created_total = Counter(
    "gateway_incidents_created_total",
    "Total number of security incidents created in the gateway",
    ["incident_type", "severity"]
)

gateway_incidents_open = Gauge(
    "gateway_incidents_open",
    "Current number of open security incidents under active SOC investigation",
    ["severity"]
)

gateway_incidents_resolved_total = Counter(
    "gateway_incidents_resolved_total",
    "Total number of security incidents resolved or closed",
    ["resolution_type"]
)

gateway_incident_actions_total = Counter(
    "gateway_incident_actions_total",
    "Total number of controlled SOC response actions recorded for incidents",
    ["action_type", "status"]
)

gateway_incident_correlation_total = Counter(
    "gateway_incident_correlation_total",
    "Total number of automated incident correlation evaluations",
    ["status"]
)

gateway_incident_correlation_errors_total = Counter(
    "gateway_incident_correlation_errors_total",
    "Total number of incident correlation execution errors (isolated fail-safe)",
    ["error_type"]
)

gateway_incident_risk_score = Histogram(
    "gateway_incident_risk_score",
    "Distribution of deterministic security incident risk scores (0-100)",
    ["incident_type"],
    buckets=[10, 25, 40, 55, 70, 85, 100]
)


def record_incident_created_metric(incident_type: str, severity: str) -> None:
    """
    Record a newly created security incident.
    """
    try:
        safe_type = incident_type.strip().upper() if incident_type else "UNKNOWN"
        safe_sev = severity.strip().upper() if severity else "UNKNOWN"
        gateway_incidents_created_total.labels(incident_type=safe_type, severity=safe_sev).inc()
    except Exception as e:
        logger.debug(f"Failed to record incident created metric: {e}")


def set_incidents_open_metric(severity: str, count: int) -> None:
    """
    Set gauge of open incidents by severity.
    """
    try:
        safe_sev = severity.strip().upper() if severity else "UNKNOWN"
        gateway_incidents_open.labels(severity=safe_sev).set(count)
    except Exception as e:
        logger.debug(f"Failed to set open incidents gauge: {e}")


def record_incident_resolved_metric(resolution_type: str) -> None:
    """
    Record an incident resolution or closure.
    """
    try:
        safe_res = resolution_type.strip().upper() if resolution_type else "RESOLVED"
        gateway_incidents_resolved_total.labels(resolution_type=safe_res).inc()
    except Exception as e:
        logger.debug(f"Failed to record incident resolved metric: {e}")


def record_incident_action_metric(action_type: str, status: str = "COMPLETED") -> None:
    """
    Record a controlled incident response action.
    """
    try:
        safe_act = action_type.strip().upper() if action_type else "UNKNOWN"
        safe_stat = status.strip().upper() if status else "COMPLETED"
        gateway_incident_actions_total.labels(action_type=safe_act, status=safe_stat).inc()
    except Exception as e:
        logger.debug(f"Failed to record incident action metric: {e}")


def record_incident_correlation_metric(status: str = "CORRELATED") -> None:
    """
    Record an incident correlation attempt.
    """
    try:
        safe_stat = status.strip().upper() if status else "UNKNOWN"
        gateway_incident_correlation_total.labels(status=safe_stat).inc()
    except Exception as e:
        logger.debug(f"Failed to record incident correlation metric: {e}")


def record_incident_correlation_error_metric(error_type: str = "UNKNOWN") -> None:
    """
    Record an isolated incident correlation error.
    """
    try:
        safe_err = error_type.strip().upper() if error_type else "UNKNOWN"
        gateway_incident_correlation_errors_total.labels(error_type=safe_err).inc()
    except Exception as e:
        logger.debug(f"Failed to record incident correlation error metric: {e}")


def record_incident_risk_score_metric(incident_type: str, score: float) -> None:
    """
    Observe incident risk score distribution.
    """
    try:
        safe_type = incident_type.strip().upper() if incident_type else "UNKNOWN"
        gateway_incident_risk_score.labels(incident_type=safe_type).observe(score)
    except Exception as e:
        logger.debug(f"Failed to record incident risk score metric: {e}")


# =============================================================================
# 12. Step 20 Threat Intelligence, Attack Surface & Exposure Metrics
# =============================================================================

gateway_assets_total = Gauge(
    "gateway_assets_total",
    "Total inventoried gateway assets by type",
    ["asset_type"]
)

gateway_assets_critical = Gauge(
    "gateway_assets_critical",
    "Total critical enterprise assets inventoried"
)

gateway_control_coverage = Gauge(
    "gateway_control_coverage",
    "Current overall security control coverage percentage"
)

gateway_control_gaps_total = Gauge(
    "gateway_control_gaps_total",
    "Current number of detected security control gaps"
)

gateway_threat_intelligence_matches_total = Counter(
    "gateway_threat_intelligence_matches_total",
    "Total threat intelligence metadata matches",
    ["category"]
)

gateway_exposures_total = Gauge(
    "gateway_exposures_total",
    "Total active security exposures by category",
    ["category"]
)

gateway_exposures_critical = Gauge(
    "gateway_exposures_critical",
    "Total critical security exposures open"
)

gateway_exposure_risk_score = Gauge(
    "gateway_exposure_risk_score",
    "Overall enterprise exposure risk score (0-100)"
)


def record_asset_registered_metric(asset_type: str) -> None:
    try:
        safe_type = asset_type.strip().upper() if asset_type else "UNKNOWN"
        gateway_assets_total.labels(asset_type=safe_type).inc()
    except Exception as e:
        logger.debug(f"Failed to record asset metric: {e}")


def record_asset_critical_metric() -> None:
    try:
        gateway_assets_critical.inc()
    except Exception as e:
        logger.debug(f"Failed to record critical asset metric: {e}")


def record_control_coverage_metric(coverage_pct: float) -> None:
    try:
        gateway_control_coverage.set(coverage_pct)
    except Exception as e:
        logger.debug(f"Failed to record control coverage metric: {e}")


def record_control_gap_metric(gaps_count: int) -> None:
    try:
        gateway_control_gaps_total.set(gaps_count)
    except Exception as e:
        logger.debug(f"Failed to record control gap metric: {e}")


def record_threat_intel_match_metric(category: str) -> None:
    try:
        safe_cat = category.strip().upper() if category else "UNKNOWN"
        gateway_threat_intelligence_matches_total.labels(category=safe_cat).inc()
    except Exception as e:
        logger.debug(f"Failed to record threat intel match metric: {e}")


def record_exposure_created_metric(category: str) -> None:
    try:
        safe_cat = category.strip().upper() if category else "UNKNOWN"
        gateway_exposures_total.labels(category=safe_cat).inc()
    except Exception as e:
        logger.debug(f"Failed to record exposure created metric: {e}")


def record_exposure_critical_metric() -> None:
    try:
        gateway_exposures_critical.inc()
    except Exception as e:
        logger.debug(f"Failed to record critical exposure metric: {e}")


def record_exposure_risk_score_metric(risk_score: int) -> None:
    try:
        gateway_exposure_risk_score.set(risk_score)
    except Exception as e:
        logger.debug(f"Failed to record exposure risk score metric: {e}")


# =============================================================================
# Step 21 — Governance, Risk Acceptance & Control Assurance Metrics
# =============================================================================
gateway_governance_risk_score = Gauge(
    "gateway_governance_risk_score",
    "Overall enterprise security governance risk score (0-100)"
)

gateway_risk_exceptions_total = Counter(
    "gateway_risk_exceptions_total",
    "Total security risk exceptions created or transitioned",
    ["status"]
)

gateway_risk_exceptions_open = Gauge(
    "gateway_risk_exceptions_open",
    "Current count of active or approved risk exceptions"
)

gateway_risk_exceptions_overdue = Gauge(
    "gateway_risk_exceptions_overdue",
    "Current count of overdue or expired active risk exceptions"
)

gateway_risk_exceptions_expired_total = Counter(
    "gateway_risk_exceptions_expired_total",
    "Total risk exceptions that reached expiration"
)

gateway_control_assurance_score = Gauge(
    "gateway_control_assurance_score",
    "Average continuous control assurance effectiveness score (0-100)"
)

gateway_control_assurance_gaps_total = Gauge(
    "gateway_control_assurance_gaps_total",
    "Total control assurance gaps identified across security controls"
)

gateway_governance_reviews_total = Counter(
    "gateway_governance_reviews_total",
    "Total security governance reviews completed",
    ["review_type"]
)

gateway_governance_review_failures_total = Counter(
    "gateway_governance_review_failures_total",
    "Total security governance review runs that encountered failures"
)


def record_governance_risk_metric(score: int) -> None:
    try:
        gateway_governance_risk_score.set(max(0, min(100, score)))
    except Exception as e:
        logger.debug(f"Failed to record governance risk metric: {e}")


def record_risk_exception_metric(status: str) -> None:
    try:
        safe_st = status.strip().upper() if status else "DRAFT"
        gateway_risk_exceptions_total.labels(status=safe_st).inc()
    except Exception as e:
        logger.debug(f"Failed to record risk exception metric: {e}")


def set_open_exceptions_metric(open_count: int) -> None:
    try:
        gateway_risk_exceptions_open.set(open_count)
    except Exception as e:
        logger.debug(f"Failed to set open exceptions metric: {e}")


def set_overdue_exceptions_metric(overdue_count: int) -> None:
    try:
        gateway_risk_exceptions_overdue.set(overdue_count)
    except Exception as e:
        logger.debug(f"Failed to set overdue exceptions metric: {e}")


def record_exception_expired_metric() -> None:
    try:
        gateway_risk_exceptions_expired_total.inc()
    except Exception as e:
        logger.debug(f"Failed to record exception expired metric: {e}")


def record_control_assurance_score_metric(score: float) -> None:
    try:
        gateway_control_assurance_score.set(score)
    except Exception as e:
        logger.debug(f"Failed to record control assurance score metric: {e}")


def record_control_assurance_gaps_metric(gaps: int) -> None:
    try:
        gateway_control_assurance_gaps_total.set(gaps)
    except Exception as e:
        logger.debug(f"Failed to record control assurance gaps metric: {e}")


def record_governance_review_metric(review_type: str) -> None:
    try:
        safe_type = review_type.strip().upper() if review_type else "GENERAL"
        gateway_governance_reviews_total.labels(review_type=safe_type).inc()
    except Exception as e:
        logger.debug(f"Failed to record governance review metric: {e}")


def generate_prometheus_metrics() -> bytes:
    """
    Generate Prometheus exposition format payload.
    """
    return generate_latest(REGISTRY)





