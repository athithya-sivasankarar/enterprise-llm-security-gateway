from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Boolean, Float, DateTime, JSON, Index, Text
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class AuditLog(Base):
    """
    SQLAlchemy model for enterprise security audit trail.
    STRICT PRIVACY: Stores security metadata only, never raw PII or raw sensitive prompts/responses.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(64), nullable=False, unique=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    user = Column(String(100), nullable=False, index=True)
    role = Column(String(50), nullable=False)
    model = Column(String(100), nullable=False)
    provider = Column(String(50), default="mock", nullable=True, index=True)
    action = Column(String(20), nullable=False, index=True)  # ALLOW, SANITIZE, BLOCK, ERROR
    risk_score = Column(Integer, nullable=False)
    pii_detected = Column(Boolean, default=False, nullable=False)
    injection_detected = Column(Boolean, default=False, nullable=False)
    threat_type = Column(String(50), nullable=True, index=True)
    response_status = Column(Integer, nullable=False)  # 200, 403, 429, 502, etc.
    latency_ms = Column(Float, nullable=False)
    detected_entities = Column(JSON, default=list, nullable=False)  # e.g. ["EMAIL_ADDRESS"]
    
    # Response security audit fields
    response_risk_score = Column(Integer, default=0, nullable=True)
    response_action = Column(String(20), nullable=True)
    response_threat_type = Column(String(50), nullable=True)

    # Semantic Cache tracking
    cache_hit = Column(Boolean, default=False, nullable=False)

    # Policy Version correlation
    policy_version = Column(String(32), default="1.0.0", nullable=True, index=True)

    __table_args__ = (
        Index("idx_audit_user_timestamp", "user", "timestamp"),
        Index("idx_audit_action_timestamp", "action", "timestamp"),
        Index("idx_audit_cache_hit", "cache_hit"),
        Index("idx_audit_provider", "provider"),
        Index("idx_audit_policy_version", "policy_version"),
    )


class SecurityPolicyModel(Base):
    """
    SQLAlchemy model for versioned, centralized security policies.
    Guaranteed: Only one policy is marked is_active=True at any time.
    """
    __tablename__ = "security_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    policy_version = Column(String(32), nullable=False, unique=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    policy_json = Column(JSON, nullable=False)
    is_active = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    created_by = Column(String(100), default="system", nullable=False)


class SecurityTestRunModel(Base):
    """
    SQLAlchemy model for tracking security validation / red-team test runs.
    """
    __tablename__ = "security_test_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), nullable=False, unique=True, index=True)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(50), default="RUNNING", nullable=False, index=True)  # RUNNING, COMPLETED, COMPLETED_WITH_FAILURES, COMPLETED_WITH_ERRORS
    total_tests = Column(Integer, default=0, nullable=False)
    passed_tests = Column(Integer, default=0, nullable=False)
    failed_tests = Column(Integer, default=0, nullable=False)
    error_tests = Column(Integer, default=0, nullable=False)
    skipped_tests = Column(Integer, default=0, nullable=False)
    security_score = Column(Float, default=0.0, nullable=False)
    created_by = Column(String(100), default="system", nullable=False)
    policy_version = Column(String(32), default="1.0.0", nullable=True, index=True)

    __table_args__ = (
        Index("idx_test_run_status", "status"),
        Index("idx_test_run_started_at", "started_at"),
        Index("idx_test_run_policy_version", "policy_version"),
    )


class SecurityTestResultModel(Base):
    """
    SQLAlchemy model for individual security assertion / test case results.
    """
    __tablename__ = "security_test_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), nullable=False, index=True)
    test_id = Column(String(64), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    status = Column(String(50), nullable=False, index=True)  # PASS, FAIL, ERROR, SKIPPED
    severity = Column(String(20), default="MEDIUM", nullable=False, index=True)

    expected_action = Column(String(20), nullable=True)
    actual_action = Column(String(20), nullable=True)
    expected_status = Column(Integer, nullable=True)
    actual_status = Column(Integer, nullable=True)
    threat_type = Column(String(50), nullable=True)
    latency_ms = Column(Float, default=0.0, nullable=False)
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    __table_args__ = (
        Index("idx_test_result_run_test", "run_id", "test_id"),
        Index("idx_test_result_category_status", "category", "status"),
        Index("idx_test_result_severity", "severity"),
        Index("idx_test_result_created_at", "created_at"),
    )


class SecurityTestFindingModel(Base):
    """
    SQLAlchemy model for normalized security findings arising from failed tests.
    """
    __tablename__ = "security_test_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(64), nullable=False, unique=True, index=True)
    run_id = Column(String(64), nullable=False, index=True)
    test_id = Column(String(64), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    expected_behavior = Column(Text, nullable=False)
    actual_behavior = Column(Text, nullable=False)
    endpoint = Column(String(100), default="/api/chat", nullable=False)
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    __table_args__ = (
        Index("idx_finding_run_id", "run_id"),
        Index("idx_finding_test_id", "test_id"),
        Index("idx_finding_category", "category"),
        Index("idx_finding_severity", "severity"),
        Index("idx_finding_created_at", "created_at"),
    )


class SecurityCampaignModel(Base):
    """
    SQLAlchemy model for managing security assessment campaigns.
    """
    __tablename__ = "security_campaigns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(String(64), nullable=False, unique=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    status = Column(String(20), default="ACTIVE", nullable=False, index=True)  # ACTIVE, PAUSED, ARCHIVED
    created_by = Column(String(100), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    last_run_id = Column(String(64), nullable=True)
    schedule_enabled = Column(Boolean, default=False, nullable=False)
    schedule_interval = Column(String(50), nullable=True)  # e.g. "hourly", "daily", "weekly"
    category_filter = Column(JSON, default=list, nullable=False)  # empty = all categories
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    baseline_run_id = Column(String(64), nullable=True, index=True)

    __table_args__ = (
        Index("idx_campaign_status", "status"),
        Index("idx_campaign_created_by", "created_by"),
        Index("idx_campaign_created_at", "created_at"),
        Index("idx_campaign_baseline_run", "baseline_run_id"),
    )


class SecurityCampaignRunModel(Base):
    """
    SQLAlchemy model for recording executions of assessment campaigns.
    """
    __tablename__ = "security_campaign_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_run_id = Column(String(64), nullable=False, unique=True, index=True)
    campaign_id = Column(String(64), nullable=False, index=True)
    run_id = Column(String(64), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(50), default="RUNNING", nullable=False)  # RUNNING, COMPLETED, COMPLETED_WITH_REGRESSIONS, FAILED
    total_tests = Column(Integer, default=0, nullable=False)
    passed_tests = Column(Integer, default=0, nullable=False)
    failed_tests = Column(Integer, default=0, nullable=False)
    error_tests = Column(Integer, default=0, nullable=False)
    skipped_tests = Column(Integer, default=0, nullable=False)
    security_score = Column(Float, default=0.0, nullable=False)
    baseline_score = Column(Float, nullable=True)
    score_delta = Column(Float, nullable=True)
    regression_detected = Column(Boolean, default=False, nullable=False, index=True)
    created_by = Column(String(100), nullable=False)
    policy_version = Column(String(32), default="1.0.0", nullable=True)

    __table_args__ = (
        Index("idx_campaign_run_campaign", "campaign_id"),
        Index("idx_campaign_run_run_id", "run_id"),
        Index("idx_campaign_run_started", "started_at"),
        Index("idx_campaign_run_regression", "regression_detected"),
    )


class SecurityRegressionModel(Base):
    """
    SQLAlchemy model for tracking individual test regressions compared to baseline.
    """
    __tablename__ = "security_regressions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    regression_id = Column(String(64), nullable=False, unique=True, index=True)
    campaign_run_id = Column(String(64), nullable=False, index=True)
    campaign_id = Column(String(64), nullable=False, index=True)
    test_id = Column(String(64), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    previous_status = Column(String(50), nullable=False)
    current_status = Column(String(50), nullable=False)
    previous_score = Column(Float, nullable=True)
    current_score = Column(Float, nullable=True)
    score_delta = Column(Float, nullable=True)
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    baseline_run_id = Column(String(64), nullable=True)
    current_run_id = Column(String(64), nullable=True)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    __table_args__ = (
        Index("idx_regression_campaign", "campaign_id"),
        Index("idx_regression_campaign_run", "campaign_run_id"),
        Index("idx_regression_test_id", "test_id"),
        Index("idx_regression_category", "category"),
        Index("idx_regression_severity", "severity"),
        Index("idx_regression_created_at", "created_at"),
    )


class SecurityScheduleModel(Base):
    """
    SQLAlchemy model for managing recurring campaign execution schedules.
    """
    __tablename__ = "security_campaign_schedules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    schedule_id = Column(String(64), nullable=False, unique=True, index=True)
    campaign_id = Column(String(64), nullable=False, index=True)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    schedule_type = Column(String(20), default="INTERVAL", nullable=False)  # INTERVAL, CRON
    cron_expression = Column(String(100), nullable=True)
    interval_minutes = Column(Integer, default=1440, nullable=True)  # Minimum 60 minutes
    timezone = Column(String(50), default="UTC", nullable=False)
    next_run_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_run_status = Column(String(50), nullable=True)
    last_error = Column(Text, nullable=True)
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("idx_schedule_campaign", "campaign_id"),
        Index("idx_schedule_enabled_next_run", "enabled", "next_run_at"),
    )


class SecurityAlertModel(Base):
    """
    SQLAlchemy model for actionable SOC alerts triggered by campaign regressions & degradation.
    """
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), nullable=False, unique=True, index=True)
    campaign_id = Column(String(64), nullable=False, index=True)
    campaign_run_id = Column(String(64), nullable=True, index=True)
    alert_type = Column(String(50), nullable=False, index=True)  # CAMPAIGN_REGRESSION, SECURITY_SCORE_DEGRADATION, CAMPAIGN_EXECUTION_ERROR, SCHEDULER_ERROR
    severity = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status = Column(String(20), default="OPEN", nullable=False, index=True)  # OPEN, ACKNOWLEDGED, RESOLVED
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    score = Column(Float, nullable=True)
    baseline_score = Column(Float, nullable=True)
    score_delta = Column(Float, nullable=True)
    regression_count = Column(Integer, default=0, nullable=False)
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    acknowledged_by = Column(String(100), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(100), nullable=True)

    __table_args__ = (
        Index("idx_alert_campaign", "campaign_id"),
        Index("idx_alert_run", "campaign_run_id"),
        Index("idx_alert_status_severity", "status", "severity"),
        Index("idx_alert_type", "alert_type"),
        Index("idx_alert_created_at", "created_at"),
    )


class SecurityReportModel(Base):
    """
    SQLAlchemy model for persistent, auditable security assessment reports.
    """
    __tablename__ = "security_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String(64), nullable=False, unique=True, index=True)
    report_type = Column(String(50), nullable=False, index=True)  # CAMPAIGN, SECURITY_VALIDATION, REGRESSION, EXECUTIVE, COMPLIANCE
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default="GENERATING", nullable=False, index=True)  # GENERATING, COMPLETED, FAILED
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    campaign_id = Column(String(64), nullable=True, index=True)
    campaign_run_id = Column(String(64), nullable=True, index=True)
    security_score = Column(Float, default=0.0, nullable=False)
    baseline_score = Column(Float, nullable=True)
    score_delta = Column(Float, nullable=True)
    regression_count = Column(Integer, default=0, nullable=False)
    critical_findings = Column(Integer, default=0, nullable=False)
    high_findings = Column(Integer, default=0, nullable=False)
    medium_findings = Column(Integer, default=0, nullable=False)
    low_findings = Column(Integer, default=0, nullable=False)
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    report_version = Column(String(32), default="1.0.0", nullable=False)
    report_hash = Column(String(64), nullable=True, index=True)
    report_data = Column(JSON, nullable=True)  # Canonical sanitized report snapshot

    __table_args__ = (
        Index("idx_report_campaign", "campaign_id"),
        Index("idx_report_campaign_run", "campaign_run_id"),
        Index("idx_report_status", "status"),
        Index("idx_report_created_at", "created_at"),
    )


class SecurityEvidenceModel(Base):
    """
    SQLAlchemy model for normalized, sanitized security control evidence.
    Never stores raw prompts, raw responses, API keys, passwords, bearer tokens, or PII.
    """
    __tablename__ = "security_report_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String(64), nullable=False, unique=True, index=True)
    report_id = Column(String(64), nullable=False, index=True)
    campaign_run_id = Column(String(64), nullable=True, index=True)
    test_id = Column(String(64), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    evidence_type = Column(String(50), nullable=False)
    expected_behavior = Column(Text, nullable=False)
    actual_behavior = Column(Text, nullable=False)
    security_control = Column(String(100), nullable=False)
    endpoint = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False)
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    __table_args__ = (
        Index("idx_evidence_report", "report_id"),
        Index("idx_evidence_test", "test_id"),
        Index("idx_evidence_category", "category"),
        Index("idx_evidence_severity", "severity"),
        Index("idx_evidence_created_at", "created_at"),
    )


class SecurityIncidentModel(Base):
    """
    SQLAlchemy model for enterprise security incidents, case management, and SOC investigations.
    """
    __tablename__ = "security_incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(64), nullable=False, unique=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    incident_type = Column(String(50), nullable=False, default="SECURITY_REGRESSION")  # SECURITY_REGRESSION, POSTURE_DEGRADATION, MULTI_DOMAIN_VULNERABILITY, THREAT_SPIKE, MANUAL
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status = Column(String(20), nullable=False, default="OPEN", index=True)  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE
    priority = Column(String(20), nullable=False, default="P2")  # P1, P2, P3, P4
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(String(100), default="system", nullable=False)
    assigned_to = Column(String(100), nullable=True)
    source_alert_id = Column(String(64), nullable=True, index=True)
    campaign_id = Column(String(64), nullable=True, index=True)
    campaign_run_id = Column(String(64), nullable=True, index=True)
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    risk_score = Column(Integer, default=0, nullable=False)  # Deterministic 0-100 incident risk score

    __table_args__ = (
        Index("idx_incident_id", "incident_id"),
        Index("idx_incident_severity", "severity"),
        Index("idx_incident_status", "status"),
        Index("idx_incident_created_at", "created_at"),
        Index("idx_incident_campaign_id", "campaign_id"),
        Index("idx_incident_campaign_run_id", "campaign_run_id"),
        Index("idx_incident_source_alert_id", "source_alert_id"),
    )


class SecurityIncidentEventModel(Base):
    """
    SQLAlchemy model for normalized timeline events linked to a security incident.
    Stores sanitized metadata only.
    """
    __tablename__ = "security_incident_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), nullable=False, unique=True, index=True)
    incident_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    event_timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    source_type = Column(String(50), nullable=False)  # ALERT, CAMPAIGN_RUN, TEST_RUN, FINDING, REGRESSION, NOTE, ACTION, REPORT
    source_id = Column(String(64), nullable=True, index=True)
    category = Column(String(50), nullable=True, index=True)
    severity = Column(String(20), nullable=True, index=True)
    description = Column(Text, nullable=False)
    metadata_json = Column("metadata", JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("idx_inc_event_incident_id", "incident_id"),
        Index("idx_inc_event_type", "event_type"),
        Index("idx_inc_event_timestamp", "event_timestamp"),
        Index("idx_inc_event_category", "category"),
        Index("idx_inc_event_severity", "severity"),
    )


class SecurityIncidentEvidenceModel(Base):
    """
    SQLAlchemy model for auditable evidence artifacts attached to a security incident investigation.
    Never stores sensitive credentials or raw prompts/responses.
    """
    __tablename__ = "security_incident_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String(64), nullable=False, unique=True, index=True)
    incident_id = Column(String(64), nullable=False, index=True)
    evidence_type = Column(String(50), nullable=False, index=True)  # SECURITY_TEST_RESULT, FINDING, REGRESSION, REPORT, AUDIT_METADATA, MANUAL
    source_id = Column(String(64), nullable=True, index=True)
    description = Column(Text, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    created_by = Column(String(100), default="system", nullable=False)

    __table_args__ = (
        Index("idx_inc_ev_incident_id", "incident_id"),
        Index("idx_inc_ev_id", "evidence_id"),
        Index("idx_inc_ev_type", "evidence_type"),
        Index("idx_inc_ev_created_at", "created_at"),
    )


class SecurityIncidentNoteModel(Base):
    """
    SQLAlchemy model for analyst notes and investigation observations.
    Notes are strictly sanitized before persistence.
    """
    __tablename__ = "security_incident_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    note_id = Column(String(64), nullable=False, unique=True, index=True)
    incident_id = Column(String(64), nullable=False, index=True)
    author = Column(String(100), nullable=False, index=True)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    __table_args__ = (
        Index("idx_inc_note_incident_id", "incident_id"),
        Index("idx_inc_note_created_at", "created_at"),
        Index("idx_inc_note_author", "author"),
    )


class SecurityIncidentActionModel(Base):
    """
    SQLAlchemy model for controlled, non-destructive SOC response actions taken on an incident.
    """
    __tablename__ = "security_incident_actions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action_id = Column(String(64), nullable=False, unique=True, index=True)
    incident_id = Column(String(64), nullable=False, index=True)
    action_type = Column(String(50), nullable=False, index=True)  # ACKNOWLEDGE_ALERT, ASSIGN_INCIDENT, CHANGE_STATUS, MARK_FALSE_POSITIVE, ATTACH_EVIDENCE, ATTACH_REPORT, REQUEST_POLICY_REVIEW
    requested_by = Column(String(100), nullable=False)
    approved_by = Column(String(100), nullable=True)
    status = Column(String(20), default="COMPLETED", nullable=False, index=True)  # REQUESTED, APPROVED, COMPLETED, REJECTED
    description = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_inc_action_incident_id", "incident_id"),
        Index("idx_inc_action_id", "action_id"),
        Index("idx_inc_action_type", "action_type"),
        Index("idx_inc_action_status", "status"),
        Index("idx_inc_action_created_at", "created_at"),
    )


# =============================================================================
# Step 20 — Threat Intelligence, Attack Surface & Security Control Coverage Models
# =============================================================================

class SecurityAssetModel(Base):
    """
    SQLAlchemy model representing an inventoried enterprise AI/LLM asset or gateway component.
    """
    __tablename__ = "security_assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(String(64), nullable=False, unique=True, index=True)
    asset_type = Column(String(50), nullable=False, index=True)  # APPLICATION, API, ENDPOINT, LLM_MODEL, LLM_PROVIDER, DATABASE, CACHE, SECURITY_CONTROL, KUBERNETES_SERVICE
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    environment = Column(String(50), default="production", nullable=False)  # production, staging, development
    endpoint = Column(String(255), nullable=True)
    provider = Column(String(50), nullable=True)  # openai, anthropic, mock, postgres, redis, system
    model = Column(String(100), nullable=True)
    owner = Column(String(100), default="security-team", nullable=False)
    criticality = Column(String(20), default="HIGH", nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(20), default="ACTIVE", nullable=False, index=True)  # ACTIVE, INACTIVE, DECOMMISSIONED
    discovered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    last_security_score = Column(Float, nullable=True)
    risk_score = Column(Integer, default=0, nullable=False, index=True)  # Deterministic 0-100 asset risk score
    policy_version = Column(String(32), default="1.0.0", nullable=True)

    __table_args__ = (
        Index("idx_asset_type_crit", "asset_type", "criticality"),
        Index("idx_asset_status_risk", "status", "risk_score"),
    )


class SecurityControlModel(Base):
    """
    SQLAlchemy model representing an inventoried security control and its verification status.
    """
    __tablename__ = "security_controls"

    id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(String(64), nullable=False, unique=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    domain = Column(String(50), nullable=False, index=True)  # AUTHENTICATION, RBAC, INPUT_DLP, PROMPT_INJECTION, JAILBREAK, SYSTEM_PROMPT_EXTRACTION, SECRET_LEAKAGE, UNSAFE_CONTENT, RESPONSE_PII, RATE_LIMITING, CACHE_ISOLATION, POLICY, AUDIT, OBSERVABILITY
    control_type = Column(String(50), default="PREVENTIVE", nullable=False, index=True)  # PREVENTIVE, DETECTIVE, CORRECTIVE
    enabled = Column(Boolean, default=True, nullable=False)
    implementation_status = Column(String(50), default="IMPLEMENTED", nullable=False, index=True)  # IMPLEMENTED, PARTIAL, NOT_IMPLEMENTED, DISABLED
    coverage_percentage = Column(Float, default=100.0, nullable=False)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    last_test_status = Column(String(50), default="PASS", nullable=True)  # PASS, FAIL, ERROR, NOT_TESTED
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("idx_control_domain_type", "domain", "control_type"),
        Index("idx_control_impl_status", "implementation_status"),
    )


class SecurityAssetFindingModel(Base):
    """
    SQLAlchemy model linking discovered vulnerabilities/findings to specific inventoried assets.
    """
    __tablename__ = "security_asset_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(64), nullable=False, unique=True, index=True)
    asset_id = Column(String(64), nullable=False, index=True)
    source_type = Column(String(50), nullable=False)  # SECURITY_TEST, CAMPAIGN_REGRESSION, INCIDENT, THREAT_INTEL, MANUAL
    source_id = Column(String(64), nullable=True, index=True)
    category = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status = Column(String(20), default="OPEN", nullable=False, index=True)  # OPEN, IN_PROGRESS, RESOLVED, FALSE_POSITIVE
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    risk_score = Column(Integer, default=0, nullable=False)
    first_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    policy_version = Column(String(32), default="1.0.0", nullable=True)

    __table_args__ = (
        Index("idx_asset_finding_asset_sev", "asset_id", "severity"),
        Index("idx_asset_finding_status", "status"),
    )


class ThreatIntelligenceModel(Base):
    """
    SQLAlchemy model for normalized, safe threat intelligence indicators (CVE, CWE, ATLAS, OWASP).
    Metadata only. Never stores exploit payloads or malicious shellcode.
    """
    __tablename__ = "security_threat_intelligence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    intel_id = Column(String(64), nullable=False, unique=True, index=True)
    source = Column(String(50), nullable=False)  # BUILTIN_CATALOG, MITRE_ATLAS, MITRE_ATTACK, OWASP_TOP_10_LLM, NVD_CVE, COMMUNITY
    indicator_type = Column(String(50), nullable=False, index=True)  # CVE, CWE, ATTACK_TECHNIQUE, ATLAS_TECHNIQUE, OWASP_CATEGORY, CONTROL_WEAKNESS, THREAT_PATTERN
    indicator = Column(String(100), nullable=False, index=True)  # e.g., "AML.T0054", "LLM01", "CWE-77", "CVE-2024-0001"
    category = Column(String(50), nullable=False, index=True)  # PROMPT_INJECTION, SECRET_LEAKAGE, etc.
    severity = Column(String(20), default="HIGH", nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(Float, default=0.9, nullable=False)  # 0.0 - 1.0 confidence score
    description = Column(Text, nullable=False)
    first_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(20), default="ACTIVE", nullable=False, index=True)  # ACTIVE, DEPRECATED, EXPIRED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    __table_args__ = (
        Index("idx_intel_indicator_type", "indicator_type", "indicator"),
        Index("idx_intel_cat_sev", "category", "severity"),
    )


class SecurityExposureModel(Base):
    """
    SQLAlchemy model for enterprise security exposures and attack surface vulnerabilities.
    """
    __tablename__ = "security_exposures"

    id = Column(Integer, primary_key=True, autoincrement=True)
    exposure_id = Column(String(64), nullable=False, unique=True, index=True)
    asset_id = Column(String(64), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    risk_score = Column(Integer, default=0, nullable=False, index=True)  # Deterministic 0-100 risk score
    exposure_type = Column(String(50), nullable=False)  # CONTROL_GAP, ACTIVE_REGRESSION, UNPROTECTED_MODEL, THREAT_MATCH, UNTESTED_CONTROL
    description = Column(Text, nullable=False)
    source_id = Column(String(64), nullable=True, index=True)  # finding_id, regression_id, incident_id, intel_id
    first_detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    status = Column(String(20), default="OPEN", nullable=False, index=True)  # OPEN, MITIGATED, RESOLVED, FALSE_POSITIVE

    __table_args__ = (
        Index("idx_exposure_asset_cat", "asset_id", "category"),
        Index("idx_exposure_sev_risk", "severity", "risk_score"),
        Index("idx_exposure_status", "status"),
    )


# =============================================================================
# Step 21 — Security Governance, Risk Acceptance & Control Assurance Models
# =============================================================================

class SecurityRiskExceptionModel(Base):
    """
    SQLAlchemy model representing a governed, bounded risk exception.
    Tracks business justification, mandatory expiration, compensating controls, and full lifecycle.
    INVARIANT: Risk acceptance does NOT disable or weaken runtime security controls.
    """
    __tablename__ = "security_risk_exceptions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    exception_id = Column(String(64), nullable=False, unique=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    risk_type = Column(String(50), nullable=False, default="GENERAL")
    severity = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(30), default="DRAFT", nullable=False, index=True)  # DRAFT, PENDING_APPROVAL, APPROVED, REJECTED, EXPIRED, REVOKED, CLOSED
    asset_id = Column(String(64), nullable=True, index=True)
    control_id = Column(String(64), nullable=True, index=True)
    exposure_id = Column(String(64), nullable=True, index=True)
    incident_id = Column(String(64), nullable=True, index=True)
    source_type = Column(String(50), nullable=True)  # EXPOSURE, INCIDENT, FINDING, CONTROL_GAP, MANUAL
    source_id = Column(String(64), nullable=True, index=True)
    business_justification = Column(Text, nullable=False)
    compensating_controls = Column(Text, nullable=True)
    owner = Column(String(100), nullable=False, index=True)
    requested_by = Column(String(100), nullable=False)
    approved_by = Column(String(100), nullable=True)
    requested_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    effective_from = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    review_due_at = Column(DateTime(timezone=True), nullable=True, index=True)
    risk_score = Column(Integer, default=0, nullable=False, index=True)  # Clamped 0-100 deterministic score
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_risk_exc_status_sev", "status", "severity"),
        Index("idx_risk_exc_expires_owner", "expires_at", "owner"),
        Index("idx_risk_exc_asset_control", "asset_id", "control_id"),
        Index("idx_risk_exc_score", "risk_score"),
    )


class SecurityGovernanceReviewModel(Base):
    """
    SQLAlchemy model representing periodic or triggered governance reviews aggregating posture,
    control effectiveness, exceptions, exposures, and incident histories.
    """
    __tablename__ = "security_governance_reviews"

    id = Column(Integer, primary_key=True, autoincrement=True)
    review_id = Column(String(64), nullable=False, unique=True, index=True)
    review_type = Column(String(50), nullable=False, index=True)  # CONTROL_EFFECTIVENESS, RISK_EXCEPTION_REVIEW, EXPOSURE_REVIEW, INCIDENT_REVIEW, EXECUTIVE_SECURITY_REVIEW
    scope = Column(String(100), default="enterprise", nullable=False)
    status = Column(String(30), default="COMPLETED", nullable=False, index=True)  # PLANNED, IN_PROGRESS, COMPLETED, FAILED
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    reviewer = Column(String(100), default="security-officer", nullable=False)
    overall_score = Column(Float, default=100.0, nullable=False)
    control_coverage = Column(Float, default=100.0, nullable=False)
    open_exceptions = Column(Integer, default=0, nullable=False)
    overdue_exceptions = Column(Integer, default=0, nullable=False)
    critical_exposures = Column(Integer, default=0, nullable=False)
    open_incidents = Column(Integer, default=0, nullable=False)
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    summary = Column(Text, nullable=False)  # Sanitized narrative executive summary or JSON
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    __table_args__ = (
        Index("idx_gov_review_type_status", "review_type", "status"),
        Index("idx_gov_review_created_at", "created_at"),
    )


class SecurityControlAssuranceModel(Base):
    """
    SQLAlchemy model recording continuous control assurance assessments for each security control.
    """
    __tablename__ = "security_control_assurance"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assurance_id = Column(String(64), nullable=False, unique=True, index=True)
    control_id = Column(String(64), nullable=False, index=True)
    assessment_period = Column(String(50), default="current", nullable=False)
    test_count = Column(Integer, default=0, nullable=False)
    passed_tests = Column(Integer, default=0, nullable=False)
    failed_tests = Column(Integer, default=0, nullable=False)
    coverage_percentage = Column(Float, default=100.0, nullable=False)
    effectiveness_score = Column(Float, default=100.0, nullable=False)
    gap_count = Column(Integer, default=0, nullable=False)
    regression_count = Column(Integer, default=0, nullable=False)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    last_status = Column(String(20), default="PASS", nullable=False)  # PASS, FAIL, GAP, DEGRADED
    risk_score = Column(Integer, default=0, nullable=False)
    policy_version = Column(String(32), default="1.0.0", nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("idx_ctrl_assurance_control_id", "control_id"),
        Index("idx_ctrl_assurance_status", "last_status"),
    )


class SecurityGovernanceEventModel(Base):
    """
    SQLAlchemy model representing an append-only, immutable audit trail for all governance events.
    STRICT PRIVACY: Metadata contains sanitized operational context only.
    """
    __tablename__ = "security_governance_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), nullable=False, unique=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)  # RISK_EXCEPTION_CREATED, APPROVED, EXPIRED, etc.
    entity_type = Column(String(50), nullable=False, index=True)  # EXCEPTION, ASSURANCE, REVIEW, POSTURE
    entity_id = Column(String(64), nullable=False, index=True)
    actor = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    metadata_json = Column("metadata", JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    __table_args__ = (
        Index("idx_gov_event_type_entity", "event_type", "entity_type"),
        Index("idx_gov_event_created_actor", "created_at", "actor"),
    )







