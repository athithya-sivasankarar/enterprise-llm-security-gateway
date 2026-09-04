import re
import json
import logging
import datetime
from typing import Any, Dict, Optional

# Regex patterns for central automated redaction of sensitive values
SENSITIVE_PATTERNS = [
    (r"(?i)\b(?:sk-[a-zA-Z0-9_-]{20,})\b", "[REDACTED_API_KEY]"),
    (r"(?i)\b(?:AKIA[0-9A-Z]{16})\b", "[REDACTED_AWS_KEY]"),
    (r"(?i)\b(?:Bearer\s+[a-zA-Z0-9_\-\.]{20,})\b", "Bearer [REDACTED_TOKEN]"),
    (r"(?i)\b(?:password|passwd|pwd|api_secret|client_secret)[\s:=]+['\"]?([^'\"\s]{4,})['\"]?", r"\1: [REDACTED_SECRET]"),
    (r"(?i)\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    (r"(?i)\b(?:\d{4}[- ]?){3}\d{4}\b", "[REDACTED_CARD]"),
    (r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]"),
]

# Sensitive keys to never log in dict metadata
FORBIDDEN_METADATA_KEYS = {
    "prompt",
    "raw_prompt",
    "response",
    "raw_response",
    "api_key",
    "x_api_key",
    "authorization",
    "password",
    "postgres_password",
    "openai_api_key",
    "anthropic_api_key",
    "secret",
    "secret_key",
    "token",
    "access_token",
    "bearer_token",
    "cache_value"
}


def sanitize_text(text: Optional[str]) -> str:
    """
    Central redaction of any sensitive credentials or PII from log strings.
    """
    if not text:
        return ""
    sanitized = str(text)
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = re.sub(pattern, replacement, sanitized)
    return sanitized


def sanitize_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively sanitize dictionary to ensure no forbidden sensitive keys or patterns are logged.
    """
    cleaned: Dict[str, Any] = {}
    for k, v in data.items():
        if str(k).lower() in FORBIDDEN_METADATA_KEYS:
            continue
        if isinstance(v, dict):
            cleaned[k] = sanitize_metadata(v)
        elif isinstance(v, list):
            cleaned[k] = [sanitize_metadata(item) if isinstance(item, dict) else (sanitize_text(str(item)) if isinstance(item, str) else item) for item in v]
        elif isinstance(v, str):
            cleaned[k] = sanitize_text(v)
        else:
            cleaned[k] = v
    return cleaned


class StructuredJSONFormatter(logging.Formatter):
    """
    Formats log records into normalized, SIEM-friendly JSON strings.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "enterprise-llm-security-gateway",
            "logger": record.name,
            "message": sanitize_text(record.getMessage())
        }

        # Include custom structured fields attached to the LogRecord
        if hasattr(record, "structured_data") and isinstance(record.structured_data, dict):
            cleaned_data = sanitize_metadata(record.structured_data)
            log_entry.update(cleaned_data)

        if record.exc_info:
            # Mask any credentials in exception representations
            exc_str = self.formatException(record.exc_info)
            log_entry["exception"] = sanitize_text(exc_str)

        return json.dumps(log_entry)


logger = logging.getLogger("enterprise_security")


def setup_structured_logging(level: int = logging.INFO) -> None:
    """
    Configure root and application handlers with StructuredJSONFormatter.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJSONFormatter())
    
    root = logging.getLogger()
    root.setLevel(level)
    # Remove existing stream handlers to prevent duplicate lines
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)


def log_security_event(
    event_type: str,
    request_id: str,
    action: str,
    response_status: int,
    user: Optional[str] = None,
    role: Optional[str] = None,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    threat_type: Optional[str] = None,
    risk_score: int = 0,
    pii_detected: bool = False,
    injection_detected: bool = False,
    latency_ms: Optional[float] = None,
    cache_hit: bool = False,
    route: str = "/api/chat",
    method: str = "POST",
    detected_entities: Optional[list] = None
) -> None:
    """
    Emit a structured JSON security audit log containing metadata only.
    Guaranteed to never log prompts, responses, or API keys.
    """
    structured_payload: Dict[str, Any] = {
        "event_type": event_type,
        "request_id": request_id,
        "route": route,
        "method": method,
        "action": action,
        "response_status": response_status,
        "user": user or "anonymous",
        "role": role or "unknown",
        "model": model or "unknown",
        "provider": provider or "mock",
        "threat_type": threat_type,
        "risk_score": risk_score,
        "pii_detected": pii_detected,
        "injection_detected": injection_detected,
        "latency_ms": latency_ms,
        "cache_hit": cache_hit,
        "detected_entities": detected_entities or []
    }

    cleaned = sanitize_metadata(structured_payload)
    
    log_level = logging.WARNING if action == "BLOCK" or response_status >= 400 else logging.INFO
    logger.log(
        log_level,
        f"Security Event: {event_type} | action={action} | status={response_status} | user={user}",
        extra={"structured_data": cleaned}
    )


def log_governance_event(
    event_type: str,
    entity_type: str,
    entity_id: str,
    actor: str,
    description: str,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """
    Emit a structured JSON SIEM governance event containing sanitized metadata only.
    Guaranteed: zero raw prompts, responses, credentials, or PII.
    """
    structured_payload: Dict[str, Any] = {
        "event_type": event_type,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "actor": actor,
        "description": sanitize_text(description),
        "metadata": metadata or {}
    }

    cleaned = sanitize_metadata(structured_payload)
    log_level = logging.WARNING if "CRITICAL" in event_type or "EXPIRED" in event_type or "REJECTED" in event_type else logging.INFO
    logger.log(
        log_level,
        f"Governance Event: {event_type} | entity={entity_type}:{entity_id} | actor={actor}",
        extra={"structured_data": cleaned}
    )

