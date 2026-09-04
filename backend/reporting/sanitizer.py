import re
from typing import Any, Dict, List, Union, Optional

# Regex patterns for high-confidence sensitive credential and PII redaction
REDACTION_PATTERNS = [
    # JWT Tokens
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+\b"), "[REDACTED_JWT]"),
    # Bearer Tokens
    (re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9._\-]{10,}\b"), "Bearer [REDACTED_TOKEN]"),
    # OpenAI API Keys
    (re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"), "[REDACTED_API_KEY]"),
    # AWS Access Key IDs
    (re.compile(r"\bAKIA[0-9A-Z]{12,28}\b"), "[REDACTED_AWS_KEY]"),
    # GitHub Tokens

    (re.compile(r"\bgh[pousr]_[a-zA-Z0-9]{36}\b"), "[REDACTED_TOKEN]"),
    # Generic API Keys / Secrets
    (re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?"), r"\1=[REDACTED_SECRET]"),
    # Passwords in connection strings or key-value pairs
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s,;]+['\"]?"), r"\1=[REDACTED_PASSWORD]"),
    # Database connection strings with embedded credentials
    (re.compile(r"(?i)([a-zA-Z0-9+_.-]+)://([^:]+):([^@]+)@"), r"\1://[REDACTED_USER]:[REDACTED_PASSWORD]@"),
    # Private Keys

    (re.compile(r"-----BEGIN [A-Z\s]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z\s]+ PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # Credit Card Numbers (Luhn-like 16 digits)
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "[REDACTED_CREDIT_CARD]"),
    # US Social Security Numbers
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[REDACTED_EMAIL]"),
    # Phone numbers
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED_PHONE]")
]

FORBIDDEN_RAW_KEYS = {
    "prompt",
    "raw_prompt",
    "response",
    "raw_response",
    "payload",
    "raw_payload",
    "api_key",
    "authorization",
    "password",
    "secret",
    "token",
    "credential",
    "credentials",
    "database_url",
    "db_password",
    "auth_header"
}


def sanitize_text(text: Optional[str]) -> str:
    """
    Sanitize text strings by scrubbing credentials, tokens, PII, and secrets.
    Preserves normal security terminology (e.g. 'SQL injection', 'API security', 'authentication').
    """
    if not text:
        return ""

    sanitized = str(text)
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized


def sanitize_metadata(data: Union[Dict[str, Any], List[Any], Any]) -> Any:
    """
    Recursively sanitize dictionaries and lists, stripping forbidden payload keys
    and redacting sensitive values.
    """
    if isinstance(data, dict):
        cleaned = {}
        for key, value in data.items():
            k_lower = key.lower()
            if k_lower in FORBIDDEN_RAW_KEYS or any(f in k_lower for f in ["raw_prompt", "raw_response", "api_key", "password", "secret"]):
                cleaned[key] = "[REDACTED_SENSITIVE_PAYLOAD]"
            else:
                cleaned[key] = sanitize_metadata(value)
        return cleaned
    elif isinstance(data, list):
        return [sanitize_metadata(item) for item in data]
    elif isinstance(data, str):
        return sanitize_text(data)
    else:
        return data


def sanitize_evidence_item(evidence_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize a single evidence dictionary before persistence or reporting.
    Ensures expected and actual behaviors contain no raw sensitive payloads.
    """
    sanitized = sanitize_metadata(evidence_dict)
    if "expected_behavior" in sanitized:
        sanitized["expected_behavior"] = sanitize_text(sanitized["expected_behavior"])
    if "actual_behavior" in sanitized:
        sanitized["actual_behavior"] = sanitize_text(sanitized["actual_behavior"])
    return sanitized
