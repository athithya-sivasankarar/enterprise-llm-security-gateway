import re
from typing import Any, Dict, List, Optional, Union

# Regex patterns for redacting sensitive values while preserving legitimate security nomenclature
SENSITIVE_PATTERNS = [
    # API Keys
    (r"(?i)\b(?:sk-[a-zA-Z0-9_-]{20,})\b", "[REDACTED_API_KEY]"),
    # AWS Access Keys
    (r"\b(?:AKIA[0-9A-Z]{16})\b", "[REDACTED_AWS_KEY]"),
    # JWT Tokens (3 base64 strings separated by dots)
    (r"\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b", "[REDACTED_JWT]"),
    # Bearer Tokens
    (r"(?i)\b(?:Bearer\s+[a-zA-Z0-9_\-\.]{20,})\b", "Bearer [REDACTED_TOKEN]"),
    # Database Connection Strings (postgresql, mysql, mongodb, redis)
    (r"(?i)\b(?:postgresql|postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-]+:[^@\s]+@[^\s]+\b", "[REDACTED_DB_URL]"),
    # Generic passwords in key-value format (avoid matching security terms like "password policy")
    (r"(?i)\b(?:password|passwd|pwd|client_secret)[\s:=]+['\"]?([^'\"\s]{4,})['\"]?", r"password: [REDACTED_SECRET]"),
    # Social Security Numbers (SSN)
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    # Credit Card Numbers (16 digits separated by dashes or spaces)
    (r"\b(?:\d{4}[- ]){3}\d{4}\b|\b\d{16}\b", "[REDACTED_CARD]"),
    # Emails
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]"),
    # Phone Numbers (e.g. +1-555-123-4567, 555-123-4567, (555) 123-4567)
    (r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b", "[REDACTED_PHONE]"),
    # Raw Prompt / Response payloads markers
    (r"(?i)\b(?:raw_prompt|prompt_payload|raw_response|model_response_raw)[\s:=]+['\"]?([^'\"\n]{8,})['\"]?", r"\1: [REDACTED_PAYLOAD]")
]

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
    "cache_value",
    "private_key"
}


def sanitize_governance_text(text: Optional[str]) -> str:
    """
    Sanitize text by redacting API keys, passwords, tokens, PII, and DB credentials.
    Preserves legitimate security terminology (e.g., CVE-2026-1234, CWE-77, DLP, RBAC, Prompt Injection).
    """
    if not text:
        return ""
    sanitized = str(text)
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = re.sub(pattern, replacement, sanitized)
    return sanitized


def sanitize_governance_metadata(data: Union[Dict[str, Any], List[Any], str, Any]) -> Any:
    """
    Recursively sanitize governance metadata dictionary or list to strip forbidden keys and scrub strings.
    """
    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            if str(k).lower() in FORBIDDEN_METADATA_KEYS:
                continue
            cleaned[k] = sanitize_governance_metadata(v)
        return cleaned
    elif isinstance(data, list):
        return [sanitize_governance_metadata(item) for item in data]
    elif isinstance(data, str):
        return sanitize_governance_text(data)
    else:
        return data
