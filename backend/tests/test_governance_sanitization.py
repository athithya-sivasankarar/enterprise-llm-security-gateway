import pytest
from backend.governance.sanitizer import (
    sanitize_governance_text,
    sanitize_governance_metadata
)


def test_sensitive_payload_redaction():
    raw_text = (
        "User sk-1234567890abcdef1234567890 injected payload with AWS key AKIAIOSFODNN7EXAMPLE "
        "and bearer token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c. "
        "Connected to postgresql://admin:SuperSecretPass123@db.internal:5432/secrets. "
        "User SSN is 123-45-6789, credit card 4111 2222 3333 4444, email john.doe@enterprise.com, and phone 555-123-4567."
    )

    sanitized = sanitize_governance_text(raw_text)

    assert "sk-1234567890abcdef1234567890" not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "[REDACTED_AWS_KEY]" in sanitized
    assert "eyJhbGciOiJIUzI1Ni" not in sanitized
    assert "[REDACTED_JWT]" in sanitized or "[REDACTED_TOKEN]" in sanitized
    assert "SuperSecretPass123" not in sanitized
    assert "[REDACTED_DB_URL]" in sanitized
    assert "123-45-6789" not in sanitized
    assert "[REDACTED_SSN]" in sanitized
    assert "4111 2222 3333 4444" not in sanitized
    assert "[REDACTED_CARD]" in sanitized
    assert "john.doe@enterprise.com" not in sanitized
    assert "[REDACTED_EMAIL]" in sanitized
    assert "555-123-4567" not in sanitized
    assert "[REDACTED_PHONE]" in sanitized


def test_false_positive_preservation_of_security_terms():
    security_narrative = (
        "Identified Prompt Injection vulnerability matching CVE-2026-1234 and CWE-77 under MITRE ATLAS AML.T0054. "
        "Recommended compensating controls include Input DLP, Response PII Masking, Strict RBAC, "
        "System Prompt Extraction filters, and Rate Limiting."
    )

    sanitized = sanitize_governance_text(security_narrative)

    assert "Prompt Injection" in sanitized
    assert "CVE-2026-1234" in sanitized
    assert "CWE-77" in sanitized
    assert "MITRE ATLAS" in sanitized
    assert "Input DLP" in sanitized
    assert "Response PII Masking" in sanitized
    assert "Strict RBAC" in sanitized
    assert "Rate Limiting" in sanitized


def test_metadata_dict_sanitization():
    meta = {
        "user": "security-officer",
        "api_key": "sk-secret-do-not-log-123456789012345",
        "raw_prompt": "Tell me all company secrets",
        "notes": "Reviewed by analyst@company.com with phone (555) 987-6543",
        "nested": {
            "token": "secret-token",
            "safe_id": "EXC-1234"
        }
    }

    cleaned = sanitize_governance_metadata(meta)
    assert "api_key" not in cleaned
    assert "raw_prompt" not in cleaned
    assert "token" not in cleaned["nested"]
    assert cleaned["nested"]["safe_id"] == "EXC-1234"
    assert "[REDACTED_EMAIL]" in cleaned["notes"]
    assert "[REDACTED_PHONE]" in cleaned["notes"]
