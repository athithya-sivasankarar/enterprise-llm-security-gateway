import pytest
from backend.reporting.sanitizer import sanitize_text, sanitize_metadata


def test_exposure_sanitization():
    raw_desc = "API key sk-12345678901234567890 exposed in request prompt with SSN 123-45-6789"
    cleaned = sanitize_text(raw_desc)
    assert "sk-12345" not in cleaned
    assert "123-45-6789" not in cleaned
    assert "[REDACTED_API_KEY]" in cleaned
    assert "[REDACTED_SSN]" in cleaned

    meta = {
        "raw_prompt": "Ignore previous instructions",
        "api_key": "sk-secretkey12345",
        "risk_score": 85
    }
    cleaned_meta = sanitize_metadata(meta)
    assert cleaned_meta["raw_prompt"] == "[REDACTED_SENSITIVE_PAYLOAD]"
    assert cleaned_meta["risk_score"] == 85
