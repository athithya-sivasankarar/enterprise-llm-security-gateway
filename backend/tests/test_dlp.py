import pytest
from backend.security.dlp import inspect_prompt, DLPResult


def test_dlp_normal_prompt():
    prompt = "Explain SQL injection in simple terms"
    result = inspect_prompt(prompt)

    assert isinstance(result, DLPResult)
    assert result.pii_detected is False
    assert result.action == "ALLOW"
    assert result.risk_score == 0
    assert result.sanitized_prompt == prompt
    assert len(result.detected_entities) == 0


def test_dlp_empty_prompt():
    result = inspect_prompt("")
    assert result.pii_detected is False
    assert result.action == "ALLOW"
    assert result.risk_score == 0


def test_dlp_email_detection():
    prompt = "Please send the report to fake.user@example.com immediately."
    result = inspect_prompt(prompt)

    assert result.pii_detected is True
    assert result.action == "SANITIZE"
    assert "EMAIL_ADDRESS" in result.detected_entities
    assert "<EMAIL_ADDRESS>" in result.sanitized_prompt
    assert "fake.user@example.com" not in result.sanitized_prompt
    assert result.risk_score > 0


def test_dlp_phone_detection():
    prompt = "You can reach customer service at +1 555-123-4567."
    result = inspect_prompt(prompt)

    assert result.pii_detected is True
    assert result.action == "SANITIZE"
    assert "PHONE_NUMBER" in result.detected_entities
    assert "<PHONE_NUMBER>" in result.sanitized_prompt
    assert "555-123-4567" not in result.sanitized_prompt


def test_dlp_credit_card_detection():
    # Luhn-valid fake test card
    prompt = "My payment card number is 4012888888881881 for the transaction."
    result = inspect_prompt(prompt)

    assert result.pii_detected is True
    assert result.action == "SANITIZE"
    assert "CREDIT_CARD" in result.detected_entities
    assert "<CREDIT_CARD>" in result.sanitized_prompt
    assert "4012888888881881" not in result.sanitized_prompt
    assert result.risk_score >= 40


def test_dlp_ssn_detection():
    prompt = "My social security number is 219-09-5432."
    result = inspect_prompt(prompt)

    assert result.pii_detected is True
    assert result.action == "SANITIZE"
    assert "US_SSN" in result.detected_entities
    assert "<US_SSN>" in result.sanitized_prompt
    assert "219-09-5432" not in result.sanitized_prompt
    assert result.risk_score >= 40


def test_dlp_ip_address_detection():
    prompt = "The internal database is hosted at 192.168.1.100 on port 5432."
    result = inspect_prompt(prompt)

    assert result.pii_detected is True
    assert result.action == "SANITIZE"
    assert "IP_ADDRESS" in result.detected_entities
    assert "<IP_ADDRESS>" in result.sanitized_prompt
    assert "192.168.1.100" not in result.sanitized_prompt


def test_dlp_api_key_detection():
    prompt = "Use this OpenAI API key sk-abcdef1234567890abcdef123456 to query the model."
    result = inspect_prompt(prompt)

    assert result.pii_detected is True
    assert result.action == "SANITIZE"
    assert "API_KEY" in result.detected_entities
    assert "<API_KEY>" in result.sanitized_prompt
    assert "sk-abcdef1234567890abcdef123456" not in result.sanitized_prompt


def test_dlp_multiple_entities_detection():
    prompt = "Contact John Doe at john.doe@example.com or phone +1 555-019-2834 regarding card 4012888888881881."
    result = inspect_prompt(prompt)

    assert result.pii_detected is True
    assert result.action == "SANITIZE"
    assert "EMAIL_ADDRESS" in result.detected_entities
    assert "PHONE_NUMBER" in result.detected_entities
    assert "CREDIT_CARD" in result.detected_entities
    # Raw values must be completely redacted
    assert "john.doe@example.com" not in result.sanitized_prompt
    assert "4012888888881881" not in result.sanitized_prompt
    assert result.risk_score >= 60
