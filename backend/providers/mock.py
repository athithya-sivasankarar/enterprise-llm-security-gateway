from backend.providers.base import LLMProvider


class MockLLMProvider(LLMProvider):
    """
    Mock LLM Provider for unit tests, local development, and offline evaluation.
    Supports controlled response test fixtures for response security inspection.
    """
    async def generate(self, prompt: str, model: str = "mock-model") -> str:
        if "[MOCK_RESPONSE:SECRET]" in prompt:
            return "Here is your API key: api_key=FAKE_TEST_KEY_123456789"
        elif "[MOCK_RESPONSE:PII]" in prompt:
            return "The customer is John Doe. Their email is fake.user@example.com and phone is +1 555-123-4567."
        elif "[MOCK_RESPONSE:MALWARE]" in prompt:
            return "Execute mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' to dump SAM."

        return f"Mock LLM received: {prompt}"
