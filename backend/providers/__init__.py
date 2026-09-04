import os
import logging
from typing import Optional, Dict, Any
from fastapi import HTTPException, status

from backend.providers.base import LLMProvider
from backend.providers.mock import MockLLMProvider
from backend.providers.openai_provider import OpenAIProvider
from backend.providers.anthropic_provider import AnthropicProvider

logger = logging.getLogger(__name__)

# Cached provider instances
_mock_provider = MockLLMProvider()
_openai_provider: Optional[OpenAIProvider] = None
_anthropic_provider: Optional[AnthropicProvider] = None


def resolve_provider_name(provider_name: Optional[str] = None, model: Optional[str] = None) -> str:
    """
    Resolve target provider name from explicit parameter, model prefix, or LLM_PROVIDER env variable.
    """
    if provider_name:
        return provider_name.lower().strip()

    if model:
        clean_model = model.lower().strip()
        if clean_model == "mock-model" or clean_model.startswith("mock"):
            return "mock"
        elif clean_model.startswith("claude") or "anthropic" in clean_model:
            return "anthropic"
        elif clean_model.startswith("gpt-") or clean_model.startswith("o1") or clean_model.startswith("o3") or "openai" in clean_model:
            return "openai"

    return os.getenv("LLM_PROVIDER", "mock").lower().strip()


def get_provider(
    provider_name: Optional[str] = None,
    model: Optional[str] = None
) -> LLMProvider:
    """
    Resolve and return the appropriate LLMProvider instance.
    Supported providers: 'mock', 'openai', 'anthropic'.
    """
    global _openai_provider, _anthropic_provider

    target = resolve_provider_name(provider_name, model)

    if target == "mock":
        return _mock_provider
    elif target == "openai":
        if _openai_provider is None:
            _openai_provider = OpenAIProvider()
        return _openai_provider
    elif target == "anthropic":
        if _anthropic_provider is None:
            _anthropic_provider = AnthropicProvider()
        return _anthropic_provider
    else:
        logger.error("Unknown LLM provider requested: %s", target)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported LLM provider: '{target}'. Supported providers: 'mock', 'openai', 'anthropic'."
        )


def get_providers_health() -> Dict[str, Any]:
    """
    Report configuration availability for all providers without exposing secrets.
    """
    return {
        "providers": {
            "mock": {
                "configured": True
            },
            "openai": {
                "configured": bool(os.getenv("OPENAI_API_KEY"))
            },
            "anthropic": {
                "configured": bool(os.getenv("ANTHROPIC_API_KEY"))
            }
        }
    }


__all__ = [
    "LLMProvider",
    "MockLLMProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "get_provider",
    "resolve_provider_name",
    "get_providers_health"
]
