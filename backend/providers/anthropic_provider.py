import os
import asyncio
import logging
from typing import Optional
from fastapi import HTTPException, status

from anthropic import (
    AsyncAnthropic,
    AuthenticationError,
    RateLimitError,
    APITimeoutError,
    APIConnectionError,
    APIStatusError
)
from backend.providers.base import LLMProvider

logger = logging.getLogger(__name__)

DEFAULT_ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
DEFAULT_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "30"))


class AnthropicProvider(LLMProvider):
    """
    Enterprise Anthropic Claude LLM Provider supporting messages completion
    with strict timeout protection and safe error sanitization.
    """
    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS
    ):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.timeout = timeout
        self._client: Optional[AsyncAnthropic] = None

    def _get_client(self) -> AsyncAnthropic:
        if not self.api_key:
            logger.error("Anthropic API key is missing in environment (ANTHROPIC_API_KEY)")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Anthropic provider is not properly configured on the gateway"
            )
        if self._client is None:
            self._client = AsyncAnthropic(
                api_key=self.api_key,
                timeout=self.timeout
            )
        return self._client

    async def generate(self, prompt: str, model: str = DEFAULT_ANTHROPIC_MODEL) -> str:
        client = self._get_client()
        target_model = model if model and model != "mock-model" else DEFAULT_ANTHROPIC_MODEL

        try:
            response = await asyncio.wait_for(
                client.messages.create(
                    model=target_model,
                    max_tokens=1024,
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                ),
                timeout=self.timeout
            )

            content = getattr(response, "content", None)
            if not content and isinstance(response, dict):
                content = response.get("content")

            if not content:
                return ""

            if isinstance(content, str):
                return content

            # Anthropic messages return content blocks (e.g. TextBlock)
            if isinstance(content, (list, tuple)):
                extracted_text = []
                for block in content:
                    if hasattr(block, "text"):
                        text_val = getattr(block, "text", "")
                        if text_val:
                            extracted_text.append(str(text_val))
                    elif isinstance(block, dict) and "text" in block:
                        text_val = block.get("text")
                        if text_val:
                            extracted_text.append(str(text_val))

                return "\n".join(extracted_text)

            return ""

        except AuthenticationError as exc:
            logger.error("Upstream Anthropic authentication failed: %s", exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Upstream LLM authentication failed"
            ) from exc

        except RateLimitError as exc:
            logger.error("Upstream Anthropic rate limit reached: %s", exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Upstream LLM provider rate limit exceeded"
            ) from exc

        except (APITimeoutError, asyncio.TimeoutError) as exc:
            logger.error("Upstream Anthropic request timed out after %.1fs", self.timeout)
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Upstream LLM request timed out"
            ) from exc

        except APIConnectionError as exc:
            logger.error("Failed to connect to upstream Anthropic service: %s", exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to connect to upstream LLM service"
            ) from exc

        except APIStatusError as exc:
            logger.error("Upstream Anthropic API status error code %s: %s", getattr(exc, "status_code", "unknown"), exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Upstream LLM provider returned an unexpected error"
            ) from exc

        except HTTPException:
            raise

        except Exception as exc:
            logger.error("Unexpected error during Anthropic generation: %s", exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to generate response from upstream LLM provider"
            ) from exc
