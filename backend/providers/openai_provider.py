import os
import asyncio
import logging
from typing import Optional
from fastapi import HTTPException, status
from openai import AsyncOpenAI, AuthenticationError, RateLimitError, APITimeoutError, APIConnectionError, APIStatusError
from backend.providers.base import LLMProvider

logger = logging.getLogger(__name__)

DEFAULT_OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
DEFAULT_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "30"))


class OpenAIProvider(LLMProvider):
    """
    Production OpenAI LLM Provider supporting chat completions with
    strict timeout protection and safe error handling.
    """
    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.timeout = timeout
        self._client: Optional[AsyncOpenAI] = None

    def _get_client(self) -> AsyncOpenAI:
        if not self.api_key:
            logger.error("OpenAI API key is missing in environment (OPENAI_API_KEY)")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OpenAI provider is not properly configured on the gateway"
            )
        if self._client is None:
            self._client = AsyncOpenAI(
                api_key=self.api_key,
                timeout=self.timeout
            )
        return self._client

    async def generate(self, prompt: str, model: str = DEFAULT_OPENAI_MODEL) -> str:
        client = self._get_client()
        target_model = model if model and model != "mock-model" else DEFAULT_OPENAI_MODEL

        try:
            response = await asyncio.wait_for(
                client.chat.completions.create(
                    model=target_model,
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                ),
                timeout=self.timeout
            )

            choices = getattr(response, "choices", None)
            if not choices or not isinstance(choices, (list, tuple)) or len(choices) == 0:
                return ""

            first_choice = choices[0]
            message = getattr(first_choice, "message", None)
            if message is not None:
                content = getattr(message, "content", None)
                if content:
                    return str(content)
            elif isinstance(first_choice, dict):
                msg = first_choice.get("message")
                if isinstance(msg, dict):
                    return str(msg.get("content") or "")
                if msg is not None:
                    return str(getattr(msg, "content", "") or "")

            return ""

        except AuthenticationError as exc:
            logger.error("Upstream OpenAI authentication failed: %s", exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Upstream LLM authentication failed"
            ) from exc

        except RateLimitError as exc:
            logger.error("Upstream OpenAI rate limit reached: %s", exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Upstream LLM provider rate limit exceeded"
            ) from exc

        except (APITimeoutError, asyncio.TimeoutError) as exc:
            logger.error("Upstream OpenAI request timed out after %.1fs", self.timeout)
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Upstream LLM request timed out"
            ) from exc

        except APIConnectionError as exc:
            logger.error("Failed to connect to upstream OpenAI service: %s", exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to connect to upstream LLM service"
            ) from exc

        except APIStatusError as exc:
            logger.error("Upstream OpenAI API status error code %s: %s", getattr(exc, "status_code", "unknown"), exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Upstream LLM provider returned an unexpected error"
            ) from exc

        except HTTPException:
            raise

        except Exception as exc:
            logger.error("Unexpected error during OpenAI generation: %s", exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to generate response from upstream LLM provider"
            ) from exc
