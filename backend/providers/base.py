from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """
    Abstract base class for all LLM providers.
    Ensures a consistent interface across Mock, OpenAI, and future providers.
    """
    @abstractmethod
    async def generate(self, prompt: str, model: str) -> str:
        """
        Generate completion for a sanitized prompt with the given model.
        
        :param prompt: The sanitized prompt (DLP applied).
        :param model: The target model name.
        :return: Generated text response.
        """
        pass
