"""Shared LLM helpers — centralise ChatOllama creation and model-specific directives."""
import os

from langchain_ollama import ChatOllama

# Models that support the /no_think directive (Qwen3 "thinking" family)
_NO_THINK_MODELS = ("qwen", "gpt-oss")


def get_ollama(*, temperature: int = 0, num_predict: int = 4096, num_ctx: int = 8192) -> ChatOllama:
    """Create a ChatOllama instance configured entirely from environment variables."""
    return ChatOllama(
        model=os.getenv("OLLAMA_MODEL", "gpt-oss:20b"),
        temperature=temperature,
        format="json",
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        num_predict=num_predict,
        num_ctx=num_ctx,
    )


def thinking_off(prompt: str) -> str:
    """Append /no_think to prompt for Qwen3-family models; no-op for all others."""
    model = os.getenv("OLLAMA_MODEL", "").lower()
    if any(x in model for x in _NO_THINK_MODELS):
        return prompt + "\n/no_think"
    return prompt
