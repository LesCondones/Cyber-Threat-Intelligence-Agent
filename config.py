from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel, Field
from langchain_ollama import ChatOllama
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel
from enum import Enum
from pathlib import Path
from typing import Type


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    CLAUDE = "claude"


class Settings(BaseSettings):
    """Application settings with validation."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    tavily_api_key: str = Field(..., alias="TAVILY_SEARCH_API_KEY", description="Tavily API key")
    anthropic_api_key: str = Field(default="", description="Anthropic API key")
    llm_provider: LLMProvider = Field(default=LLMProvider.OLLAMA)
    ollama_model: str = Field(default="qwen3:8b")
    ollama_base_url: str = Field(default="http://localhost:11434")
    claude_model: str = Field(default="claude-sonnet-4-20250514")

    # Enrichment API keys (all optional — enrichment skips missing keys)
    virustotal_api_key: str = Field(default="", description="VirusTotal API key")
    shodan_api_key: str = Field(default="", description="Shodan API key")
    abuseipdb_api_key: str = Field(default="", description="AbuseIPDB API key")


# Find .env file in project root
project_root = Path(__file__).parent
env_path = project_root / ".env"

settings = Settings(_env_file=str(env_path) if env_path.exists() else None)


def get_llm() -> BaseChatModel:
    """
    Get a ChatModel based on configuration.

    Returns ChatAnthropic or ChatOllama — both support:
    - .invoke() for text generation
    - .with_structured_output() for Pydantic model output
    - LCEL chain composition (prompt | llm | parser)
    """
    if settings.llm_provider == LLMProvider.CLAUDE:
        return ChatAnthropic(
            model=settings.claude_model,
            api_key=settings.anthropic_api_key,
            temperature=0.7,
        )
    return ChatOllama(
        model=settings.ollama_model,
        base_url=settings.ollama_base_url,
        temperature=0.7,
    )


def get_structured_llm(schema: Type[BaseModel], llm: BaseChatModel = None) -> BaseChatModel:
    """
    Get an LLM bound to produce structured output matching a Pydantic schema.

    Uses native structured output (tool calling / JSON mode) for reliability.
    The returned object can be invoked directly or composed into LCEL chains.

    Usage:
        class MyOutput(BaseModel):
            items: list[str]

        structured = get_structured_llm(MyOutput)
        result = structured.invoke("list 3 items")  # returns MyOutput instance
    """
    if llm is None:
        llm = get_llm()
    return llm.with_structured_output(schema)
