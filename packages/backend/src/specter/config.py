"""Pydantic settings for SPECTER."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str = "SPECTER"
    environment: str = "development"
    secret_key: str = "change-me-in-production"
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql://specter:specter@localhost:5432/specter"
    db_pool_size: int = 20
    db_max_overflow: int = 10

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # LLM
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    default_llm_model: str = "claude-3-5-sonnet-20241022"

    # AWS
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_region: str = "us-east-1"

    # Splunk
    splunk_host: str | None = None
    splunk_port: int = 8089
    splunk_username: str | None = None
    splunk_password: str | None = None
    splunk_token: str | None = Field(
        default=None,
        description=(
            "Bearer token or full Authorization header value (e.g. Splunk session key prefix)."
        ),
    )
    splunk_verify_ssl: bool = True
    splunk_mcp_base_url: str | None = Field(
        default=None,
        description="Optional Splunk MCP Server base URL for NL→SPL when deployed.",
    )

    # Sola
    sola_api_key: str | None = None
    sola_base_url: str = "https://api.sola.security"

    # SIFT
    sift_host: str | None = None
    sift_port: int = 22
    sift_username: str | None = None

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
