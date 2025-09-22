"""
DECOYtry:
    from pydantic_settings import BaseSettings
    from pydantic import Field
    PYDANTIC_V2 = True
except ImportError:
    # Fallback for older versions
    from pydantic import BaseModel as BaseSettings, Field
    PYDANTIC_V2 = Falseguration Module

Centralized configuration management using Pydantic settings.
Supports environment variables and .env files.
"""

import os
from typing import List, Optional

try:
    from pydantic import BaseSettings, Field, validator
except ImportError:
    # Pydantic v2 moved BaseSettings to pydantic-settings
    try:
        from pydantic_settings import BaseSettings
        from pydantic import Field, validator
    except ImportError:
        # Fallback for older versions or missing pydantic-settings
        from pydantic import BaseModel as BaseSettings, Field
        validator = None  # No validator available


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # Database
    database_url: str = Field(default="sqlite:///./decoyable.db")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0")

    # Kafka (optional streaming)
    kafka_enabled: bool = Field(default=False)
    kafka_bootstrap_servers: str = Field(default="localhost:9092")
    kafka_attack_topic: str = Field(default="decoyable.attacks")
    kafka_consumer_group: str = Field(default="decoyable-consumers")

    @property
    def kafka_bootstrap_servers_list(self) -> List[str]:
        """Get bootstrap servers as a list."""
        return [s.strip() for s in self.kafka_bootstrap_servers.split(",")]

    # API
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)

    # Security
    secret_key: str = Field(default="dev-secret-key-change-in-production")

    # Application
    app_env: str = Field(default="development")
    log_level: str = Field(default="INFO")

    # VS Code Extension
    vscode_extension_enabled: bool = Field(default=True)

    model_config = {"env_file": ".env", "extra": "ignore"}


# Global settings instance
settings = Settings()