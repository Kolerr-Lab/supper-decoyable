"""
DECOYABLE Configuration Module

Centralized configuration management using Pydantic settings.
Single source of truth for all application configuration.
Supports environment variables and .env files with type safety.
"""

import os
from typing import List, Optional, Dict, Any
from pathlib import Path

# Load environment variables from .env file at module level
try:
    from dotenv import load_dotenv
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    ENV_FILE = PROJECT_ROOT / ".env"
    load_dotenv(ENV_FILE)
except ImportError:
    # dotenv not available, rely on system environment
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    ENV_FILE = PROJECT_ROOT / ".env"

try:
    from pydantic import Field, validator, ValidationError
    from pydantic_settings import BaseSettings
    PYDANTIC_V2 = True
except ImportError:
    # Fallback for older versions
    try:
        from pydantic_settings import BaseSettings
        from pydantic import Field, validator, ValidationError
        PYDANTIC_V2 = True
    except ImportError:
        # Fallback for very old versions
        from pydantic import BaseModel as BaseSettings, Field
        validator = None
        ValidationError = Exception
        PYDANTIC_V2 = False


class DatabaseSettings(BaseSettings):
    """Database configuration settings."""
    url: str = Field(default="sqlite:///./decoyable.db", env="DATABASE_URL")
    pool_size: int = Field(default=10, env="DATABASE_POOL_SIZE")
    max_overflow: int = Field(default=20, env="DATABASE_MAX_OVERFLOW")
    pool_timeout: int = Field(default=30, env="DATABASE_POOL_TIMEOUT")
    echo: bool = Field(default=False, env="DATABASE_ECHO")


class RedisSettings(BaseSettings):
    """Redis configuration settings."""
    url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    db: int = Field(default=0, env="REDIS_DB")
    socket_timeout: Optional[float] = Field(default=None, env="REDIS_SOCKET_TIMEOUT")
    socket_connect_timeout: Optional[float] = Field(default=None, env="REDIS_SOCKET_CONNECT_TIMEOUT")


class KafkaSettings(BaseSettings):
    """Kafka streaming configuration settings."""
    enabled: bool = Field(default=False, env="KAFKA_ENABLED")
    bootstrap_servers: str = Field(default="localhost:9092", env="KAFKA_BOOTSTRAP_SERVERS")
    attack_topic: str = Field(default="decoyable.attacks", env="KAFKA_ATTACK_TOPIC")
    consumer_group: str = Field(default="decoyable-consumers", env="KAFKA_CONSUMER_GROUP")
    auto_offset_reset: str = Field(default="latest", env="KAFKA_AUTO_OFFSET_RESET")
    enable_auto_commit: bool = Field(default=True, env="KAFKA_ENABLE_AUTO_COMMIT")

    @property
    def bootstrap_servers_list(self) -> List[str]:
        """Get bootstrap servers as a list."""
        return [s.strip() for s in self.bootstrap_servers.split(",")]


class APISettings(BaseSettings):
    """API server configuration settings."""
    host: str = Field(default="0.0.0.0", env="API_HOST")
    port: int = Field(default=8000, env="APP_PORT")
    debug: bool = Field(default=False, env="API_DEBUG")
    workers: int = Field(default=1, env="API_WORKERS")
    reload: bool = Field(default=False, env="API_RELOAD")


class SecuritySettings(BaseSettings):
    """Security configuration settings."""
    secret_key: str = Field(default="dev-secret-key-change-in-production", env="SECRET_KEY")
    jwt_secret_key: str = Field(default="jwt-secret-key", env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    jwt_expiration_hours: int = Field(default=24, env="JWT_EXPIRATION_HOURS")


class LLMSettings(BaseSettings):
    """LLM provider configuration settings."""
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(default=None, env="ANTHROPIC_API_KEY")
    google_api_key: Optional[str] = Field(default=None, env="GOOGLE_API_KEY")
    default_provider: str = Field(default="openai", env="DEFAULT_LLM_PROVIDER")
    request_timeout: int = Field(default=30, env="LLM_REQUEST_TIMEOUT")
    max_retries: int = Field(default=3, env="LLM_MAX_RETRIES")


class HoneypotSettings(BaseSettings):
    """Honeypot configuration settings."""
    enabled: bool = Field(default=True, env="HONEYPOT_ENABLED")
    ports: str = Field(default="9001,2222", env="DECOY_PORTS")
    security_team_endpoint: str = Field(default="", env="SECURITY_TEAM_ENDPOINT")
    log_attacks: bool = Field(default=True, env="HONEYPOT_LOG_ATTACKS")
    block_ips: bool = Field(default=True, env="HONEYPOT_BLOCK_IPS")
    block_duration_minutes: int = Field(default=60, env="HONEYPOT_BLOCK_DURATION_MINUTES")

    @property
    def ports_list(self) -> List[int]:
        """Get honeypot ports as a list of integers."""
        return [int(port.strip()) for port in self.ports.split(",") if port.strip()]


class CelerySettings(BaseSettings):
    """Celery task queue configuration settings."""
    broker_url: str = Field(default="redis://localhost:6379/0", env="CELERY_BROKER_URL")
    result_backend: str = Field(default="redis://localhost:6379/0", env="CELERY_RESULT_BACKEND")
    task_serializer: str = Field(default="json", env="CELERY_TASK_SERIALIZER")
    result_serializer: str = Field(default="json", env="CELERY_RESULT_SERIALIZER")
    accept_content: List[str] = Field(default=["json"], env="CELERY_ACCEPT_CONTENT")
    timezone: str = Field(default="UTC", env="CELERY_TIMEZONE")
    enable_utc: bool = Field(default=True, env="CELERY_ENABLE_UTC")


class LoggingSettings(BaseSettings):
    """Structured logging configuration settings."""
    level: str = Field(default="INFO", env="LOG_LEVEL")
    console_enabled: bool = Field(default=True, env="LOG_CONSOLE_ENABLED")
    console_level: str = Field(default="INFO", env="LOG_CONSOLE_LEVEL")
    file_enabled: bool = Field(default=True, env="LOG_FILE_ENABLED")
    file_path: Optional[str] = Field(default="logs/decoyable.log", env="LOG_FILE_PATH")
    file_level: str = Field(default="INFO", env="LOG_FILE_LEVEL")
    file_max_size_mb: int = Field(default=10, env="LOG_FILE_MAX_SIZE_MB")
    file_backup_count: int = Field(default=5, env="LOG_FILE_BACKUP_COUNT")
    performance_enabled: bool = Field(default=True, env="LOG_PERFORMANCE_ENABLED")
    performance_file_path: Optional[str] = Field(default="logs/performance.log", env="LOG_PERFORMANCE_FILE_PATH")
    performance_max_size_mb: int = Field(default=50, env="LOG_PERFORMANCE_MAX_SIZE_MB")
    performance_backup_count: int = Field(default=3, env="LOG_PERFORMANCE_BACKUP_COUNT")
    json_format: bool = Field(default=True, env="LOG_JSON_FORMAT")
    include_correlation_id: bool = Field(default=True, env="LOG_INCLUDE_CORRELATION_ID")


class VSExtensionSettings(BaseSettings):
    """VS Code extension configuration settings."""
    enabled: bool = Field(default=True, env="VSCODE_EXTENSION_ENABLED")
    server_host: str = Field(default="localhost", env="VSCODE_SERVER_HOST")
    server_port: int = Field(default=3001, env="VSCODE_SERVER_PORT")


class KnowledgeSettings(BaseSettings):
    """Knowledge database configuration settings."""
    db_path: str = Field(default="decoyable_knowledge.db", env="KNOWLEDGE_DB_PATH")
    max_connections: int = Field(default=5, env="KNOWLEDGE_MAX_CONNECTIONS")
    cache_size: int = Field(default=1000, env="KNOWLEDGE_CACHE_SIZE")


class ScannersSettings(BaseSettings):
    """Security scanners configuration settings."""
    secrets_enabled: bool = Field(default=True, env="SCANNERS_SECRETS_ENABLED")
    deps_enabled: bool = Field(default=True, env="SCANNERS_DEPS_ENABLED")
    sast_enabled: bool = Field(default=True, env="SCANNERS_SAST_ENABLED")
    timeout_seconds: int = Field(default=300, env="SCANNERS_TIMEOUT_SECONDS")
    max_file_size_mb: int = Field(default=10, env="SCANNERS_MAX_FILE_SIZE_MB")
    exclude_patterns: List[str] = Field(default=[".git", "__pycache__", "node_modules", ".venv", "venv"], env="SCANNERS_EXCLUDE_PATTERNS")
    min_confidence: float = Field(default=0.8, env="SCANNERS_MIN_CONFIDENCE")
    check_missing_imports: bool = Field(default=True, env="SCANNERS_CHECK_MISSING_IMPORTS")
    check_unused_dependencies: bool = Field(default=False, env="SCANNERS_CHECK_UNUSED_DEPS")
    severity_threshold: str = Field(default="LOW", env="SCANNERS_SEVERITY_THRESHOLD")


class Settings:
    """Main application settings - single source of truth."""

    def __init__(self):
        # Application metadata
        self.app_name: str = "decoyable"
        self.version: str = "0.1.0"
        self.environment: str = os.getenv("APP_ENV", "development")

        # Component configurations - manually construct from env vars
        self.database = DatabaseSettings(
            url=os.getenv("DATABASE_URL", "sqlite:///./decoyable.db"),
            pool_size=int(os.getenv("DATABASE_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DATABASE_MAX_OVERFLOW", "20")),
            pool_timeout=int(os.getenv("DATABASE_POOL_TIMEOUT", "30")),
            echo=os.getenv("DATABASE_ECHO", "false").lower() == "true"
        )

        self.redis = RedisSettings(
            url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            password=os.getenv("REDIS_PASSWORD"),
            db=int(os.getenv("REDIS_DB", "0"))
        )

        self.kafka = KafkaSettings(
            enabled=os.getenv("KAFKA_ENABLED", "false").lower() == "true",
            bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            attack_topic=os.getenv("KAFKA_ATTACK_TOPIC", "decoyable.attacks"),
            consumer_group=os.getenv("KAFKA_CONSUMER_GROUP", "decoyable-consumers"),
            auto_offset_reset=os.getenv("KAFKA_AUTO_OFFSET_RESET", "latest"),
            enable_auto_commit=os.getenv("KAFKA_ENABLE_AUTO_COMMIT", "true").lower() == "true"
        )

        self.api = APISettings(
            host=os.getenv("API_HOST", "0.0.0.0"),
            port=int(os.getenv("APP_PORT", "8000")),
            debug=os.getenv("API_DEBUG", "false").lower() == "true",
            workers=int(os.getenv("API_WORKERS", "1")),
            reload=os.getenv("API_RELOAD", "false").lower() == "true"
        )

        self.security = SecuritySettings(
            secret_key=os.getenv("SECRET_KEY", "dev-secret-key-change-in-production"),
            jwt_secret_key=os.getenv("JWT_SECRET_KEY", "jwt-secret-key"),
            jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
            jwt_expiration_hours=int(os.getenv("JWT_EXPIRATION_HOURS", "24"))
        )

        self.llm = LLMSettings(
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            google_api_key=os.getenv("GOOGLE_API_KEY"),
            default_provider=os.getenv("DEFAULT_LLM_PROVIDER", "openai"),
            request_timeout=int(os.getenv("LLM_REQUEST_TIMEOUT", "30")),
            max_retries=int(os.getenv("LLM_MAX_RETRIES", "3"))
        )

        self.honeypot = HoneypotSettings(
            enabled=os.getenv("HONEYPOT_ENABLED", "true").lower() == "true",
            ports=os.getenv("DECOY_PORTS", "9001,2222"),
            security_team_endpoint=os.getenv("SECURITY_TEAM_ENDPOINT", ""),
            log_attacks=os.getenv("HONEYPOT_LOG_ATTACKS", "true").lower() == "true",
            block_ips=os.getenv("HONEYPOT_BLOCK_IPS", "true").lower() == "true",
            block_duration_minutes=int(os.getenv("HONEYPOT_BLOCK_DURATION_MINUTES", "60"))
        )

        self.celery = CelerySettings(
            broker_url=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
            result_backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
            task_serializer=os.getenv("CELERY_TASK_SERIALIZER", "json"),
            result_serializer=os.getenv("CELERY_RESULT_SERIALIZER", "json"),
            accept_content=["json"],  # Simplified for now
            timezone=os.getenv("CELERY_TIMEZONE", "UTC"),
            enable_utc=os.getenv("CELERY_ENABLE_UTC", "true").lower() == "true"
        )

        self.logging = LoggingSettings(
            level=os.getenv("LOG_LEVEL", "INFO"),
            console_enabled=os.getenv("LOG_CONSOLE_ENABLED", "true").lower() == "true",
            console_level=os.getenv("LOG_CONSOLE_LEVEL", "INFO"),
            file_enabled=os.getenv("LOG_FILE_ENABLED", "true").lower() == "true",
            file_path=os.getenv("LOG_FILE_PATH", "logs/decoyable.log"),
            file_level=os.getenv("LOG_FILE_LEVEL", "INFO"),
            file_max_size_mb=int(os.getenv("LOG_FILE_MAX_SIZE_MB", "10")),
            file_backup_count=int(os.getenv("LOG_FILE_BACKUP_COUNT", "5")),
            performance_enabled=os.getenv("LOG_PERFORMANCE_ENABLED", "true").lower() == "true",
            performance_file_path=os.getenv("LOG_PERFORMANCE_FILE_PATH", "logs/performance.log"),
            performance_max_size_mb=int(os.getenv("LOG_PERFORMANCE_MAX_SIZE_MB", "50")),
            performance_backup_count=int(os.getenv("LOG_PERFORMANCE_BACKUP_COUNT", "3")),
            json_format=os.getenv("LOG_JSON_FORMAT", "true").lower() == "true",
            include_correlation_id=os.getenv("LOG_INCLUDE_CORRELATION_ID", "true").lower() == "true"
        )

        self.vscode_extension = VSExtensionSettings(
            enabled=os.getenv("VSCODE_EXTENSION_ENABLED", "true").lower() == "true",
            server_host=os.getenv("VSCODE_SERVER_HOST", "localhost"),
            server_port=int(os.getenv("VSCODE_SERVER_PORT", "3001"))
        )

        self.knowledge = KnowledgeSettings(
            db_path=os.getenv("KNOWLEDGE_DB_PATH", "decoyable_knowledge.db"),
            max_connections=int(os.getenv("KNOWLEDGE_MAX_CONNECTIONS", "5")),
            cache_size=int(os.getenv("KNOWLEDGE_CACHE_SIZE", "1000"))
        )

        self.scanners = ScannersSettings(
            secrets_enabled=os.getenv("SCANNERS_SECRETS_ENABLED", "true").lower() == "true",
            deps_enabled=os.getenv("SCANNERS_DEPS_ENABLED", "true").lower() == "true",
            sast_enabled=os.getenv("SCANNERS_SAST_ENABLED", "true").lower() == "true",
            timeout_seconds=int(os.getenv("SCANNERS_TIMEOUT_SECONDS", "300")),
            max_file_size_mb=int(os.getenv("SCANNERS_MAX_FILE_SIZE_MB", "10")),
            exclude_patterns=os.getenv("SCANNERS_EXCLUDE_PATTERNS", ".git,__pycache__,node_modules,.venv,venv").split(","),
            min_confidence=float(os.getenv("SCANNERS_MIN_CONFIDENCE", "0.8")),
            check_missing_imports=os.getenv("SCANNERS_CHECK_MISSING_IMPORTS", "true").lower() == "true",
            check_unused_dependencies=os.getenv("SCANNERS_CHECK_UNUSED_DEPS", "false").lower() == "true",
            severity_threshold=os.getenv("SCANNERS_SEVERITY_THRESHOLD", "LOW")
        )

    # Legacy compatibility properties (deprecated - use nested settings)
    @property
    def database_url(self) -> str:
        """Legacy compatibility."""
        return self.database.url

    @property
    def redis_url(self) -> str:
        """Legacy compatibility."""
        return self.redis.url

    @property
    def kafka_enabled(self) -> bool:
        """Legacy compatibility."""
        return self.kafka.enabled

    @property
    def kafka_bootstrap_servers(self) -> str:
        """Legacy compatibility."""
        return self.kafka.bootstrap_servers

    @property
    def kafka_attack_topic(self) -> str:
        """Legacy compatibility."""
        return self.kafka.attack_topic

    @property
    def kafka_consumer_group(self) -> str:
        """Legacy compatibility."""
        return self.kafka.consumer_group

    @property
    def api_host(self) -> str:
        """Legacy compatibility."""
        return self.api.host

    @property
    def api_port(self) -> int:
        """Legacy compatibility."""
        return self.api.port

    @property
    def secret_key(self) -> str:
        """Legacy compatibility."""
        return self.security.secret_key

    @property
    def app_env(self) -> str:
        """Legacy compatibility."""
        return self.environment

    @property
    def log_level(self) -> str:
        """Legacy compatibility."""
        return self.logging.level

    @property
    def vscode_extension_enabled(self) -> bool:
        """Legacy compatibility."""
        return self.vscode_extension.enabled


# Global settings instance - single source of truth
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings


def reload_settings() -> Settings:
    """Reload settings from environment (useful for testing)."""
    global settings
    settings = Settings()
    return settings