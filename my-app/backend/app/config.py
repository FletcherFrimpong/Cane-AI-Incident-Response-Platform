from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # App
    app_name: str = "Cane AI Incident Response Platform"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # Database
    database_url: str = "postgresql+asyncpg://cane:cane_secret@localhost:5432/cane_db"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # JWT
    jwt_secret_key: str = "CHANGE-ME-IN-PRODUCTION-use-openssl-rand-hex-32"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7

    # Encryption (for API keys and integration credentials)
    encryption_master_key: str = "CHANGE-ME-IN-PRODUCTION-use-openssl-rand-hex-32"

    # Celery
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Auto-response
    auto_response_confidence_threshold: float = 0.95

    # Auto-triage (system-level LLM key for automated analysis)
    auto_triage_enabled: bool = True
    auto_triage_provider: str = "claude"
    auto_triage_api_key: str = ""
    auto_triage_model: str | None = None

    model_config = {"env_file": ".env", "env_prefix": "CANE_", "case_sensitive": False}


@lru_cache
def get_settings() -> Settings:
    return Settings()
