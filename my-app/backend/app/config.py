from pydantic_settings import BaseSettings
from functools import lru_cache

DEFAULT_SECRET = "CHANGE-ME-IN-PRODUCTION-use-openssl-rand-hex-32"


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
    jwt_secret_key: str = DEFAULT_SECRET
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7

    # Encryption (for API keys and integration credentials)
    encryption_master_key: str = DEFAULT_SECRET

    # Celery
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000", "http://localhost:3002"]

    # Registration. The very first account is always allowed and becomes the admin.
    # After that, accounts are created by an admin unless this is switched on,
    # in which case anyone may self-register as a tier-1 analyst (never higher).
    allow_self_registration: bool = False

    # Ingestion
    # Optional shared secret for machine senders (Sentinel webhook, log shippers):
    # send it as the X-API-Key header instead of a user token.
    ingest_api_key: str = ""
    ingest_max_batch_events: int = 5000
    ingest_max_upload_bytes: int = 20 * 1024 * 1024
    # A correlated group opens an incident once its worst event reaches this severity
    # (or an attack pattern / security alert is recognised). Quieter events stay as logs.
    incident_min_severity: str = "medium"
    # An event with no correlation ID opens its own incident at or above this severity.
    incident_min_severity_uncorrelated: str = "high"

    # Auto-response
    auto_response_confidence_threshold: float = 0.95
    # Only these action types may ever run without an analyst. Everything else the AI
    # recommends (disable account, isolate host, ...) always waits in the approval queue.
    auto_execute_action_types: list[str] = ["block_ip", "block_url", "block_file_hash"]

    # Auto-triage (system-level LLM key for automated analysis)
    auto_triage_enabled: bool = True
    auto_triage_provider: str = "claude"
    auto_triage_api_key: str = ""
    auto_triage_model: str | None = None
    auto_triage_azure_endpoint: str = ""  # required when the provider is azure_openai
    # Seconds to wait after an incident opens before triaging, so the rest of a burst
    # of correlated events has landed and the model sees the whole picture.
    auto_triage_delay_seconds: int = 5

    # Where analysts reach the UI. Used for links in notifications and tickets.
    public_url: str = "http://localhost:5173"
    # Notifications and tickets are raised for incidents at or above these severities
    notify_min_severity: str = "high"
    ticket_min_severity: str = "high"
    # How often connected log sources (Splunk, Elastic, GuardDuty...) are polled
    source_poll_seconds: int = 60

    # Auto-enrichment (query threat intel before AI triage)
    auto_enrichment_enabled: bool = True
    auto_enrichment_max_iocs: int = 4

    model_config = {"env_file": ".env", "env_prefix": "CANE_", "case_sensitive": False}


    def insecure_defaults(self) -> list[str]:
        """Names of secrets still set to the value published in this repository."""
        names = []
        if self.jwt_secret_key == DEFAULT_SECRET:
            names.append("CANE_JWT_SECRET_KEY")
        if self.encryption_master_key == DEFAULT_SECRET:
            names.append("CANE_ENCRYPTION_MASTER_KEY")
        return names


@lru_cache
def get_settings() -> Settings:
    return Settings()
