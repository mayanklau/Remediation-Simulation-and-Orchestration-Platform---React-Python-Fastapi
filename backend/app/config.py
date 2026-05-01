from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Remediation Twin"
    environment: str = "development"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "remediation_twin"
    default_tenant_slug: str = "default"
    session_secret: str = "replace-with-32-byte-random-secret"
    rate_limit_per_minute: int = 120
    evidence_storage_url: str = "file://./evidence"
    otel_exporter_otlp_endpoint: str = ""
    alert_webhook_url: str = ""
    jira_base_url: str = ""
    github_app_id: str = ""
    servicenow_instance_url: str = ""
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    anthropic_api_key: str = ""
    anthropic_base_url: str = ""
    anthropic_model: str = ""
    gemini_api_key: str = ""
    gemini_base_url: str = ""
    gemini_model: str = ""
    local_slm_url: str = ""
    local_slm_model: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()

