from functools import lru_cache
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Remediation Twin"
    environment: Literal["local", "dev", "staging", "production"] = "local"
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
    feature_autonomous_remediation: bool = False
    feature_model_planning: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    def validate_runtime(self) -> None:
        if self.environment == "production" and self.session_secret == "replace-with-32-byte-random-secret":
            raise ValueError("SESSION_SECRET must be configured in production")
        if self.environment == "production" and (not self.oidc_issuer or not self.oidc_client_id):
            raise ValueError("OIDC issuer and client id are required in production")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_runtime()
    return settings
