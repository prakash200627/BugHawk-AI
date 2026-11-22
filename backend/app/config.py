"""
BugHawk AI 2.0 — Application Configuration
Loads settings from environment variables with safe defaults.
"""
from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, model_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "BugHawk AI 2.0"
    app_version: str = "2.0.0"
    app_env: str = "development"
    app_secret_key: str = ""
    app_debug: bool = False
    allowed_origins: str = "http://localhost:5173,http://localhost:3000"

    # Database — set DATABASE_URL in the environment. No password is stored here.
    database_url: str = "postgresql://bughawk@localhost:5432/bughawk_db"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # JWT
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60

    # AI Provider
    llm_provider: str = "demo"  # demo | openai | anthropic | google
    llm_model: str = "gpt-4o"
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    google_api_key: Optional[str] = None

    # Security Tools. The API never accepts a path from a request.
    subfinder_path: str = "subfinder"
    subfinder_timeout_seconds: int = 120
    subfinder_max_output_bytes: int = 1_000_000
    httpx_path: str = "httpx"
    httpx_timeout_seconds: int = 10
    httpx_job_timeout_seconds: int = 180
    httpx_threads: int = 5
    httpx_max_assets: int = 50
    httpx_max_output_bytes: int = 1_000_000
    scan_worker_poll_seconds: float = 5
    nuclei_path: str = "nuclei"
    nuclei_timeout_seconds: int = 10
    nuclei_job_timeout_seconds: int = 180
    nuclei_rate_limit: int = 5
    nuclei_concurrency: int = 2
    nuclei_bulk_size: int = 5
    nuclei_max_targets: int = 25
    nuclei_max_output_bytes: int = 1_000_000
    semgrep_path: str = "semgrep"
    semgrep_timeout_seconds: int = 60
    semgrep_job_timeout_seconds: int = 180
    semgrep_max_output_bytes: int = 1_000_000
    zap_path: str = "zap.sh"
    zap_bind_port: int = 18080
    zap_job_timeout_seconds: int = 180
    zap_max_alerts: int = 50
    zap_max_output_bytes: int = 1_000_000
    zap_api_url: str = "http://127.0.0.1:18080"
    zap_api_key: Optional[str] = None

    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    # Celery
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # Demo Mode. Production stays off unless DEMO_MODE=true is set explicitly.
    demo_mode: bool = False
    demo_admin_email: str = "demo@bughawk.ai"
    demo_admin_password: str = ""

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v: str) -> str:
        return v

    def get_allowed_origins(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @model_validator(mode="after")
    def force_production_debug_off(self) -> "Settings":
        """Production never runs with debug enabled, even if APP_DEBUG=true is set."""
        if self.is_production and self.app_debug:
            self.app_debug = False
        return self

    @property
    def is_demo(self) -> bool:
        if self.is_production:
            return self.demo_mode
        return self.llm_provider == "demo" or self.demo_mode

    def validate_runtime_settings(self) -> None:
        """Refuse to boot a public deployment with missing secrets or local origins."""
        if not self.is_production:
            return
        problems = []
        if len(self.app_secret_key) < 32:
            problems.append("APP_SECRET_KEY")
        if len(self.jwt_secret_key) < 32:
            problems.append("JWT_SECRET_KEY")
        origins = self.get_allowed_origins()
        if not origins or any(
            marker in origin
            for origin in origins
            for marker in ("localhost", "127.0.0.1")
        ):
            problems.append("ALLOWED_ORIGINS")
        if problems:
            raise RuntimeError(
                "Refusing to start in production. Set secure values for: "
                + ", ".join(problems)
            )


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
