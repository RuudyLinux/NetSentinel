from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="NETSENTINEL_", extra="ignore")

    database_url: str = f"sqlite:///{REPO_ROOT / 'var' / 'netsentinel.db'}"
    # 56 bytes: PyJWT warns below HS256's RFC 7518 §3.2 recommended 32-byte minimum (R12).
    # Any real deployment overrides this via NETSENTINEL_JWT_SECRET.
    jwt_secret: str = "dev-only-secret-change-me-before-deploying-to-production"
    storage_dir: Path = REPO_ROOT / "var" / "blobs"
    rules_dir: Path = REPO_ROOT / "rules"
    mappings_dir: Path = REPO_ROOT / "mappings"
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    max_upload_bytes: int = 5 * 1024 * 1024
    engine_version: str = "0.1.0"
    # Advisory AI interpretation of unrecognized config lines (see services/ai/client.py).
    # Unset by default — the feature 503s cleanly rather than being silently broken.
    openrouter_api_key: str | None = None
    openrouter_model: str = "openai/gpt-4o-mini"


settings = Settings()
