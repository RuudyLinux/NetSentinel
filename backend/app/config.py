from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]

# The one value that must never reach a production deployment. Startup fails closed
# if `environment="production"` and `jwt_secret` still equals this (see main.py).
DEV_JWT_SECRET = "dev-only-secret-change-me-before-deploying-to-production"

# HS256's RFC 7518 §3.2 recommended minimum. Startup fails closed in production
# below this length too, even for a secret that isn't the literal default.
MIN_PRODUCTION_JWT_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="NETSENTINEL_", extra="ignore")

    # "production" is the only value that activates the startup secret check below.
    # Anything else (including typos) stays permissive, matching local/CI defaults.
    environment: Literal["development", "test", "production"] = "development"
    database_url: str = f"sqlite:///{REPO_ROOT / 'var' / 'netsentinel.db'}"
    # Any real deployment overrides this via NETSENTINEL_JWT_SECRET.
    jwt_secret: str = DEV_JWT_SECRET
    storage_dir: Path = REPO_ROOT / "var" / "blobs"
    # "local" (default) uses storage_dir on disk; "s3" targets S3 or an S3-compatible
    # endpoint (e.g. MinIO) via the s3_* settings below — see storage/registry.py.
    storage_backend: Literal["local", "s3"] = "local"
    s3_bucket: str = "netsentinel"
    # Leave unset for real AWS S3; point at a MinIO (or other S3-compatible) endpoint
    # for local/self-hosted deployments, e.g. "http://minio:9000" in docker-compose.
    s3_endpoint_url: str | None = None
    s3_access_key: str | None = None
    s3_secret_key: str | None = None
    s3_region: str = "us-east-1"
    rules_dir: Path = REPO_ROOT / "rules"
    mappings_dir: Path = REPO_ROOT / "mappings"
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    password_reset_minutes: int = 30
    max_upload_bytes: int = 5 * 1024 * 1024
    engine_version: str = "0.1.0"
    # Advisory AI interpretation of unrecognized config lines (see services/ai/client.py).
    # Unset by default — the feature 503s cleanly rather than being silently broken.
    openrouter_api_key: str | None = None
    openrouter_model: str = "openai/gpt-4o-mini"


settings = Settings()
