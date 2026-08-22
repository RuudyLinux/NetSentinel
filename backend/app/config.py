from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="NETSENTINEL_", extra="ignore")

    database_url: str = f"sqlite:///{REPO_ROOT / 'var' / 'netsentinel.db'}"
    jwt_secret: str = "dev-only-secret-change-me"
    storage_dir: Path = REPO_ROOT / "var" / "blobs"
    rules_dir: Path = REPO_ROOT / "rules"
    mappings_dir: Path = REPO_ROOT / "mappings"
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    max_upload_bytes: int = 5 * 1024 * 1024
    engine_version: str = "0.1.0"


settings = Settings()
