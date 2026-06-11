"""Environment-backed production settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("SHIELDDOME_DATABASE_URL", f"sqlite:///{ROOT / 'data' / 'shielddome.db'}")
    raw_storage_dir: Path = Path(os.getenv("SHIELDDOME_RAW_STORAGE_DIR", str(ROOT / "data" / "raw")))
    max_upload_bytes: int = int(os.getenv("SHIELDDOME_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
    raw_retention_hours: int = int(os.getenv("SHIELDDOME_RAW_RETENTION_HOURS", "72"))
    record_retention_days: int = int(os.getenv("SHIELDDOME_RECORD_RETENTION_DAYS", "180"))
    data_encryption_key: str = os.getenv("SHIELDDOME_DATA_ENCRYPTION_KEY", "")
    worker_poll_seconds: float = float(os.getenv("SHIELDDOME_WORKER_POLL_SECONDS", "1"))
    worker_max_attempts: int = int(os.getenv("SHIELDDOME_WORKER_MAX_ATTEMPTS", "3"))
    bootstrap_admin_password: str = os.getenv("SHIELDDOME_BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe-Before-Production")
    bootstrap_admin_username: str = os.getenv("SHIELDDOME_BOOTSTRAP_ADMIN_USERNAME", "admin")
    api_token_ttl_hours: int = int(os.getenv("SHIELDDOME_API_TOKEN_TTL_HOURS", "12"))


SETTINGS = Settings()
