"""Apply raw-message and record retention policies."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from shielddome.settings import SETTINGS


def main() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=SETTINGS.raw_retention_hours)
    deleted = 0
    for path in SETTINGS.raw_storage_dir.glob("*.eml*"):
        modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        if modified < cutoff:
            path.unlink()
            deleted += 1
    print(f"Deleted {deleted} expired raw EML files.")


if __name__ == "__main__":
    main()
