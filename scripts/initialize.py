"""Initialize ShieldDome database and storage."""

from pathlib import Path

from shielddome.settings import SETTINGS
from shielddome.storage import Database


def main() -> None:
    SETTINGS.raw_storage_dir.mkdir(parents=True, exist_ok=True)
    Database().initialize()
    print("ShieldDome database and raw storage initialized.")


if __name__ == "__main__":
    main()
