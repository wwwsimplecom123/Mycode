"""Initialize ShieldDome database and storage."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shielddome.settings import SETTINGS
from shielddome.storage import Database


def main() -> None:
    SETTINGS.raw_storage_dir.mkdir(parents=True, exist_ok=True)
    Database().initialize()
    print("ShieldDome database and raw storage initialized.")


if __name__ == "__main__":
    main()
