"""Print an offline threshold report from confirmed ShieldDome labels."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shielddome.evaluation import recommend_thresholds  # noqa: E402
from shielddome.storage import Database  # noqa: E402


def main() -> int:
    database = Database()
    database.initialize()
    report = recommend_thresholds(database.confirmed_evaluation_dataset())
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["sample_count"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
