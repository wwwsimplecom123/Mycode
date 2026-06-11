"""ShieldDome durable analysis worker."""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shielddome.enterprise import EnterpriseService  # noqa: E402
from shielddome.settings import SETTINGS  # noqa: E402


def run() -> None:
    service = EnterpriseService()
    worker_id = f"{socket.gethostname()}-{id(service)}"
    print(f"ShieldDome worker started: {worker_id}")
    while True:
        task = service.db.claim_task(worker_id)
        if not task:
            time.sleep(SETTINGS.worker_poll_seconds)
            continue
        try:
            result, degraded = service.process_analysis(task["analysis_id"])
            service.db.complete_task(task["id"], task["analysis_id"], result, degraded)
        except Exception as exc:
            service.db.fail_task(task, str(exc), SETTINGS.worker_max_attempts)


if __name__ == "__main__":
    run()
