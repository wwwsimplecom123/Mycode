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
    last_recovery = 0.0
    while True:
        service.db.record_worker_heartbeat(worker_id)
        now = time.time()
        if now - last_recovery >= 60:
            service.recover_stale_tasks(SETTINGS.worker_stale_after_seconds)
            last_recovery = now
        task = service.db.claim_task(worker_id)
        if task:
            try:
                result, degraded = service.process_analysis(task["analysis_id"])
                service.db.complete_task(task["id"], task["analysis_id"], result, degraded)
            except Exception as exc:
                service.db.fail_task(task, str(exc), SETTINGS.worker_max_attempts)
            continue
        knowledge_task = service.db.claim_knowledge_task(worker_id)
        if not knowledge_task:
            time.sleep(SETTINGS.worker_poll_seconds)
            continue
        try:
            embedding = service.process_knowledge_embedding(knowledge_task["knowledge_id"])
            service.db.complete_knowledge_task(knowledge_task["id"], knowledge_task["knowledge_id"], embedding)
        except Exception as exc:
            service.db.fail_knowledge_task(knowledge_task, str(exc), SETTINGS.worker_max_attempts)


if __name__ == "__main__":
    run()
