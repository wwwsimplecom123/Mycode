"""Start and stop the local Windows API and worker without PowerShell process bugs."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPS = ROOT / ".deps"
DATA = ROOT / "data"
PID_FILE = DATA / "windows-services.json"


def clean_environment(port: int) -> dict[str, str]:
    environment: dict[str, str] = {}
    path_value = ""
    for key, value in os.environ.items():
        if key.lower() == "path":
            path_value = value
        else:
            environment[key] = value
    environment["Path"] = path_value
    environment["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(DEPS)])
    environment["SHIELDDOME_DATABASE_URL"] = f"sqlite:///{(DATA / 'shielddome.db').as_posix()}"
    environment["SHIELDDOME_RAW_STORAGE_DIR"] = str(DATA / "raw")
    environment["SHIELDDOME_ADMIN_TOKEN"] = "shielddome-local-admin"
    environment["SHIELDDOME_INGEST_TOKEN"] = "shielddome-local-ingest"
    environment["SHIELDDOME_BOOTSTRAP_ADMIN_USERNAME"] = "admin"
    environment["SHIELDDOME_BOOTSTRAP_ADMIN_PASSWORD"] = "ShieldDome-Local-Admin-2026"
    return environment


def start(host: str, port: int, with_llm: bool) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    if PID_FILE.exists():
        stop()
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(f"Port {port} is already in use. Stop the existing service or choose another port.")
    environment = clean_environment(port)
    environment["SHIELDDOME_WINDOWS_HOST"] = host
    environment["SHIELDDOME_WINDOWS_PORT"] = str(port)
    if not with_llm:
        environment.pop("SHIELDDOME_LLM_API_KEY", None)

    sys.path[:0] = [str(ROOT), str(DEPS)]
    os.environ.update(environment)
    from shielddome.storage import Database

    Database().initialize()
    flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    api_out = (DATA / "windows-api.out.log").open("wb")
    api_err = (DATA / "windows-api.err.log").open("wb")
    worker_out = (DATA / "windows-worker.out.log").open("wb")
    worker_err = (DATA / "windows-worker.err.log").open("wb")
    api = subprocess.Popen(
        [sys.executable, "scripts/run_windows_api.py"],
        cwd=ROOT,
        env=environment,
        stdout=api_out,
        stderr=api_err,
        creationflags=flags,
    )
    worker = subprocess.Popen(
        [sys.executable, "app/worker.py"],
        cwd=ROOT,
        env=environment,
        stdout=worker_out,
        stderr=worker_err,
        creationflags=flags,
    )
    PID_FILE.write_text(
        json.dumps({"api_pid": api.pid, "worker_pid": worker.pid, "host": host, "port": port}),
        encoding="utf-8",
    )
    try:
        for _ in range(60):
            if api.poll() is not None:
                error = (DATA / "windows-api.err.log").read_text(encoding="utf-8", errors="replace")[-2000:]
                raise RuntimeError(f"API process exited with code {api.returncode}.\n{error}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/health", timeout=1) as response:
                    if response.status == 200:
                        return
            except OSError:
                time.sleep(0.25)
        raise RuntimeError("API did not become healthy. Check data/windows-api.err.log.")
    except Exception:
        stop()
        raise


def stop() -> None:
    if not PID_FILE.exists():
        return
    services = json.loads(PID_FILE.read_text(encoding="utf-8-sig"))
    for key in ("api_pid", "worker_pid"):
        try:
            pid = int(services[key])
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            else:
                os.kill(pid, signal.SIGTERM)
        except (OSError, KeyError, ValueError):
            pass
        except subprocess.TimeoutExpired:
            pass
    PID_FILE.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    start_parser = subparsers.add_parser("start")
    start_parser.add_argument("--host", default="127.0.0.1")
    start_parser.add_argument("--port", type=int, default=8000)
    start_parser.add_argument("--with-llm", action="store_true")
    subparsers.add_parser("stop")
    args = parser.parse_args()
    if args.action == "start":
        start(args.host, args.port, args.with_llm)
    else:
        stop()


if __name__ == "__main__":
    main()
