"""Robust Windows API entrypoint that imports dependencies from the project."""

from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPS = ROOT / ".deps"
sys.path[:0] = [str(ROOT), str(DEPS)]

import uvicorn  # noqa: E402


if __name__ == "__main__":
    uvicorn.run(
        "app.api:app",
        host=os.getenv("SHIELDDOME_WINDOWS_HOST", "127.0.0.1"),
        port=int(os.getenv("SHIELDDOME_WINDOWS_PORT", "8000")),
        log_level="info",
    )
