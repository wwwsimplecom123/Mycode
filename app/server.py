"""Legacy dependency-free demo server.

Production Linux deployments use ``uvicorn app.api:app`` and ``app/worker.py``.
This server remains available for environments that have not installed the
enterprise dependencies yet.
"""

from __future__ import annotations

import json
import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shielddome.analyzer import AnalyzerService  # noqa: E402


SERVICE = AnalyzerService()
WEB_ROOT = ROOT / "web"


class ShieldDomeHandler(BaseHTTPRequestHandler):
    server_version = "ShieldDomeMVP/1.1"

    def do_OPTIONS(self) -> None:
        self._send_empty(204)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path.startswith("/api/email/analyze/status/"):
                analysis_id = unquote(path.rsplit("/", 1)[-1])
                self._send_json(200, SERVICE.status(analysis_id))
                return
            if path == "/api/soc/records":
                self._send_json(200, {"records": SERVICE.list_records()})
                return
            if path == "/api/soc/tickets":
                self._send_json(200, {"tickets": SERVICE.list_tickets()})
                return
            if path == "/api/config/llm":
                self._ensure_local_config_origin()
                self._send_json(200, SERVICE.llm_config())
                return
            self._serve_static(path)
        except PermissionError as exc:
            self._send_json(403, {"error": str(exc)})
        except KeyError as exc:
            self._send_json(404, {"error": str(exc)})
        except Exception as exc:  # pragma: no cover - guard for manual MVP use
            self._send_json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            payload = self._read_json()
            if path == "/api/email/analyze/quick":
                self._send_json(200, SERVICE.quick_analyze(payload))
                return
            if path == "/api/email/analyze/deep":
                self._send_json(200, SERVICE.deep_analyze(str(payload.get("analysis_id"))))
                return
            if path == "/api/email/action-log":
                self._send_json(200, SERVICE.log_action(payload))
                return
            if path == "/api/soc/false-positive":
                self._send_json(200, SERVICE.create_false_positive_ticket(payload))
                return
            if path == "/api/soc/review-result":
                self._send_json(200, SERVICE.review_ticket(payload))
                return
            if path == "/api/config/llm":
                self._ensure_local_config_origin()
                self._send_json(200, SERVICE.configure_llm(payload))
                return
            self._send_json(404, {"error": f"Unknown route: {path}"})
        except PermissionError as exc:
            self._send_json(403, {"error": str(exc)})
        except KeyError as exc:
            self._send_json(404, {"error": str(exc)})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:  # pragma: no cover - guard for manual MVP use
            self._send_json(500, {"error": str(exc)})

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            data = json.loads(body or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON body") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def _serve_static(self, path: str) -> None:
        if path in {"", "/"}:
            target = WEB_ROOT / "index.html"
        else:
            target = (WEB_ROOT / path.lstrip("/")).resolve()
            if not str(target).startswith(str(WEB_ROOT.resolve())):
                self._send_json(403, {"error": "Forbidden"})
                return
        if not target.exists() or not target.is_file():
            self._send_json(404, {"error": "Not found"})
            return

        content = target.read_bytes()
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, status: int, payload: dict) -> None:
        content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_empty(self, status: int) -> None:
        self.send_response(status)
        self._cors_headers()
        self.end_headers()

    def _cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _ensure_local_config_origin(self) -> None:
        origin = self.headers.get("Origin") or ""
        if origin and not origin.startswith(("http://127.0.0.1:", "http://localhost:")):
            raise PermissionError("LLM configuration is only available from the local management page")


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), ShieldDomeHandler)
    print(f"ShieldDome MVP server running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
