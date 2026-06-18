"""Persistent storage and reliable task queue.

SQLite is the zero-dependency development backend. Production uses PostgreSQL;
the schema and queue semantics are kept compatible, including SKIP LOCKED task
claiming for multiple workers.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator

from .config import BLACKLISTED_DOMAINS, HIGH_RISK_KEYWORDS, RISK_THRESHOLDS, TRUSTED_IP_RANGES, TRUSTED_ROOT_DOMAINS
from .settings import SETTINGS


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_safe(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return value


def _json(value: Any) -> str:
    return json.dumps(_json_safe(value), ensure_ascii=False, separators=(",", ":"), default=str)



class Database:
    def __init__(self, url: str | None = None):
        self.url = url or SETTINGS.database_url
        self._lock = threading.RLock()
        self._is_postgres = self.url.startswith(("postgresql://", "postgres://"))
        if self._is_postgres:
            try:
                import psycopg  # type: ignore
                from psycopg.rows import dict_row  # type: ignore
            except ImportError as exc:  # pragma: no cover - production dependency
                raise RuntimeError("PostgreSQL requires psycopg; install requirements.txt") from exc
            self._psycopg = psycopg
            self._dict_row = dict_row
        else:
            path = Path(self.url.removeprefix("sqlite:///"))
            path.parent.mkdir(parents=True, exist_ok=True)
            self._path = path

    @property
    def state_directory(self) -> Path:
        return SETTINGS.raw_storage_dir.parent if self._is_postgres else self._path.parent

    @contextmanager
    def connect(self) -> Iterator[Any]:
        if self._is_postgres:
            with self._psycopg.connect(self.url, row_factory=self._dict_row) as connection:
                yield connection
            return
        connection = sqlite3.connect(self._path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        schema = POSTGRES_SCHEMA if self._is_postgres else SQLITE_SCHEMA
        with self.connect() as connection:
            if self._is_postgres:
                for statement in [part.strip() for part in schema.split(";") if part.strip()]:
                    connection.execute(statement)
            else:
                connection.executescript(schema)
        self.seed_default_policies()

    def seed_default_policies(self) -> None:
        defaults = [
            ("trusted_domains", sorted(TRUSTED_ROOT_DOMAINS)),
            ("trusted_ip_ranges", sorted(TRUSTED_IP_RANGES)),
            ("blacklisted_domains", sorted(BLACKLISTED_DOMAINS)),
            ("high_risk_keywords", sorted(HIGH_RISK_KEYWORDS)),
            ("risk_thresholds", RISK_THRESHOLDS),
            ("trusted_include_subdomains", True),
        ]
        with self.connect() as connection:
            for key, value in defaults:
                self._insert_ignore(connection, "policies", ["key", "value", "updated_at"], [key, _json(value), utc_now()])

    def create_analysis(self, source_name: str, raw_path: str, parsed: dict[str, Any], quick: dict[str, Any]) -> str:
        analysis_id = str(uuid.uuid4())
        now = utc_now()
        with self.connect() as connection:
            self._insert(
                connection,
                "analyses",
                ["id", "source_name", "status", "risk_level", "quick_result", "parsed_message", "raw_path", "created_at", "updated_at"],
                [analysis_id, source_name, "queued", quick.get("risk_level", "low"), _json(quick), _json(parsed), raw_path, now, now],
            )
            self._insert(
                connection,
                "tasks",
                ["id", "analysis_id", "status", "attempts", "available_at", "created_at", "updated_at"],
                [str(uuid.uuid4()), analysis_id, "queued", 0, now, now, now],
            )
        return analysis_id

    def claim_task(self, worker_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            if self._is_postgres:
                row = connection.execute(
                    """
                    SELECT * FROM tasks
                    WHERE status = 'queued' AND available_at <= NOW()
                    ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
                    """
                ).fetchone()
            else:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM tasks WHERE status = 'queued' AND available_at <= ? ORDER BY created_at LIMIT 1",
                    [utc_now()],
                ).fetchone()
            if not row:
                return None
            task = dict(row)
            self._execute(
                connection,
                "UPDATE tasks SET status = ?, worker_id = ?, attempts = attempts + 1, updated_at = ? WHERE id = ?",
                ["running", worker_id, utc_now(), task["id"]],
            )
            self._execute(
                connection,
                "UPDATE analyses SET status = ?, updated_at = ? WHERE id = ?",
                ["running", utc_now(), task["analysis_id"]],
            )
            task["task_type"] = "analysis"
            return task

    def queue_knowledge_embedding(self, knowledge_id: str) -> str:
        task_id = str(uuid.uuid4())
        now = utc_now()
        with self.connect() as connection:
            self._insert(
                connection,
                "knowledge_tasks",
                ["id", "knowledge_id", "status", "attempts", "available_at", "created_at", "updated_at"],
                [task_id, knowledge_id, "queued", 0, now, now, now],
            )
        self.update_knowledge_metadata(knowledge_id, {"embedding_status": "queued", "embedding_error": ""})
        return task_id

    def claim_knowledge_task(self, worker_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            if self._is_postgres:
                row = connection.execute(
                    """
                    SELECT * FROM knowledge_tasks
                    WHERE status = 'queued' AND available_at <= NOW()
                    ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
                    """
                ).fetchone()
            else:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM knowledge_tasks WHERE status = 'queued' AND available_at <= ? ORDER BY created_at LIMIT 1",
                    [utc_now()],
                ).fetchone()
            if not row:
                return None
            task = dict(row)
            self._execute(
                connection,
                "UPDATE knowledge_tasks SET status = ?, worker_id = ?, attempts = attempts + 1, updated_at = ? WHERE id = ?",
                ["running", worker_id, utc_now(), task["id"]],
            )
            self._update_knowledge_metadata_on(connection, task["knowledge_id"], {"embedding_status": "running", "embedding_error": ""})
            task["task_type"] = "knowledge_embedding"
            return task

    def recover_stale_tasks(self, timeout_seconds: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max(60, timeout_seconds))).isoformat()
        recovered = 0
        with self.connect() as connection:
            rows = self._fetchall_on(
                connection,
                "SELECT id, analysis_id FROM tasks WHERE status = ? AND updated_at < ?",
                ["running", cutoff],
            )
            recovered += len(rows)
            for row in rows:
                self._execute(
                    connection,
                    "UPDATE tasks SET status = ?, worker_id = NULL, available_at = ?, updated_at = ? WHERE id = ?",
                    ["queued", utc_now(), utc_now(), row["id"]],
                )
                self._execute(
                    connection,
                    "UPDATE analyses SET status = ?, error = ?, updated_at = ? WHERE id = ?",
                    ["queued", "Recovered stale running task", utc_now(), row["analysis_id"]],
                )
            knowledge_rows = self._fetchall_on(
                connection,
                "SELECT id, knowledge_id FROM knowledge_tasks WHERE status = ? AND updated_at < ?",
                ["running", cutoff],
            )
            recovered += len(knowledge_rows)
            for row in knowledge_rows:
                self._execute(
                    connection,
                    "UPDATE knowledge_tasks SET status = ?, worker_id = NULL, available_at = ?, updated_at = ? WHERE id = ?",
                    ["queued", utc_now(), utc_now(), row["id"]],
                )
                self._update_knowledge_metadata_on(
                    connection,
                    row["knowledge_id"],
                    {"embedding_status": "queued", "embedding_error": "Recovered stale running task"},
                )
        return recovered

    def retry_analysis(self, analysis_id: str) -> bool:
        analysis = self.get_analysis(analysis_id)
        if not analysis or analysis.get("status") not in {"failed", "degraded"}:
            return False
        now = utc_now()
        with self.connect() as connection:
            self._insert(
                connection,
                "tasks",
                ["id", "analysis_id", "status", "attempts", "available_at", "created_at", "updated_at"],
                [str(uuid.uuid4()), analysis_id, "queued", 0, now, now, now],
            )
            self._execute(
                connection,
                "UPDATE analyses SET status = ?, error = NULL, updated_at = ? WHERE id = ?",
                ["queued", now, analysis_id],
            )
        return True

    def complete_task(self, task_id: str, analysis_id: str, result: dict[str, Any], degraded: bool = False) -> None:
        status = "degraded" if degraded else "completed"
        with self.connect() as connection:
            self._execute(connection, "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?", [status, utc_now(), task_id])
            self._execute(
                connection,
                "UPDATE analyses SET status = ?, risk_level = ?, result = ?, updated_at = ? WHERE id = ?",
                [status, result.get("risk_level", "low"), _json(result), utc_now(), analysis_id],
            )

    def complete_knowledge_task(self, task_id: str, knowledge_id: str, embedding: list[float]) -> None:
        with self.connect() as connection:
            self._execute(connection, "UPDATE knowledge_tasks SET status = ?, updated_at = ? WHERE id = ?", ["completed", utc_now(), task_id])
        self.update_knowledge(knowledge_id, embedding=embedding)
        self.update_knowledge_metadata(knowledge_id, {"embedding_status": "completed", "embedding_error": ""})

    def fail_task(self, task: dict[str, Any], error: str, max_attempts: int) -> None:
        attempts = int(task.get("attempts") or 0) + 1
        terminal = attempts >= max_attempts
        task_status = "dead" if terminal else "queued"
        analysis_status = "failed" if terminal else "queued"
        available = datetime.now(timezone.utc) + timedelta(seconds=min(300, 2**attempts))
        with self.connect() as connection:
            self._execute(
                connection,
                "UPDATE tasks SET status = ?, last_error = ?, available_at = ?, updated_at = ? WHERE id = ?",
                [task_status, error[:1000], available.isoformat(), utc_now(), task["id"]],
            )
            self._execute(
                connection,
                "UPDATE analyses SET status = ?, error = ?, updated_at = ? WHERE id = ?",
                [analysis_status, error[:1000], utc_now(), task["analysis_id"]],
            )

    def fail_knowledge_task(self, task: dict[str, Any], error: str, max_attempts: int) -> None:
        attempts = int(task.get("attempts") or 0) + 1
        terminal = attempts >= max_attempts
        task_status = "dead" if terminal else "queued"
        embedding_status = "failed" if terminal else "queued"
        available = datetime.now(timezone.utc) + timedelta(seconds=min(300, 2**attempts))
        with self.connect() as connection:
            self._execute(
                connection,
                "UPDATE knowledge_tasks SET status = ?, last_error = ?, available_at = ?, updated_at = ? WHERE id = ?",
                [task_status, error[:1000], available.isoformat(), utc_now(), task["id"]],
            )
            self._update_knowledge_metadata_on(
                connection,
                task["knowledge_id"],
                {"embedding_status": embedding_status, "embedding_error": error[:1000]},
            )

    def record_worker_heartbeat(self, worker_id: str) -> None:
        now = utc_now()
        with self.connect() as connection:
            existing = self._fetchone_on(connection, "SELECT worker_id FROM worker_heartbeats WHERE worker_id = ?", [worker_id])
            if existing:
                self._execute(
                    connection,
                    "UPDATE worker_heartbeats SET last_seen_at = ?, updated_at = ? WHERE worker_id = ?",
                    [now, now, worker_id],
                )
            else:
                self._insert(
                    connection,
                    "worker_heartbeats",
                    ["worker_id", "last_seen_at", "updated_at"],
                    [worker_id, now, now],
                )

    def get_analysis(self, analysis_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM analyses WHERE id = ?", [analysis_id])
        return self._decode_analysis(row) if row else None

    def list_analyses(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        rows = self._fetchall("SELECT * FROM analyses ORDER BY created_at DESC LIMIT ? OFFSET ?", [min(limit, 500), max(offset, 0)])
        return [self._decode_analysis(row) for row in rows]

    def list_analyses_for_actor(self, user_id: str = "", username: str = "", limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        rows = self._fetchall("SELECT * FROM analyses ORDER BY created_at DESC LIMIT 5000", [])
        filtered = [item for item in (self._decode_analysis(row) for row in rows) if self._analysis_owned_by(item, user_id, username)]
        offset = max(offset, 0)
        return filtered[offset: offset + min(limit, 500)]

    def dashboard(self, user_id: str = "", username: str = "") -> dict[str, Any]:
        rows = self._fetchall("SELECT risk_level, status, created_at, parsed_message FROM analyses ORDER BY created_at DESC LIMIT 5000", [])
        if user_id or username:
            rows = [self._decode_analysis(row) for row in rows]
            rows = [row for row in rows if self._analysis_owned_by(row, user_id, username)]
        risk = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for row in rows:
            level = row.get("risk_level") or "low"
            risk[level] = risk.get(level, 0) + 1
        return {
            "total": len(rows),
            "risk": risk,
            "pending": sum(1 for row in rows if row.get("status") in {"queued", "running"}),
            "degraded": sum(1 for row in rows if row.get("status") == "degraded"),
            "trend": self._daily_counts(rows),
        }

    def queue_stats(self) -> dict[str, Any]:
        rows = self._fetchall("SELECT status, COUNT(*) AS count FROM tasks GROUP BY status", [])
        stats = {str(row.get("status")): int(row.get("count") or 0) for row in rows}
        knowledge_rows = self._fetchall("SELECT status, COUNT(*) AS count FROM knowledge_tasks GROUP BY status", [])
        knowledge_stats = {str(row.get("status")): int(row.get("count") or 0) for row in knowledge_rows}
        return {
            "queued": stats.get("queued", 0),
            "running": stats.get("running", 0),
            "dead": stats.get("dead", 0),
            "completed": stats.get("completed", 0) + stats.get("degraded", 0),
            "failed": stats.get("dead", 0),
            "by_status": stats,
            "knowledge": {
                "queued": knowledge_stats.get("queued", 0),
                "running": knowledge_stats.get("running", 0),
                "failed": knowledge_stats.get("dead", 0),
                "completed": knowledge_stats.get("completed", 0),
                "by_status": knowledge_stats,
            },
        }

    def knowledge_stats(self) -> dict[str, int]:
        rows = self._fetchall("SELECT status, COUNT(*) AS count FROM knowledge GROUP BY status", [])
        stats = {str(row.get("status")): int(row.get("count") or 0) for row in rows}
        return {
            "total": sum(stats.values()),
            "pending": stats.get("pending", 0),
            "published": stats.get("published", 0),
            "disabled": stats.get("disabled", 0),
        }

    def worker_heartbeats(self) -> list[dict[str, Any]]:
        return self._fetchall("SELECT worker_id, last_seen_at, updated_at FROM worker_heartbeats ORDER BY last_seen_at DESC", [])

    def add_knowledge(self, title: str, source_type: str, content: str, generalized: str, metadata: dict[str, Any]) -> str:
        item_id = str(uuid.uuid4())
        now = utc_now()
        with self.connect() as connection:
            self._insert(
                connection,
                "knowledge",
                ["id", "title", "source_type", "status", "content", "generalized_content", "metadata", "version", "created_at", "updated_at"],
                [item_id, title, source_type, "pending", content, generalized, _json(metadata), 1, now, now],
            )
        return item_id

    def find_knowledge_by_content_hash(self, content_sha256: str) -> dict[str, Any] | None:
        if not content_sha256:
            return None
        try:
            if self._is_postgres:
                row = self._fetchone(
                    "SELECT id, title, source_type, status, metadata, version, created_at, updated_at FROM knowledge WHERE metadata->>'content_sha256' = ? ORDER BY created_at DESC LIMIT 1",
                    [content_sha256],
                )
            else:
                row = self._fetchone(
                    "SELECT id, title, source_type, status, metadata, version, created_at, updated_at FROM knowledge WHERE json_extract(metadata, '$.content_sha256') = ? ORDER BY created_at DESC LIMIT 1",
                    [content_sha256],
                )
            if row:
                return self._decode_json_fields(row, ["metadata"])
        except Exception:
            pass
        for item in self.list_knowledge_summaries(limit=5000).get("items", []):
            if (item.get("metadata") or {}).get("content_sha256") == content_sha256:
                return item
        return None

    def update_knowledge(self, item_id: str, status: str | None = None, embedding: list[float] | None = None) -> None:
        if status:
            self._execute_direct("UPDATE knowledge SET status = ?, updated_at = ? WHERE id = ?", [status, utc_now(), item_id])
        if embedding is not None:
            self._execute_direct("UPDATE knowledge SET embedding = ?, updated_at = ? WHERE id = ?", [_json(embedding), utc_now(), item_id])
            if self._is_postgres and len(embedding) == 1024:
                vector = "[" + ",".join(str(float(value)) for value in embedding) + "]"
                self._execute_direct(
                    "UPDATE knowledge SET embedding_vector = ?::vector, updated_at = ? WHERE id = ?",
                    [vector, utc_now(), item_id],
                )

    def update_knowledge_metadata(self, item_id: str, updates: dict[str, Any]) -> None:
        with self.connect() as connection:
            self._update_knowledge_metadata_on(connection, item_id, updates)

    def _update_knowledge_metadata_on(self, connection: Any, item_id: str, updates: dict[str, Any]) -> None:
        row = self._fetchone_on(connection, "SELECT metadata FROM knowledge WHERE id = ?", [item_id])
        if not row:
            return
        metadata = self._decode_json_fields(row, ["metadata"]).get("metadata") or {}
        metadata.update(updates)
        self._execute(connection, "UPDATE knowledge SET metadata = ?, updated_at = ? WHERE id = ?", [_json(metadata), utc_now(), item_id])

    def vector_knowledge(self, embedding: list[float], limit: int = 20) -> list[dict[str, Any]]:
        if not self._is_postgres or len(embedding) != 1024:
            return self.published_knowledge()
        vector = "[" + ",".join(str(float(value)) for value in embedding) + "]"
        rows = self._fetchall(
            """
            SELECT *, 1 - (embedding_vector <=> ?::vector) AS vector_score
            FROM knowledge
            WHERE status = 'published' AND embedding_vector IS NOT NULL
            ORDER BY embedding_vector <=> ?::vector
            LIMIT ?
            """,
            [vector, vector, min(limit, 100)],
        )
        return [self._decode_json_fields(row, ["metadata", "embedding"]) for row in rows]

    def list_knowledge(self) -> list[dict[str, Any]]:
        rows = self._fetchall("SELECT * FROM knowledge ORDER BY created_at DESC", [])
        return [self._decode_json_fields(row, ["metadata", "embedding"]) for row in rows]

    def list_knowledge_summaries(
        self,
        limit: int = 50,
        offset: int = 0,
        status: str = "",
        source_type: str = "",
        q: str = "",
    ) -> dict[str, Any]:
        where: list[str] = []
        params: list[Any] = []
        if status:
            where.append("status = ?")
            params.append(status)
        if source_type:
            where.append("source_type = ?")
            params.append(source_type)
        if q:
            where.append("(LOWER(title) LIKE ? OR LOWER(metadata) LIKE ?)")
            needle = f"%{q.lower()}%"
            params.extend([needle, needle])
        clause = "WHERE " + " AND ".join(where) if where else ""
        total_row = self._fetchone(f"SELECT COUNT(*) AS count FROM knowledge {clause}", params)
        rows = self._fetchall(
            f"SELECT id, title, source_type, status, metadata, version, created_at, updated_at FROM knowledge {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [*params, min(max(limit, 1), 200), max(offset, 0)],
        )
        return {"items": [self._decode_json_fields(row, ["metadata"]) for row in rows], "total": int((total_row or {}).get("count") or 0)}

    def get_knowledge(self, item_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM knowledge WHERE id = ?", [item_id])
        return self._decode_json_fields(row, ["metadata", "embedding"]) if row else None

    def published_knowledge(self) -> list[dict[str, Any]]:
        rows = self._fetchall("SELECT * FROM knowledge WHERE status = 'published' ORDER BY updated_at DESC", [])
        return [self._decode_json_fields(row, ["metadata", "embedding"]) for row in rows]

    def record_audit(self, actor: str, action: str, target: str, details: dict[str, Any] | None = None) -> None:
        with self.connect() as connection:
            self._insert(
                connection,
                "audit_logs",
                ["id", "actor", "action", "target", "details", "created_at"],
                [str(uuid.uuid4()), actor, action, target, _json(details or {}), utc_now()],
            )

    def list_audit(self, limit: int = 200, actor: str = "", offset: int = 0) -> list[dict[str, Any]]:
        params: list[Any] = []
        where = ""
        if actor:
            where = "WHERE actor = ?"
            params.append(actor)
        params.extend([min(limit, 1000), max(offset, 0)])
        return [
            self._decode_json_fields(row, ["details"])
            for row in self._fetchall(f"SELECT * FROM audit_logs {where} ORDER BY created_at DESC LIMIT ? OFFSET ?", params)
        ]

    def get_policy(self, key: str, default: Any = None) -> Any:
        row = self._fetchone("SELECT value FROM policies WHERE key = ?", [key])
        if not row:
            return default
        return json.loads(row["value"]) if isinstance(row["value"], str) else row["value"]

    def set_policy(self, key: str, value: Any) -> None:
        now = utc_now()
        with self.connect() as connection:
            existing = self._fetchone_on(connection, "SELECT key FROM policies WHERE key = ?", [key])
            if existing:
                self._execute(connection, "UPDATE policies SET value = ?, updated_at = ? WHERE key = ?", [_json(value), now, key])
            else:
                self._insert(connection, "policies", ["key", "value", "updated_at"], [key, _json(value), now])

    def create_user_if_missing(self, username: str, password_hash: str, display_name: str, role: str) -> None:
        now = utc_now()
        with self.connect() as connection:
            self._insert_ignore(
                connection,
                "users",
                ["id", "username", "password_hash", "display_name", "role", "disabled", "failed_attempts", "created_at", "updated_at"],
                [str(uuid.uuid4()), username, password_hash, display_name, role, 0, 0, now, now],
            )

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        return self._fetchone("SELECT * FROM users WHERE username = ?", [username])

    def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        return self._fetchone("SELECT * FROM users WHERE id = ?", [user_id])

    def list_users(self) -> list[dict[str, Any]]:
        rows = self._fetchall(
            """
            SELECT id, username, display_name, role, disabled, failed_attempts,
                   lock_until, created_at, updated_at,
                   EXISTS(
                       SELECT 1 FROM plugin_tokens
                       WHERE plugin_tokens.user_id = users.id AND plugin_tokens.revoked = 0
                   ) AS plugin_token_configured,
                   (
                       SELECT token_prefix FROM plugin_tokens
                       WHERE plugin_tokens.user_id = users.id AND plugin_tokens.revoked = 0
                       LIMIT 1
                   ) AS plugin_token_prefix,
                   (
                       SELECT last_used_at FROM plugin_tokens
                       WHERE plugin_tokens.user_id = users.id AND plugin_tokens.revoked = 0
                       LIMIT 1
                   ) AS plugin_token_last_used_at
            FROM users ORDER BY created_at
            """,
            [],
        )
        for row in rows:
            row["disabled"] = bool(row.get("disabled"))
            row["plugin_token_configured"] = bool(row.get("plugin_token_configured"))
        return rows

    def create_user(self, username: str, password_hash: str, display_name: str, role: str) -> dict[str, Any]:
        user_id = str(uuid.uuid4())
        now = utc_now()
        with self.connect() as connection:
            self._insert(
                connection,
                "users",
                ["id", "username", "password_hash", "display_name", "role", "disabled", "failed_attempts", "created_at", "updated_at"],
                [user_id, username, password_hash, display_name, role, 0, 0, now, now],
            )
        return self.get_user_by_id(user_id) or {}

    def update_user(self, user_id: str, display_name: str, role: str, disabled: bool) -> dict[str, Any] | None:
        self._execute_direct(
            "UPDATE users SET display_name = ?, role = ?, disabled = ?, updated_at = ? WHERE id = ?",
            [display_name, role, int(disabled), utc_now(), user_id],
        )
        if disabled:
            self.revoke_user_sessions(user_id)
            self.revoke_user_plugin_tokens(user_id)
        return self.get_user_by_id(user_id)

    def set_user_password(self, user_id: str, password_hash: str) -> None:
        self._execute_direct(
            "UPDATE users SET password_hash = ?, failed_attempts = 0, lock_until = NULL, updated_at = ? WHERE id = ?",
            [password_hash, utc_now(), user_id],
        )
        self.revoke_user_sessions(user_id)

    def count_enabled_admins(self) -> int:
        row = self._fetchone("SELECT COUNT(*) AS count FROM users WHERE role = ? AND disabled = 0", ["admin"])
        return int(row.get("count") or 0) if row else 0

    def record_login_failure(self, user_id: str) -> None:
        user = self._fetchone("SELECT failed_attempts FROM users WHERE id = ?", [user_id])
        attempts = int(user.get("failed_attempts") or 0) + 1 if user else 1
        lock_until = ""
        if attempts >= 5:
            lock_until = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        self._execute_direct(
            "UPDATE users SET failed_attempts = ?, lock_until = ?, updated_at = ? WHERE id = ?",
            [attempts, lock_until, utc_now(), user_id],
        )

    def reset_login_failures(self, user_id: str) -> None:
        self._execute_direct(
            "UPDATE users SET failed_attempts = 0, lock_until = NULL, updated_at = ? WHERE id = ?",
            [utc_now(), user_id],
        )

    def create_session(self, user_id: str, token_hash: str, expires_at: str) -> None:
        with self.connect() as connection:
            self._insert(
                connection,
                "sessions",
                ["id", "user_id", "token_hash", "expires_at", "revoked", "created_at"],
                [str(uuid.uuid4()), user_id, token_hash, expires_at, 0, utc_now()],
            )

    def get_user_by_session(self, token_hash: str) -> dict[str, Any] | None:
        return self._fetchone(
            """
            SELECT users.* FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.revoked = 0
              AND sessions.expires_at > ? AND users.disabled = 0
            """,
            [token_hash, utc_now()],
        )

    def revoke_session(self, token_hash: str) -> None:
        self._execute_direct("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", [token_hash])

    def revoke_user_sessions(self, user_id: str) -> None:
        self._execute_direct("UPDATE sessions SET revoked = 1 WHERE user_id = ?", [user_id])

    def replace_user_plugin_token(self, user_id: str, token_hash: str, token_prefix: str) -> None:
        now = utc_now()
        with self.connect() as connection:
            self._execute(connection, "UPDATE plugin_tokens SET revoked = 1 WHERE user_id = ?", [user_id])
            self._insert(
                connection,
                "plugin_tokens",
                ["id", "user_id", "token_hash", "token_prefix", "revoked", "created_at"],
                [str(uuid.uuid4()), user_id, token_hash, token_prefix, 0, now],
            )

    def get_user_by_plugin_token(self, token_hash: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = self._fetchone_on(
                connection,
                """
                SELECT users.* FROM plugin_tokens
                JOIN users ON users.id = plugin_tokens.user_id
                WHERE plugin_tokens.token_hash = ? AND plugin_tokens.revoked = 0 AND users.disabled = 0
                """,
                [token_hash],
            )
            if row:
                self._execute(
                    connection,
                    "UPDATE plugin_tokens SET last_used_at = ? WHERE token_hash = ?",
                    [utc_now(), token_hash],
                )
            return row

    def revoke_user_plugin_tokens(self, user_id: str) -> None:
        self._execute_direct("UPDATE plugin_tokens SET revoked = 1 WHERE user_id = ?", [user_id])

    def _fetchone(self, sql: str, params: list[Any]) -> dict[str, Any] | None:
        with self.connect() as connection:
            return self._fetchone_on(connection, sql, params)

    def _fetchone_on(self, connection: Any, sql: str, params: list[Any]) -> dict[str, Any] | None:
        row = self._execute(connection, sql, params).fetchone()
        return dict(row) if row else None

    def _fetchall(self, sql: str, params: list[Any]) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return self._fetchall_on(connection, sql, params)

    def _fetchall_on(self, connection: Any, sql: str, params: list[Any]) -> list[dict[str, Any]]:
        return [dict(row) for row in self._execute(connection, sql, params).fetchall()]

    def _execute_direct(self, sql: str, params: list[Any]) -> None:
        with self.connect() as connection:
            self._execute(connection, sql, params)

    def _execute(self, connection: Any, sql: str, params: list[Any]) -> Any:
        return connection.execute(sql.replace("?", "%s") if self._is_postgres else sql, params)

    def _insert(self, connection: Any, table: str, columns: list[str], values: list[Any]) -> None:
        placeholders = ",".join(["%s" if self._is_postgres else "?"] * len(values))
        connection.execute(f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})", values)

    def _insert_ignore(self, connection: Any, table: str, columns: list[str], values: list[Any]) -> None:
        placeholders = ",".join(["%s" if self._is_postgres else "?"] * len(values))
        prefix = "INSERT" if self._is_postgres else "INSERT OR IGNORE"
        suffix = " ON CONFLICT DO NOTHING" if self._is_postgres else ""
        connection.execute(f"{prefix} INTO {table} ({','.join(columns)}) VALUES ({placeholders}){suffix}", values)

    @staticmethod
    def _decode_json_fields(row: dict[str, Any], fields: list[str]) -> dict[str, Any]:
        result = dict(row)
        for field in fields:
            value = result.get(field)
            if isinstance(value, str) and value:
                try:
                    result[field] = json.loads(value)
                except json.JSONDecodeError:
                    pass
        return result

    def _decode_analysis(self, row: dict[str, Any]) -> dict[str, Any]:
        return self._decode_json_fields(row, ["quick_result", "parsed_message", "result"])

    @staticmethod
    def _analysis_owned_by(item: dict[str, Any], user_id: str = "", username: str = "") -> bool:
        submitted = (item.get("parsed_message") or {}).get("submitted_by") or {}
        return bool(
            (user_id and str(submitted.get("id") or "") == str(user_id))
            or (username and str(submitted.get("username") or "") == str(username))
        )

    @staticmethod
    def _daily_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        counts: dict[str, int] = {}
        for row in rows:
            day = str(row.get("created_at") or "")[:10]
            counts[day] = counts.get(day, 0) + 1
        today = datetime.now(timezone.utc).date()
        days = [(today - timedelta(days=offset)).isoformat() for offset in range(13, -1, -1)]
        return [{"date": day, "count": counts.get(day, 0)} for day in days]


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY, source_name TEXT NOT NULL, status TEXT NOT NULL, risk_level TEXT,
  quick_result TEXT NOT NULL, parsed_message TEXT NOT NULL, result TEXT, raw_path TEXT,
  error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  worker_id TEXT, last_error TEXT, available_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_claim ON tasks(status, available_at);
CREATE TABLE IF NOT EXISTS knowledge (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, source_type TEXT NOT NULL, status TEXT NOT NULL,
  content TEXT NOT NULL, generalized_content TEXT NOT NULL, metadata TEXT NOT NULL, embedding TEXT,
  version INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS knowledge_tasks (
  id TEXT PRIMARY KEY, knowledge_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  worker_id TEXT, last_error TEXT, available_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_tasks_claim ON knowledge_tasks(status, available_at);
CREATE TABLE IF NOT EXISTS policies (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
  details TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, display_name TEXT NOT NULL,
  role TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, failed_attempts INTEGER NOT NULL DEFAULT 0,
  lock_until TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE TABLE IF NOT EXISTS plugin_tokens (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, token_prefix TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_plugin_tokens_hash ON plugin_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_plugin_tokens_user ON plugin_tokens(user_id, revoked);
CREATE TABLE IF NOT EXISTS worker_heartbeats (
  worker_id TEXT PRIMARY KEY, last_seen_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
"""


POSTGRES_SCHEMA = """
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS analyses (
  id UUID PRIMARY KEY, source_name TEXT NOT NULL, status TEXT NOT NULL, risk_level TEXT,
  quick_result JSONB NOT NULL, parsed_message JSONB NOT NULL, result JSONB, raw_path TEXT,
  error TEXT, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
  id UUID PRIMARY KEY, analysis_id UUID NOT NULL REFERENCES analyses(id), status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, worker_id TEXT, last_error TEXT, available_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_claim ON tasks(status, available_at);
CREATE TABLE IF NOT EXISTS knowledge (
  id UUID PRIMARY KEY, title TEXT NOT NULL, source_type TEXT NOT NULL, status TEXT NOT NULL,
  content TEXT NOT NULL, generalized_content TEXT NOT NULL, metadata JSONB NOT NULL, embedding JSONB,
  embedding_vector vector(1024),
  version INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS knowledge_tasks (
  id UUID PRIMARY KEY, knowledge_id UUID NOT NULL REFERENCES knowledge(id), status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, worker_id TEXT, last_error TEXT, available_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_tasks_claim ON knowledge_tasks(status, available_at);
CREATE TABLE IF NOT EXISTS policies (key TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
  details JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, display_name TEXT NOT NULL,
  role TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, failed_attempts INTEGER NOT NULL DEFAULT 0,
  lock_until TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE TABLE IF NOT EXISTS plugin_tokens (
  id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE,
  token_prefix TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL,
  last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_plugin_tokens_hash ON plugin_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_plugin_tokens_user ON plugin_tokens(user_id, revoked);
CREATE TABLE IF NOT EXISTS worker_heartbeats (
  worker_id TEXT PRIMARY KEY, last_seen_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
"""
