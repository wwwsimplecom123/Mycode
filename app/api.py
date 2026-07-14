"""ShieldDome enterprise FastAPI application."""

from __future__ import annotations

import io
import hashlib
import json
import os
import sys
import time
import zipfile
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from fastapi import Cookie, Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shielddome.enterprise import EnterpriseService  # noqa: E402
from shielddome.permissions import analysis_scope, has_permission  # noqa: E402
from shielddome.settings import SETTINGS  # noqa: E402


SERVICE = EnterpriseService()
WEB_ROOT = ROOT / "web"
EXTENSION_ROOT = ROOT / "extension"
ADMIN_TOKEN = os.getenv("SHIELDDOME_ADMIN_TOKEN", "")
INGEST_TOKEN = os.getenv("SHIELDDOME_INGEST_TOKEN", ADMIN_TOKEN)
LOGIN_RATE_LIMIT: dict[str, deque[float]] = defaultdict(deque)
PLUGIN_RATE_LIMIT: dict[str, deque[float]] = defaultdict(deque)
LOGIN_LIMIT = (10, 15 * 60)
PLUGIN_LIMIT = (120, 60)
PLUGIN_MAX_BODY_BYTES = 256 * 1024
PLUGIN_AUTH_OPTIONAL = os.getenv("SHIELDDOME_PLUGIN_AUTH_OPTIONAL", "").strip().lower() in {"1", "true", "yes", "on"}


app = FastAPI(
    title="ShieldDome Enterprise API",
    version="2.0.0",
    description="企业钓鱼邮件检测、RAG 知识管理与 SOC 复核 API",
)


@app.middleware("http")
async def browser_probe_cors(request: Request, call_next: Any) -> Response:
    """Allow the downloadable probe to call only its dedicated API routes."""
    if request.method == "OPTIONS" and request.url.path.startswith("/api/email/"):
        response = Response(status_code=204)
    else:
        response = await call_next(request)
    if request.url.path.startswith("/api/email/"):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-ShieldDome-Plugin-Token"
    return response


class FeedbackRequest(BaseModel):
    verdict: str = Field(pattern="^(false_positive|confirmed_phishing|uncertain)$")
    comment: str = Field(default="", max_length=1000)


class KnowledgeTextRequest(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    source_type: str
    content: str = Field(min_length=1, max_length=1_000_000)
    metadata: dict[str, Any] = {}


class KnowledgeBulkRequest(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=500)


class PolicyRequest(BaseModel):
    value: Any


class DetectionPolicyRequest(BaseModel):
    trusted_domains: list[str]
    trusted_urls: list[str] = []
    trusted_ip_ranges: list[str]
    blacklisted_domains: list[str]
    high_risk_keywords: list[str]
    risk_thresholds: dict[str, int]
    trusted_include_subdomains: bool = True


class ProviderRequest(BaseModel):
    chat_endpoint: str | None = None
    chat_model: str | None = None
    embedding_endpoint: str | None = None
    embedding_model: str | None = None
    timeout: float | None = None
    api_key: str | None = Field(default=None, max_length=500)
    clear_api_key: bool = False


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=300)

class CreateUserRequest(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9._-]{3,64}$")
    display_name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=300)
    role: str = Field(pattern="^(admin|analyst|auditor)$")


class UpdateUserRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=100)
    role: str = Field(pattern="^(admin|analyst|auditor)$")
    disabled: bool = False


class ResetPasswordRequest(BaseModel):
    password: str = Field(min_length=12, max_length=300)


class ReviewLabelRequest(BaseModel):
    status: str = Field(pattern="^(confirmed|rejected)$")


def bearer_token(authorization: str) -> str:
    prefix = "Bearer "
    return authorization[len(prefix) :].strip() if authorization.startswith(prefix) else ""


def session_token(authorization: str, cookie_token: str) -> str:
    return bearer_token(authorization) or cookie_token


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    return forwarded or (request.client.host if request.client else "unknown")


def check_rate_limit(bucket: dict[str, deque[float]], key: str, limit: int, window_seconds: int) -> bool:
    now = time.monotonic()
    events = bucket[key]
    while events and now - events[0] > window_seconds:
        events.popleft()
    if len(events) >= limit:
        return False
    events.append(now)
    return True


def require_admin(
    authorization: str = Header(default=""),
    x_api_key: str = Header(default=""),
    shielddome_session: str = Cookie(default=""),
) -> str:
    user = SERVICE.auth.authenticate(session_token(authorization, shielddome_session))
    if user and user.get("role") == "admin":
        return str(user["username"])
    if ADMIN_TOKEN and x_api_key == ADMIN_TOKEN:
        return "api-admin"
    raise HTTPException(status_code=401, detail="请先登录或提供有效的管理员 API Key")

def require_console(
    authorization: str = Header(default=""),
    x_api_key: str = Header(default=""),
    shielddome_session: str = Cookie(default=""),
) -> str:
    actor = require_console_actor(authorization, x_api_key, shielddome_session)
    return str(actor["username"])


def require_console_actor(
    authorization: str = Header(default=""),
    x_api_key: str = Header(default=""),
    shielddome_session: str = Cookie(default=""),
) -> dict[str, Any]:
    user = SERVICE.auth.authenticate(session_token(authorization, shielddome_session))
    if user and user.get("role") in {"admin", "analyst", "auditor"}:
        return user
    if ADMIN_TOKEN and x_api_key == ADMIN_TOKEN:
        return {"id": "api-admin", "username": "api-admin", "display_name": "API Admin", "role": "admin"}
    raise HTTPException(status_code=401, detail="请先登录或提供有效的控制台 API Key")


def require_permission(permission: str) -> Callable[..., dict[str, Any]]:
    """Build a FastAPI dependency for one explicit capability."""
    def dependency(
        authorization: str = Header(default=""),
        x_api_key: str = Header(default=""),
        shielddome_session: str = Cookie(default=""),
    ) -> dict[str, Any]:
        actor = require_console_actor(authorization, x_api_key, shielddome_session)
        if not has_permission(actor, permission):
            raise HTTPException(status_code=403, detail=f"缺少操作权限：{permission}")
        return actor

    return dependency


def require_ingest(
    authorization: str = Header(default=""),
    x_api_key: str = Header(default=""),
    shielddome_session: str = Cookie(default=""),
) -> str:
    actor = require_ingest_actor(authorization, x_api_key, shielddome_session)
    return str(actor["username"])


def require_ingest_actor(
    authorization: str = Header(default=""),
    x_api_key: str = Header(default=""),
    shielddome_session: str = Cookie(default=""),
) -> dict[str, Any]:
    user = SERVICE.auth.authenticate(session_token(authorization, shielddome_session))
    if user and has_permission(user, "analysis:create"):
        return user
    if INGEST_TOKEN and x_api_key == INGEST_TOKEN:
        return {
            "id": "api-ingest", "username": "api-ingest", "display_name": "API Ingest",
            "role": "service", "permissions": ["analysis:create"],
        }
    raise HTTPException(status_code=401, detail="请先登录或提供有效的邮件接入 API Key")


def require_browser_probe(x_shielddome_plugin_token: str = Header(default="")) -> dict[str, Any]:
    if x_shielddome_plugin_token:
        token_key = hashlib.sha256(x_shielddome_plugin_token.encode("utf-8")).hexdigest()[:16]
        if not check_rate_limit(PLUGIN_RATE_LIMIT, token_key, *PLUGIN_LIMIT):
            raise HTTPException(status_code=429, detail="插件请求过于频繁，请稍后重试")
    user = SERVICE.auth.authenticate_plugin_token(x_shielddome_plugin_token)
    if user and not has_permission(user, "analysis:create"):
        raise HTTPException(status_code=403, detail="该用户没有邮件检测提交权限")
    if not user and PLUGIN_AUTH_OPTIONAL:
        fallback_key = f"optional:{hashlib.sha256(str(x_shielddome_plugin_token or 'anonymous').encode('utf-8')).hexdigest()[:16]}"
        if not check_rate_limit(PLUGIN_RATE_LIMIT, fallback_key, *PLUGIN_LIMIT):
            raise HTTPException(status_code=429, detail="Plugin requests are too frequent; retry later")
        return {
            "id": "browser-probe-optional",
            "username": "browser-probe",
            "display_name": "Browser Probe",
            "role": "analyst",
            "auth_optional": True,
        }
    if not user:
        raise HTTPException(status_code=401, detail="请配置有效的用户插件 Token")
    return user


def safe_probe_page_url(value: Any) -> str:
    try:
        parsed = urlsplit(str(value or "")[:2000])
        if parsed.scheme not in {"http", "https"}:
            return ""
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))[:500]
    except ValueError:
        return ""


def plugin_content_length(request: Request) -> int:
    try:
        return max(0, int(request.headers.get("content-length") or 0))
    except (TypeError, ValueError):
        return 0


def record_audit_safe(actor: str, action: str, target: str, metadata: dict[str, Any] | None = None) -> None:
    try:
        SERVICE.db.record_audit(actor, action, target, metadata or {})
    except Exception:
        return


def is_global_actor(actor: dict[str, Any]) -> bool:
    return str(actor.get("role") or "") == "admin" or str(actor.get("username") or "") in {"api-admin", "api-ingest"}


def actor_username(actor: dict[str, Any]) -> str:
    return str(actor.get("username") or "")


def ensure_analysis_visible(item: dict[str, Any], actor: dict[str, Any]) -> None:
    if analysis_scope(actor)["kind"] == "all":
        return
    if str(item.get("owner_user_id") or "") == str(actor.get("id") or ""):
        return
    submitted = (item.get("parsed_message") or {}).get("submitted_by") or {}
    if str(submitted.get("id") or "") == str(actor.get("id") or ""):
        return
    if str(submitted.get("username") or "") == actor_username(actor):
        return
    raise HTTPException(status_code=403, detail="无权查看其他用户提交的邮件检测")


@app.get("/api/v1/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "shielddome", "version": app.version, "provider": SERVICE.provider_config()}


@app.post("/api/v1/auth/login")
def login(request: LoginRequest, response: Response, http_request: Request) -> dict[str, Any]:
    key = f"{client_ip(http_request)}:{request.username.strip().lower()}"
    if not check_rate_limit(LOGIN_RATE_LIMIT, key, *LOGIN_LIMIT):
        raise HTTPException(status_code=429, detail="登录尝试过于频繁，请稍后再试")
    try:
        result = SERVICE.auth.login(request.username, request.password)
        response.set_cookie(
            "shielddome_session",
            result["token"],
            max_age=SETTINGS.api_token_ttl_hours * 3600,
            httponly=True,
            secure=http_request.url.scheme == "https",
            samesite="strict",
            path="/",
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.get("/api/v1/auth/me")
def current_user(authorization: str = Header(default=""), shielddome_session: str = Cookie(default="")) -> dict[str, Any]:
    user = SERVICE.auth.authenticate(session_token(authorization, shielddome_session))
    if not user:
        raise HTTPException(status_code=401, detail="登录会话无效或已过期")
    return user


@app.post("/api/v1/auth/logout")
def logout(
    response: Response,
    authorization: str = Header(default=""),
    shielddome_session: str = Cookie(default=""),
) -> dict[str, Any]:
    token = session_token(authorization, shielddome_session)
    if token:
        SERVICE.auth.logout(token)
    response.delete_cookie("shielddome_session", path="/", samesite="strict")
    return {"status": "logged_out"}


@app.post("/api/email/analyze/quick")
def browser_probe_quick(
    payload: dict[str, Any],
    request: Request,
    actor: dict[str, Any] = Depends(require_browser_probe),
) -> dict[str, Any]:
    """Compatibility endpoint used by the downloadable browser probe."""
    content_length = plugin_content_length(request)
    if content_length > PLUGIN_MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="插件提交内容过大")
    if len(str(payload.get("body_text") or "").encode("utf-8")) > 12000 * 4:
        raise HTTPException(status_code=413, detail="邮件正文超出插件检测限制")
    try:
        result = SERVICE.ingest_browser_probe(payload, actor)
        message_id = str(payload.get("message_id") or "")
        record_audit_safe(
            str(actor.get("username") or "browser-probe"),
            "browser_probe.analysis_created",
            str(result.get("analysis_id") or ""),
            {
                "user_id": actor.get("id"),
                "display_name": actor.get("display_name"),
                "message_id_sha256": hashlib.sha256(message_id.encode("utf-8")).hexdigest() if message_id else "",
                "mail_client": str(payload.get("mail_client") or "")[:200],
                "page_url": safe_probe_page_url(payload.get("page_url")),
                "auth_optional": bool(actor.get("auth_optional")),
            },
        )
        result["submitted_by"] = actor
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        record_audit_safe(
            str(actor.get("username") or "browser-probe"),
            "browser_probe.failed",
            "quick",
            {"error": str(exc)[:500], "mail_client": str(payload.get("mail_client") or "")[:200]},
        )
        raise HTTPException(status_code=400, detail=f"插件提交内容无法解析：{str(exc)[:200]}") from exc
@app.get("/api/email/auth/me")
def browser_probe_identity(actor: dict[str, Any] = Depends(require_browser_probe)) -> dict[str, Any]:
    return actor


@app.get("/api/email/analyze/status/{analysis_id}")
def browser_probe_status(analysis_id: str, actor: dict[str, Any] = Depends(require_browser_probe)) -> dict[str, Any]:
    item = SERVICE.db.get_analysis(analysis_id)
    if not item:
        raise HTTPException(status_code=404, detail="Analysis not found")
    parsed = item.get("parsed_message") or {}
    submitted = parsed.get("submitted_by") or {}
    owner_id = str(item.get("owner_user_id") or submitted.get("id") or "")
    if owner_id != str(actor["id"]):
        raise HTTPException(status_code=403, detail="无权查看其他用户提交的插件检测")
    status = str(item.get("status") or "")
    deep_status = {
        "queued": "pending",
        "running": "running",
        "completed": "completed",
        "degraded": "completed",
        "failed": "failed",
    }.get(status, status or "pending")
    return {
        "analysis_id": analysis_id,
        "quick_result": item.get("quick_result"),
        "deep_status": deep_status,
        "deep_result": item.get("result"),
        "submitted_by": actor,
        "error": item.get("error") or "",
    }


@app.get("/api/v1/dashboard")
def dashboard(actor: dict[str, Any] = Depends(require_permission("analysis:read"))) -> dict[str, Any]:
    return SERVICE.db.dashboard_for_scope(analysis_scope(actor))


@app.post("/api/v1/messages/analyze", status_code=202)
async def analyze_message(file: UploadFile = File(...), actor: dict[str, Any] = Depends(require_ingest_actor)) -> dict[str, Any]:
    filename = file.filename or "uploaded.eml"
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")
    try:
        return SERVICE.ingest_eml(filename, await file.read(), actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/analyses")
def list_analyses(page: int = 1, limit: int = 100, actor: dict[str, Any] = Depends(require_permission("analysis:read"))) -> dict[str, Any]:
    page = max(page, 1)
    limit = min(max(limit, 1), 500)
    offset = (page - 1) * limit
    return {"items": SERVICE.db.list_analyses_by_scope(analysis_scope(actor), limit, offset), "page": page, "limit": limit}


@app.get("/api/v1/analyses/{analysis_id}")
def get_analysis(analysis_id: str, actor: dict[str, Any] = Depends(require_permission("analysis:read"))) -> dict[str, Any]:
    item = SERVICE.db.get_analysis(analysis_id)
    if not item:
        raise HTTPException(status_code=404, detail="Analysis not found")
    ensure_analysis_visible(item, actor)
    return item


@app.post("/api/v1/analyses/{analysis_id}/retry")
def retry_analysis(analysis_id: str, actor: dict[str, Any] = Depends(require_permission("analysis:retry"))) -> dict[str, Any]:
    try:
        item = SERVICE.db.get_analysis(analysis_id)
        if not item:
            raise HTTPException(status_code=404, detail="Analysis not found")
        ensure_analysis_visible(item, actor)
        return SERVICE.retry_analysis(analysis_id, actor_username(actor))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/analyses/{analysis_id}/feedback")
def feedback(analysis_id: str, request: FeedbackRequest, actor: dict[str, Any] = Depends(require_permission("analysis:feedback"))) -> dict[str, Any]:
    try:
        item = SERVICE.db.get_analysis(analysis_id)
        if not item:
            raise HTTPException(status_code=404, detail="Analysis not found")
        ensure_analysis_visible(item, actor)
        return SERVICE.feedback(analysis_id, request.verdict, request.comment, actor)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/v1/labels", dependencies=[Depends(require_admin)])
def list_analysis_labels(status: str = "", limit: int = 200) -> dict[str, Any]:
    return {"items": SERVICE.db.list_analysis_labels(status, min(max(limit, 1), 1000))}


@app.post("/api/v1/labels/{label_id}/review")
def review_analysis_label(label_id: str, request: ReviewLabelRequest, actor: str = Depends(require_admin)) -> dict[str, Any]:
    item = SERVICE.db.review_analysis_label(label_id, request.status, actor)
    if not item:
        raise HTTPException(status_code=404, detail="Label not found")
    SERVICE.db.record_audit(actor, "analysis.label_reviewed", label_id, {"status": request.status})
    return item


@app.post("/api/v1/knowledge/import")
async def import_knowledge_file(
    file: UploadFile = File(...),
    source_type: str = Form(...),
    title: str = Form(default=""),
    _actor: str = Depends(require_admin),
) -> dict[str, Any]:
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Knowledge file exceeds 10 MB")
    name = file.filename or "knowledge"
    try:
        if name.lower().endswith(".eml"):
            from shielddome.mail_parser import parse_eml

            parsed = parse_eml(raw)
            content = f"{parsed['subject']}\n{parsed['body_text']}"
        elif name.lower().endswith((".txt", ".md", ".csv")):
            content = raw.decode("utf-8", errors="replace")
        elif name.lower().endswith(".pdf"):
            from pypdf import PdfReader

            content = "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(raw)).pages)
        else:
            raise ValueError("Supported knowledge files: .eml, .txt, .md, .csv, .pdf")
        return SERVICE.import_knowledge(title or name, source_type, content, {"filename": name})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/knowledge/text")
def import_knowledge_text(request: KnowledgeTextRequest, _actor: str = Depends(require_admin)) -> dict[str, Any]:
    return SERVICE.import_knowledge(request.title, request.source_type, request.content, request.metadata)


@app.get("/api/v1/knowledge", dependencies=[Depends(require_permission("knowledge:read"))])
def list_knowledge(
    page: int = 1,
    limit: int = 50,
    status: str = "",
    source_type: str = "",
    q: str = "",
) -> dict[str, Any]:
    page = max(page, 1)
    limit = min(max(limit, 1), 200)
    result = SERVICE.db.list_knowledge_summaries(
        limit=limit,
        offset=(page - 1) * limit,
        status=status,
        source_type=source_type,
        q=q.strip(),
    )
    return {**result, "page": page, "limit": limit, "stats": SERVICE.db.knowledge_stats()}


@app.get("/api/v1/knowledge/{item_id}", dependencies=[Depends(require_permission("knowledge:read"))])
def knowledge_detail(item_id: str) -> dict[str, Any]:
    item = SERVICE.db.get_knowledge(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Knowledge item not found")
    return item


@app.post("/api/v1/knowledge/{item_id}/approve")
def approve_knowledge(item_id: str, _actor: str = Depends(require_admin)) -> dict[str, Any]:
    return SERVICE.approve_knowledge(item_id)


@app.post("/api/v1/knowledge/{item_id}/disable")
def disable_knowledge(item_id: str, _actor: str = Depends(require_admin)) -> dict[str, Any]:
    return SERVICE.disable_knowledge(item_id)


@app.post("/api/v1/knowledge/bulk-approve")
def bulk_approve_knowledge(request: KnowledgeBulkRequest, _actor: str = Depends(require_admin)) -> dict[str, Any]:
    completed = 0
    failed: list[dict[str, str]] = []
    for item_id in request.ids:
        try:
            SERVICE.approve_knowledge(item_id)
            completed += 1
        except Exception as exc:  # pragma: no cover - defensive per-item reporting
            failed.append({"id": item_id, "error": str(exc)})
    return {"requested": len(request.ids), "completed": completed, "failed": failed}


@app.post("/api/v1/knowledge/bulk-disable")
def bulk_disable_knowledge(request: KnowledgeBulkRequest, _actor: str = Depends(require_admin)) -> dict[str, Any]:
    completed = 0
    failed: list[dict[str, str]] = []
    for item_id in request.ids:
        try:
            SERVICE.disable_knowledge(item_id)
            completed += 1
        except Exception as exc:  # pragma: no cover - defensive per-item reporting
            failed.append({"id": item_id, "error": str(exc)})
    return {"requested": len(request.ids), "completed": completed, "failed": failed}


@app.post("/api/v1/knowledge/reindex")
def reindex_knowledge(_actor: str = Depends(require_admin)) -> dict[str, Any]:
    return SERVICE.reindex_knowledge()


@app.get("/api/v1/knowledge/search", dependencies=[Depends(require_admin)])
def search_knowledge(q: str, limit: int = 5) -> dict[str, Any]:
    return {"items": SERVICE.search_knowledge(q, limit)}


@app.get("/api/v1/settings/providers", dependencies=[Depends(require_permission("provider:read"))])
def provider_settings() -> dict[str, Any]:
    return SERVICE.provider_config()


@app.put("/api/v1/settings/providers")
def update_provider_settings(request: ProviderRequest, _actor: str = Depends(require_admin)) -> dict[str, Any]:
    try:
        return SERVICE.configure_provider(request.model_dump(exclude_none=True))
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/settings/providers/test")
def test_provider_settings(_actor: str = Depends(require_admin)) -> dict[str, Any]:
    return SERVICE.test_provider()


@app.get("/api/v1/settings/detection-policy", dependencies=[Depends(require_permission("policy:read"))])
def detection_policy_settings() -> dict[str, Any]:
    return SERVICE.detection_policy()


@app.put("/api/v1/settings/detection-policy")
def update_detection_policy(request: DetectionPolicyRequest, actor: str = Depends(require_admin)) -> dict[str, Any]:
    try:
        return SERVICE.configure_detection_policy(request.model_dump(), actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/policies/{key}", dependencies=[Depends(require_admin)])
def get_policy(key: str) -> dict[str, Any]:
    if key == "provider_secret":
        raise HTTPException(status_code=403, detail="敏感密钥策略不可通过通用策略接口读取")
    return {"key": key, "value": SERVICE.db.get_policy(key)}


@app.put("/api/v1/policies/{key}")
def put_policy(key: str, request: PolicyRequest, _actor: str = Depends(require_admin)) -> dict[str, Any]:
    protected = {
        "provider_secret",
        "trusted_domains",
        "trusted_urls",
        "trusted_ip_ranges",
        "blacklisted_domains",
        "high_risk_keywords",
        "risk_thresholds",
    }
    if key in protected:
        raise HTTPException(status_code=403, detail="该策略必须通过专用设置接口修改")
    SERVICE.db.set_policy(key, request.value)
    SERVICE.db.record_audit("admin", "policy.updated", key)
    return {"key": key, "value": request.value}


@app.get("/api/v1/audit")
def audit(page: int = 1, limit: int = 200, actor: dict[str, Any] = Depends(require_permission("audit:read:self"))) -> dict[str, Any]:
    page = max(page, 1)
    limit = min(max(limit, 1), 1000)
    offset = (page - 1) * limit
    if has_permission(actor, "audit:read:any"):
        return {"items": SERVICE.db.list_audit(limit, offset=offset), "page": page, "limit": limit}
    return {"items": SERVICE.db.list_audit(limit, actor_username(actor), offset), "page": page, "limit": limit}


@app.get("/api/v1/system/status", dependencies=[Depends(require_permission("system:read"))])
def system_status() -> dict[str, Any]:
    return SERVICE.system_status()


@app.get("/api/v1/users", dependencies=[Depends(require_admin)])
def list_users() -> dict[str, Any]:
    return {"items": [SERVICE.auth.public_managed_user(item) for item in SERVICE.db.list_users()]}


@app.post("/api/v1/users", status_code=201)
def create_user(request: CreateUserRequest, actor: str = Depends(require_admin)) -> dict[str, Any]:
    try:
        user = SERVICE.auth.create_user(request.username, request.password, request.display_name, request.role)
        plugin_token = SERVICE.auth.issue_plugin_token(str(user["id"]))
        SERVICE.db.record_audit(actor, "user.created", str(user["id"]), {"username": user["username"], "role": user["role"]})
        SERVICE.db.record_audit(actor, "user.plugin_token_issued", str(user["id"]), {"username": user["username"]})
        return {**user, "plugin_token": plugin_token["token"], "plugin_token_masked": plugin_token["token_masked"]}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.put("/api/v1/users/{user_id}")
def update_user(user_id: str, request: UpdateUserRequest, actor: str = Depends(require_admin)) -> dict[str, Any]:
    target = SERVICE.db.get_user_by_id(user_id)
    if target and target["username"] == actor and request.disabled:
        raise HTTPException(status_code=400, detail="不能停用当前登录账号")
    try:
        user = SERVICE.auth.update_user(user_id, request.display_name, request.role, request.disabled)
        SERVICE.db.record_audit(actor, "user.updated", user_id, {"role": request.role, "disabled": request.disabled})
        return user
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/users/{user_id}/reset-password")
def reset_user_password(user_id: str, request: ResetPasswordRequest, actor: str = Depends(require_admin)) -> dict[str, str]:
    try:
        SERVICE.auth.reset_password(user_id, request.password)
        SERVICE.db.record_audit(actor, "user.password_reset", user_id)
        return {"status": "password_reset"}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/users/{user_id}/plugin-token")
def rotate_user_plugin_token(user_id: str, actor: str = Depends(require_admin)) -> dict[str, str]:
    try:
        issued = SERVICE.auth.issue_plugin_token(user_id)
        SERVICE.db.record_audit(actor, "user.plugin_token_rotated", user_id)
        return issued
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/v1/users/{user_id}/plugin-token")
def revoke_user_plugin_token(user_id: str, actor: str = Depends(require_admin)) -> dict[str, str]:
    try:
        SERVICE.auth.revoke_plugin_token(user_id)
        SERVICE.db.record_audit(actor, "user.plugin_token_revoked", user_id)
        return {"status": "revoked"}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def browser_extension_package() -> tuple[bytes, dict[str, Any]]:
    manifest = json.loads((EXTENSION_ROOT / "manifest.json").read_text(encoding="utf-8"))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(EXTENSION_ROOT.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(EXTENSION_ROOT.parent).as_posix())
    package = output.getvalue()
    return package, {
        "id": "browser-extension",
        "name": manifest.get("name", "ShieldDome 浏览器安全探针"),
        "version": manifest.get("version", "0.0.0"),
        "description": manifest.get("description", ""),
        "platforms": ["Chrome", "Microsoft Edge"],
        "package": "shielddome-browser-extension.zip",
        "sha256": hashlib.sha256(package).hexdigest(),
        "download_url": "/api/v1/apps/browser-extension/download",
        "update_mode": "从 ShieldDome 应用中心下载网站当前最新版",
        "api_compatibility": "ShieldDome Enterprise API 2.x",
    }


@app.get("/api/v1/apps", dependencies=[Depends(require_permission("application:download"))])
def list_apps() -> dict[str, Any]:
    _, application = browser_extension_package()
    return {"items": [application]}


@app.get("/api/v1/apps/browser-extension/download")
def download_browser_extension(_actor: str = Depends(require_console)) -> StreamingResponse:
    package, application = browser_extension_package()
    SERVICE.db.record_audit(_actor, "application.downloaded", "browser-extension", {"version": application["version"]})
    return StreamingResponse(
        io.BytesIO(package),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{application["package"]}"'},
    )


@app.get("/api/v1/openapi.json", include_in_schema=False)
def openapi_json() -> dict[str, Any]:
    return app.openapi()


@app.get("/{path:path}", include_in_schema=False)
def web_app(path: str) -> FileResponse:
    target = (WEB_ROOT / path).resolve() if path else WEB_ROOT / "index.html"
    if WEB_ROOT.resolve() not in target.parents and target != WEB_ROOT.resolve():
        raise HTTPException(status_code=403, detail="Forbidden")
    if target.is_file():
        return FileResponse(target)
    return FileResponse(WEB_ROOT / "index.html")


app.mount("/assets", StaticFiles(directory=WEB_ROOT / "assets", check_dir=False), name="assets")
