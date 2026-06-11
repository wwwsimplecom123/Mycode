"""Local account password hashing and session authentication."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from .settings import SETTINGS
from .storage import Database


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(derived).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=base64.urlsafe_b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=32,
        )
        return hmac.compare_digest(derived, base64.urlsafe_b64decode(expected))
    except (ValueError, TypeError):
        return False


class AuthService:
    ROLES = {"admin", "analyst", "auditor"}

    def __init__(self, database: Database):
        self.db = database

    def bootstrap_admin(self) -> None:
        self.db.create_user_if_missing(
            SETTINGS.bootstrap_admin_username,
            hash_password(SETTINGS.bootstrap_admin_password),
            "系统管理员",
            "admin",
        )

    def login(self, username: str, password: str) -> dict[str, Any]:
        user = self.db.get_user_by_username(username)
        if not user or bool(user.get("disabled")):
            raise PermissionError("用户名或密码错误")
        lock_until = str(user.get("lock_until") or "")
        if lock_until and lock_until > datetime.now(timezone.utc).isoformat():
            raise PermissionError("登录失败次数过多，请稍后重试")
        if not verify_password(password, str(user.get("password_hash") or "")):
            self.db.record_login_failure(user["id"])
            raise PermissionError("用户名或密码错误")

        self.db.reset_login_failures(user["id"])
        token = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + timedelta(hours=SETTINGS.api_token_ttl_hours)
        self.db.create_session(user["id"], self._token_hash(token), expires.isoformat())
        self.db.record_audit(username, "auth.login", user["id"])
        return {"token": token, "expires_at": expires.isoformat(), "user": self.public_user(user)}

    def authenticate(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        user = self.db.get_user_by_session(self._token_hash(token))
        return self.public_user(user) if user else None

    def authenticate_plugin_token(self, token: str) -> dict[str, Any] | None:
        if not token or not token.startswith("sdp_"):
            return None
        user = self.db.get_user_by_plugin_token(self._token_hash(token))
        return self.public_user(user) if user else None

    def logout(self, token: str) -> None:
        self.db.revoke_session(self._token_hash(token))

    def create_user(self, username: str, password: str, display_name: str, role: str) -> dict[str, Any]:
        normalized = username.strip().lower()
        if role not in self.ROLES:
            raise ValueError("不支持的用户角色")
        if self.db.get_user_by_username(normalized):
            raise ValueError("用户名已存在")
        user = self.db.create_user(normalized, hash_password(password), display_name.strip(), role)
        return self.public_managed_user(user)

    def update_user(self, user_id: str, display_name: str, role: str, disabled: bool) -> dict[str, Any]:
        user = self.db.get_user_by_id(user_id)
        if not user:
            raise KeyError("用户不存在")
        if role not in self.ROLES:
            raise ValueError("不支持的用户角色")
        if user["role"] == "admin" and (role != "admin" or disabled) and self.db.count_enabled_admins() <= 1:
            raise ValueError("不能停用或降级最后一个可用管理员")
        updated = self.db.update_user(user_id, display_name.strip(), role, disabled)
        return self.public_managed_user(updated or {})

    def reset_password(self, user_id: str, password: str) -> None:
        if not self.db.get_user_by_id(user_id):
            raise KeyError("用户不存在")
        self.db.set_user_password(user_id, hash_password(password))

    def issue_plugin_token(self, user_id: str) -> dict[str, str]:
        user = self.db.get_user_by_id(user_id)
        if not user:
            raise KeyError("用户不存在")
        if bool(user.get("disabled")):
            raise ValueError("不能为已停用用户签发插件 Token")
        token = f"sdp_{secrets.token_urlsafe(32)}"
        prefix = token[:12]
        self.db.replace_user_plugin_token(user_id, self._token_hash(token), prefix)
        return {"token": token, "token_masked": f"{prefix}..."}

    def revoke_plugin_token(self, user_id: str) -> None:
        if not self.db.get_user_by_id(user_id):
            raise KeyError("用户不存在")
        self.db.revoke_user_plugin_tokens(user_id)

    @staticmethod
    def public_user(user: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
        }

    @staticmethod
    def public_managed_user(user: dict[str, Any]) -> dict[str, Any]:
        return {
            key: user.get(key)
            for key in (
                "id",
                "username",
                "display_name",
                "role",
                "disabled",
                "failed_attempts",
                "lock_until",
                "created_at",
                "updated_at",
                "plugin_token_configured",
                "plugin_token_prefix",
                "plugin_token_last_used_at",
            )
        }

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
