"""Role based permissions and resource data scopes."""

from __future__ import annotations

from typing import Any


ROLE_DATA_SCOPES: dict[str, str] = {
    "user": "self",
    "analyst": "team",
    "auditor": "all_readonly",
    "admin": "all",
}


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "user": frozenset({
        "analysis:create", "analysis:read:self",
        "me:dashboard", "me:alerts", "me:mail", "me:plugin_token",
        "application:download",
    }),
    "analyst": frozenset({
        "analysis:create", "analysis:read:self", "analysis:read:team", "analysis:retry",
        "analysis:feedback", "analysis:review",
        "me:plugin_token",
        "knowledge:read:published", "knowledge:draft:create", "knowledge:draft:update:self", "knowledge:submit",
        "policy:read", "provider:read", "audit:read:self", "system:read:summary",
        "application:download",
    }),
    "auditor": frozenset({
        "analysis:read:any", "knowledge:read:published", "policy:read", "provider:read",
        "audit:read:self", "audit:read:any", "audit:export", "system:read:summary",
        "user:read",
    }),
    "admin": frozenset({
        "analysis:create", "analysis:read:self", "analysis:read:team", "analysis:read:any",
        "analysis:retry", "analysis:feedback", "analysis:review",
        "knowledge:read:published", "knowledge:draft:create", "knowledge:draft:update:self",
        "knowledge:submit", "knowledge:approve", "knowledge:disable", "knowledge:reindex",
        "policy:read", "policy:update", "provider:read", "provider:update", "provider:test",
        "user:read", "user:create", "user:update", "user:reset_password", "user:plugin_token",
        "audit:read:self", "audit:read:any", "audit:export",
        "system:read:summary", "system:read:full",
        "application:download", "application:manage", "me:plugin_token", "dangerous:confirm",
    }),
}


COMPATIBILITY_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "analysis:read": ("analysis:read:self", "analysis:read:team", "analysis:read:any"),
    "knowledge:read": ("knowledge:read:published",),
    "system:read": ("system:read:summary", "system:read:full"),
}


def permissions_for_role(role: str) -> list[str]:
    values = ROLE_PERMISSIONS.get(str(role or ""), frozenset())
    return sorted(values)


def default_data_scope_for_role(role: str) -> str:
    return ROLE_DATA_SCOPES.get(str(role or ""), "self")


def has_permission(actor: dict[str, Any] | None, permission: str) -> bool:
    if not actor:
        return False
    permissions = set(actor.get("permissions") or permissions_for_role(str(actor.get("role") or "")))
    if permission in permissions:
        return True
    return any(item in permissions for item in COMPATIBILITY_PERMISSIONS.get(permission, ()))


def is_readonly_actor(actor: dict[str, Any] | None) -> bool:
    if not actor:
        return False
    return str(actor.get("data_scope") or default_data_scope_for_role(str(actor.get("role") or ""))) == "all_readonly"


def analysis_scope(actor: dict[str, Any]) -> dict[str, str]:
    configured = str(actor.get("data_scope") or default_data_scope_for_role(str(actor.get("role") or "")))
    if configured in {"all", "all_readonly"} or has_permission(actor, "analysis:read:any"):
        return {"kind": "all"}
    if configured == "team":
        return {
            "kind": "team",
            "owner_user_id": str(actor.get("id") or ""),
            "assigned_analyst_id": str(actor.get("id") or ""),
            "security_team_id": str(actor.get("security_team_id") or actor.get("department_id") or ""),
        }
    if configured == "organization" and actor.get("organization_id"):
        return {"kind": "organization", "organization_id": str(actor["organization_id"])}
    if configured == "department" and actor.get("department_id"):
        return {
            "kind": "department",
            "organization_id": str(actor.get("organization_id") or ""),
            "department_id": str(actor["department_id"]),
        }
    return {"kind": "self", "owner_user_id": str(actor.get("id") or "")}
