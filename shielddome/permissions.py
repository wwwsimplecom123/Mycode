"""Role based permissions and resource data scopes."""

from __future__ import annotations

from typing import Any


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({"*"}),
    "analyst": frozenset({
        "analysis:create", "analysis:read", "analysis:read:self", "analysis:retry", "analysis:feedback",
        "knowledge:read", "policy:read", "provider:read", "audit:read:self",
        "system:read", "application:download",
    }),
    "auditor": frozenset({
        "analysis:read", "analysis:read:any", "knowledge:read", "policy:read", "provider:read",
        "audit:read:self", "audit:read:any", "system:read", "application:download",
    }),
}


def permissions_for_role(role: str) -> list[str]:
    values = ROLE_PERMISSIONS.get(str(role or ""), frozenset())
    return ["*"] if "*" in values else sorted(values)


def has_permission(actor: dict[str, Any] | None, permission: str) -> bool:
    if not actor:
        return False
    permissions = set(actor.get("permissions") or permissions_for_role(str(actor.get("role") or "")))
    return "*" in permissions or permission in permissions


def analysis_scope(actor: dict[str, Any]) -> dict[str, str]:
    configured = str(actor.get("data_scope") or "")
    if configured == "all" or has_permission(actor, "analysis:read:any") or str(actor.get("role") or "") == "admin":
        return {"kind": "all"}
    if configured == "organization" and actor.get("organization_id"):
        return {"kind": "organization", "organization_id": str(actor["organization_id"])}
    if configured == "department" and actor.get("department_id"):
        return {
            "kind": "department",
            "organization_id": str(actor.get("organization_id") or ""),
            "department_id": str(actor["department_id"]),
        }
    return {"kind": "self", "owner_user_id": str(actor.get("id") or "")}
