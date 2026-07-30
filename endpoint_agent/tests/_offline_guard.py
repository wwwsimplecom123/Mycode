import ast
from pathlib import Path
import re
import tomllib


FORBIDDEN_IMPORT_ROOTS = frozenset(
    {
        "aiohttp",
        "fastapi",
        "flask",
        "ftplib",
        "http",
        "httpx",
        "imaplib",
        "poplib",
        "requests",
        "smtplib",
        "socket",
        "socketserver",
        "starlette",
        "telnetlib",
        "urllib",
        "uvicorn",
        "websocket",
        "websockets",
    }
)
FORBIDDEN_DISTRIBUTIONS = frozenset(
    {
        "aiohttp",
        "fastapi",
        "flask",
        "httpx",
        "requests",
        "starlette",
        "uvicorn",
        "websocket-client",
        "websockets",
    }
)
NETWORK_URL_PREFIXES = ("http://", "https://", "ws://", "wss://")


def _dependency_name(requirement: str) -> str:
    name = re.split(r"[\s\[<>=!~;]", requirement, maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", name).lower()


def scan_offline_violations(
    source_root: Path,
    pyproject_path: Path,
) -> tuple[str, ...]:
    violations: list[str] = []

    for source_path in sorted(source_root.rglob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        relative_path = source_path.relative_to(source_root)
        for node in ast.walk(tree):
            imported_roots: tuple[str, ...] = ()
            if isinstance(node, ast.Import):
                imported_roots = tuple(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots = (node.module.split(".", 1)[0],)

            for imported_root in imported_roots:
                if imported_root in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(
                        f"{relative_path}: forbidden import {imported_root}"
                    )

            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.lower().startswith(NETWORK_URL_PREFIXES):
                    violations.append(f"{relative_path}: forbidden network URL literal")

    configuration = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    dependencies = configuration.get("project", {}).get("dependencies", [])
    for dependency in dependencies:
        dependency_name = _dependency_name(dependency)
        if dependency_name in FORBIDDEN_DISTRIBUTIONS:
            violations.append(f"pyproject.toml: forbidden dependency {dependency_name}")

    return tuple(sorted(violations))
