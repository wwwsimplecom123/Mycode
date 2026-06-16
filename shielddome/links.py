"""URL and HTML-adjacent link feature helpers."""

from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

from .config import TRUSTED_ROOT_DOMAINS


DOMAIN_RE = re.compile(
    r"(?:(?:https?://)?)([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[/:?#]|$)"
)


def normalize_domain(value: str | None) -> str:
    """Return a lowercase ASCII hostname from an email, URL, or host string."""

    if not value:
        return ""

    raw = value.strip().strip("<>()[]{}'\"")
    if "@" in raw and not raw.startswith(("http://", "https://")):
        address = parseaddr(raw)[1] or raw
        raw = address.rsplit("@", 1)[-1].strip("<>()[]{}'\"")

    if "://" not in raw and "/" in raw:
        raw = f"http://{raw}"

    parsed = urlparse(raw)
    host = parsed.hostname or raw.split("/", 1)[0]
    host = host.strip().lower().strip(".")
    if host.startswith("www."):
        host = host[4:]

    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def is_trusted_domain(domain: str, trusted_roots: set[str] | None = None, include_subdomains: bool = True) -> bool:
    trusted_roots = TRUSTED_ROOT_DOMAINS if trusted_roots is None else trusted_roots
    normalized = normalize_domain(domain)
    if include_subdomains:
        return any(normalized == root or normalized.endswith(f".{root}") for root in trusted_roots)
    return normalized in trusted_roots


def is_internal_network_host(domain: str, trusted_ip_ranges: list[str] | set[str] | None = None) -> bool:
    if not trusted_ip_ranges:
        return False
    normalized = normalize_domain(domain)
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    for value in trusted_ip_ranges:
        try:
            if address in ipaddress.ip_network(str(value).strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def is_valid_web_link(href: str) -> bool:
    raw = str(href or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"", "http", "https"} or raw.count("@") > 1:
        return False
    return bool(normalize_domain(raw))


def infer_display_domain(display_text: str | None) -> str:
    if not display_text:
        return ""
    match = DOMAIN_RE.search(display_text.strip())
    return normalize_domain(match.group(1)) if match else ""


def display_href_mismatch(display_text: str | None, href: str | None) -> bool:
    if urlparse(str(href or "")).scheme.lower() not in {"http", "https"}:
        return False
    display_domain = infer_display_domain(display_text)
    href_domain = normalize_domain(href)
    if not display_domain or not href_domain:
        return False
    if display_domain == href_domain:
        return False
    if href_domain.endswith(f".{display_domain}") or display_domain.endswith(f".{href_domain}"):
        return False
    return True


def structuralize_link(
    link: dict[str, Any],
    trusted_roots: set[str] | None = None,
    trusted_ip_ranges: list[str] | set[str] | None = None,
    trusted_include_subdomains: bool = True,
) -> dict[str, Any]:
    display_text = str(link.get("display_text") or link.get("text") or "").strip()
    href = str(link.get("href") or link.get("url") or "").strip()
    context_before = str(link.get("context_before") or "")[-80:]
    context_after = str(link.get("context_after") or "")[:80]
    href_domain = normalize_domain(href)
    display_domain = infer_display_domain(display_text)
    is_web_link = is_valid_web_link(href)
    internal_network = is_web_link and is_internal_network_host(href_domain, trusted_ip_ranges)
    mismatch = is_web_link and (bool(link.get("display_href_mismatch")) or display_href_mismatch(display_text, href))

    return {
        "display_text": display_text,
        "href": href,
        "href_domain": href_domain,
        "display_domain": display_domain,
        "context_before": context_before,
        "context_after": context_after,
        "display_href_mismatch": mismatch,
        "trusted_href": is_trusted_domain(href_domain, trusted_roots, trusted_include_subdomains) or internal_network,
        "is_web_link": is_web_link,
        "internal_network": internal_network,
        "html_snippet": str(link.get("html_snippet") or "")[:300],
    }


def structuralize_links(
    links: list[dict[str, Any]] | None,
    trusted_roots: set[str] | None = None,
    trusted_ip_ranges: list[str] | set[str] | None = None,
    trusted_include_subdomains: bool = True,
) -> list[dict[str, Any]]:
    return [structuralize_link(link, trusted_roots, trusted_ip_ranges, trusted_include_subdomains) for link in links or []]
