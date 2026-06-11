"""Defensive RFC822/EML parsing and static attachment feature extraction."""

from __future__ import annotations

import hashlib
import ipaddress
import io
import re
import zipfile
from email import policy
from email.message import Message
from email.parser import BytesParser
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse


URL_RE = re.compile(r"https?://[^\s<>'\"\])}]+", re.I)
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm"}
SCRIPT_EXTENSIONS = {".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".scr", ".hta"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".msi", ".com", ".jar", ".lnk"} | SCRIPT_EXTENSIONS


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self._href = ""
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href:
            self.links.append({"display_text": "".join(self._text).strip(), "href": self._href})
            self._href = ""
            self._text = []


def parse_eml(raw: bytes) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if disposition == "attachment" or filename:
            attachments.append(analyze_attachment(filename or "unnamed", content_type, payload))
            continue
        if content_type == "text/plain":
            text_parts.append(_decode_part(part, payload))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part, payload))

    body_text = "\n".join(text_parts).strip()
    html = "\n".join(html_parts)
    if not body_text and html:
        body_text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()

    links: list[dict[str, str]] = []
    if html:
        extractor = LinkExtractor()
        extractor.feed(html)
        links.extend(extractor.links)
    known = {_canonical_web_url(link["href"]) for link in links}
    for url in URL_RE.findall(body_text):
        canonical = _canonical_web_url(url)
        if canonical not in known and _valid_extracted_web_url(url):
            links.append({"display_text": url, "href": url})
            known.add(canonical)

    authentication = parse_authentication_results(message)
    return {
        "message_id": str(message.get("Message-ID") or ""),
        "subject": str(message.get("Subject") or ""),
        "sender": str(message.get("From") or ""),
        "reply_to": str(message.get("Reply-To") or ""),
        "return_path": str(message.get("Return-Path") or ""),
        "recipients": [str(value) for value in message.get_all("To", [])],
        "date": str(message.get("Date") or ""),
        "body_text": body_text[:200_000],
        "body_summary": body_text[:4_000],
        "links": links[:200],
        "attachments": attachments[:100],
        "authentication": authentication,
        "headers": {
            "received_count": len(message.get_all("Received", [])),
            "has_list_unsubscribe": bool(message.get("List-Unsubscribe")),
            "x_mailer": str(message.get("X-Mailer") or "")[:200],
        },
    }


def parse_authentication_results(message: Message) -> dict[str, str]:
    combined = " ".join(str(value) for value in message.get_all("Authentication-Results", []))
    result: dict[str, str] = {}
    for name in ("spf", "dkim", "dmarc", "arc"):
        match = re.search(rf"\b{name}\s*=\s*([a-zA-Z_-]+)", combined, re.I)
        result[name] = match.group(1).lower() if match else "unknown"
    return result


def analyze_attachment(filename: str, content_type: str, payload: bytes) -> dict[str, Any]:
    lowered = filename.lower()
    extension = "." + lowered.rsplit(".", 1)[-1] if "." in lowered else ""
    indicators: list[str] = []
    if extension in EXECUTABLE_EXTENSIONS:
        indicators.append("executable_or_script_extension")
    if extension in MACRO_EXTENSIONS:
        indicators.append("macro_enabled_office_document")
    if payload.startswith(b"MZ"):
        indicators.append("portable_executable_magic")
    if b"AutoOpen" in payload or b"Document_Open" in payload or b"Workbook_Open" in payload:
        indicators.append("office_auto_execution_marker")

    archive_entries: list[str] = []
    archive_error = ""
    if zipfile.is_zipfile(io.BytesIO(payload)):
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                archive_entries = archive.namelist()[:100]
                if any(_extension(name) in EXECUTABLE_EXTENSIONS for name in archive_entries):
                    indicators.append("archive_contains_executable")
                if len(archive.infolist()) > 500:
                    indicators.append("archive_many_entries")
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            archive_error = str(exc)[:200]

    return {
        "filename": filename[:300],
        "content_type": content_type,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "extension": extension,
        "indicators": indicators,
        "archive_entries": archive_entries,
        "archive_error": archive_error,
        "external_scan_status": "not_configured",
    }


def _decode_part(part: Message, payload: bytes) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _extension(name: str) -> str:
    return "." + name.lower().rsplit(".", 1)[-1] if "." in name else ""


def _valid_extracted_web_url(value: str) -> bool:
    if value.count("@") > 1:
        return False
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return False
    if "." in parsed.hostname:
        return True
    try:
        ipaddress.ip_address(parsed.hostname)
        return True
    except ValueError:
        return parsed.hostname == "localhost"


def _canonical_web_url(value: str) -> tuple[str, str, int | None, str, str]:
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        port,
        parsed.path.rstrip("/"),
        parsed.query,
    )
