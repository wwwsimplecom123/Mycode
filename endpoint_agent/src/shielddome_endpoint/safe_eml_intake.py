from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
import hashlib
import os
from pathlib import Path, PureWindowsPath
import re
import time
import tracemalloc

from .domain import MailObservation

FILE_MAX_BYTES = 25 * 1024 * 1024
HEADER_TOTAL_MAX_BYTES = 64 * 1024
HEADER_LINE_MAX_BYTES = 8 * 1024
MIME_PART_MAX_ITEMS = 256
MIME_DEPTH_MAX = 16
ATTACHMENT_MAX_ITEMS = 64
RECIPIENT_MAX_ITEMS = 100
BODY_MAX_CHARACTERS = 32 * 1024
URL_MAX_ITEMS = 256
SOURCE_MESSAGE_ID_BYTES = 16
PARSE_TIME_MAX_SECONDS = 5.0
PARSE_MEMORY_MAX_BYTES = 200 * 1024 * 1024
_REPARSE_POINT = 0x400
_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
_STABLE_CODES = frozenset({"unsupported_file", "unsafe_path", "file_not_found", "file_too_large", "mime_limit_exceeded", "malformed_message", "intake_failed"})


class SafeEmlIntakeError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code if code in _STABLE_CODES else "intake_failed")

    @property
    def code(self):
        return self.args[0]


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.values = []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag.casefold() in {"script", "style", "svg", "object", "iframe"}: self.ignored += 1
    def handle_endtag(self, tag):
        if tag.casefold() in {"script", "style", "svg", "object", "iframe"} and self.ignored: self.ignored -= 1
    def handle_data(self, data):
        if not self.ignored and sum(map(len, self.values)) < BODY_MAX_CHARACTERS: self.values.append(data)


def _unsafe_lexical_path(value) -> bool:
    text = os.fspath(value)
    if not isinstance(text, str) or "\x00" in text: return True
    normalized = text.replace("/", "\\")
    if normalized.startswith("\\\\") or normalized.startswith("\\?\\") or normalized.startswith("\\.\\"): return True
    drive, tail = os.path.splitdrive(text)
    return ":" in tail or (not drive and PureWindowsPath(text).drive.startswith("\\"))


def _headers_end(payload: bytes) -> int:
    positions = [p for marker in (b"\r\n\r\n", b"\n\n") if (p := payload.find(marker)) >= 0]
    return min(positions) if positions else len(payload)


def _validate_headers(payload: bytes):
    header = payload[:_headers_end(payload)]
    if len(header) > HEADER_TOTAL_MAX_BYTES: raise SafeEmlIntakeError("mime_limit_exceeded")
    if any(len(line) > HEADER_LINE_MAX_BYTES for line in header.splitlines()): raise SafeEmlIntakeError("mime_limit_exceeded")


def _decode_text(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try: return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeError): return payload.decode("utf-8", errors="replace")


def _safe_url(value: str) -> str | None:
    bounded = value.rstrip(".,);]").split("#", 1)[0].split("?", 1)[0]
    scheme, separator, remainder = bounded.partition("://")
    if not separator or scheme.casefold() not in {"http", "https"}: return None
    authority = re.split(r"[/\\]", remainder, maxsplit=1)[0]
    if not authority or any(character.isspace() for character in authority): return None
    return f"{scheme.casefold()}://{remainder}"


def _extension_metadata(part):
    filename = part.get_filename()
    suffix = Path(str(filename or "").replace("\\", "/").rsplit("/", 1)[-1]).suffix.casefold()
    safe_name = "attachment" + suffix if re.fullmatch(r"\.[a-z0-9]{1,16}", suffix) else "attachment"
    values = [("name", safe_name), ("content_type", part.get_content_type()), ("disposition", part.get_content_disposition() or "attachment")]
    declared = part.get("Content-Length")
    if declared and str(declared).strip().isdigit(): values.append(("declared_size", str(min(int(declared), FILE_MAX_BYTES))))
    return tuple(values)


class SafeEmlReader:
    def read_explicit(self, path, *, observed_at: datetime) -> MailObservation:
        if not isinstance(observed_at, datetime) or observed_at.tzinfo is None or observed_at.utcoffset() is None: raise SafeEmlIntakeError("intake_failed")
        if _unsafe_lexical_path(path): raise SafeEmlIntakeError("unsafe_path")
        candidate = Path(path)
        if candidate.suffix.casefold() != ".eml": raise SafeEmlIntakeError("unsupported_file")
        try: before = candidate.lstat()
        except FileNotFoundError: raise SafeEmlIntakeError("file_not_found") from None
        except OSError: raise SafeEmlIntakeError("unsafe_path") from None
        if candidate.is_symlink() or getattr(before, "st_file_attributes", 0) & _REPARSE_POINT: raise SafeEmlIntakeError("unsafe_path")
        if not candidate.is_file(): raise SafeEmlIntakeError("unsupported_file")
        if before.st_size > FILE_MAX_BYTES: raise SafeEmlIntakeError("file_too_large")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(candidate, flags)
            try:
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size): raise SafeEmlIntakeError("unsafe_path")
                with os.fdopen(descriptor, "rb", closefd=False) as stream: payload = stream.read(FILE_MAX_BYTES + 1)
            finally: os.close(descriptor)
            after = candidate.lstat()
        except SafeEmlIntakeError: raise
        except FileNotFoundError: raise SafeEmlIntakeError("file_not_found") from None
        except OSError: raise SafeEmlIntakeError("unsafe_path") from None
        if len(payload) > FILE_MAX_BYTES: raise SafeEmlIntakeError("file_too_large")
        if (after.st_dev, after.st_ino, after.st_size) != (opened.st_dev, opened.st_ino, opened.st_size): raise SafeEmlIntakeError("unsafe_path")
        _validate_headers(payload)
        parse_started = time.perf_counter()
        owns_trace = not tracemalloc.is_tracing()
        if owns_trace: tracemalloc.start()
        memory_before = tracemalloc.get_traced_memory()[0] if owns_trace else 0
        try:
            message = BytesParser(policy=policy.default).parsebytes(payload)
            memory_peak = tracemalloc.get_traced_memory()[1] - memory_before if owns_trace else 0
        except Exception: raise SafeEmlIntakeError("malformed_message") from None
        finally:
            if owns_trace: tracemalloc.stop()
        if time.perf_counter() - parse_started > PARSE_TIME_MAX_SECONDS or memory_peak > PARSE_MEMORY_MAX_BYTES:
            raise SafeEmlIntakeError("mime_limit_exceeded")
        recipients = tuple(address for _, address in getaddresses(message.get_all("to", []) + message.get_all("cc", [])) if address)
        if len(recipients) > RECIPIENT_MAX_ITEMS: raise SafeEmlIntakeError("mime_limit_exceeded")
        bodies=[]; attachments=[]; part_count=0
        stack=[(message, 0)]
        while stack:
            if time.perf_counter() - parse_started > PARSE_TIME_MAX_SECONDS: raise SafeEmlIntakeError("mime_limit_exceeded")
            part, depth = stack.pop(); part_count += 1
            if part_count > MIME_PART_MAX_ITEMS or depth > MIME_DEPTH_MAX: raise SafeEmlIntakeError("mime_limit_exceeded")
            disposition = part.get_content_disposition()
            nested = part.get_content_type() == "message/rfc822"
            if disposition == "attachment" or part.get_filename() is not None or nested:
                attachments.extend(_extension_metadata(part))
                if sum(1 for name,_ in attachments if name == "name") > ATTACHMENT_MAX_ITEMS: raise SafeEmlIntakeError("mime_limit_exceeded")
                continue
            if part.is_multipart():
                children = part.get_payload()
                if not isinstance(children, list): raise SafeEmlIntakeError("malformed_message")
                stack.extend((child, depth+1) for child in reversed(children))
                continue
            if part.get_content_type() in {"text/plain", "text/html"} and sum(map(len,bodies)) < BODY_MAX_CHARACTERS:
                text=_decode_text(part)
                if part.get_content_type() == "text/html":
                    parser=_TextExtractor()
                    try: parser.feed(text); text=" ".join(parser.values)
                    except Exception: text=""
                bodies.append(text[:BODY_MAX_CHARACTERS-sum(map(len,bodies))])
        body=re.sub(r"\s+", " ", " ".join(bodies)).strip()[:BODY_MAX_CHARACTERS]
        links=[]
        for match in _URL.finditer(" ".join([body] + bodies)):
            safe=_safe_url(match.group(0))
            if safe and safe not in links: links.append(safe)
            if len(links) >= URL_MAX_ITEMS: break
        auth_text=" ".join(message.get_all("authentication-results", []) + message.get_all("received-spf", []))
        auth=[]
        for name in ("spf","dkim","dmarc"):
            found=re.search(rf"(?i)\b{name}\s*=\s*([a-z]+)",auth_text)
            if found: auth.append((name,found.group(1).casefold()))
        identity="local-"+hashlib.sha256(payload).hexdigest()[:SOURCE_MESSAGE_ID_BYTES*2]
        return MailObservation(source_kind="manual_local", source_message_id=identity, subject=str(message.get("subject", ""))[:8192], sender=str(message.get("from", ""))[:8192], reply_to=(str(message.get("reply-to"))[:8192] if message.get("reply-to") else None), recipient_summary=recipients, sanitized_body_text=body, authentication_observations=tuple(auth), normalized_links=tuple(links), attachment_metadata=tuple(attachments), language_hint=None, observed_at=observed_at)


__all__ = ["ATTACHMENT_MAX_ITEMS", "BODY_MAX_CHARACTERS", "FILE_MAX_BYTES", "HEADER_LINE_MAX_BYTES", "HEADER_TOTAL_MAX_BYTES", "MIME_DEPTH_MAX", "MIME_PART_MAX_ITEMS", "PARSE_MEMORY_MAX_BYTES", "PARSE_TIME_MAX_SECONDS", "RECIPIENT_MAX_ITEMS", "URL_MAX_ITEMS", "SafeEmlIntakeError", "SafeEmlReader"]
