from dataclasses import dataclass
import json
import struct
from typing import BinaryIO


PROTOCOL_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class NativeLimits:
    frame_bytes: int = 262_144
    source_message_id_characters: int = 128
    subject_characters: int = 512
    address_characters: int = 512
    recipient_items: int = 32
    recipient_characters: int = 256
    body_characters: int = 16_384
    link_items: int = 256
    link_characters: int = 2_048
    attachment_items: int = 128
    attachment_name_characters: int = 512
    attachment_type_characters: int = 255
    attachment_size_characters: int = 64
    language_hint_characters: int = 16


NATIVE_LIMITS = NativeLimits()


class NativeProtocolError(ValueError):
    def __init__(self, error_code: str, *, fatal: bool = False) -> None:
        super().__init__(error_code)
        self.error_code = error_code
        self.fatal = fatal


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise NativeProtocolError("unexpected_eof", fatal=True)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_native_message(stream: BinaryIO) -> dict[str, object] | None:
    header = stream.read(4)
    if header == b"":
        return None
    if len(header) != 4:
        header += _read_exact(stream, 4 - len(header))
    (length,) = struct.unpack("<I", header)
    if length == 0:
        raise NativeProtocolError("invalid_frame_length", fatal=True)
    if length > NATIVE_LIMITS.frame_bytes:
        raise NativeProtocolError("frame_too_large", fatal=True)
    payload = _read_exact(stream, length)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise NativeProtocolError("invalid_utf8") from None

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise NativeProtocolError("invalid_json")
            result[key] = value
        return result

    try:
        message = json.loads(text, object_pairs_hook=unique_object)
    except NativeProtocolError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        raise NativeProtocolError("invalid_json") from None
    if not isinstance(message, dict):
        raise NativeProtocolError("invalid_json")
    return message


def write_native_message(
    stream: BinaryIO,
    message: dict[str, object],
) -> None:
    payload = json.dumps(
        message,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    stream.write(struct.pack("<I", len(payload)))
    stream.write(payload)


__all__ = [
    "NATIVE_LIMITS",
    "PROTOCOL_VERSION",
    "NativeLimits",
    "NativeProtocolError",
    "read_native_message",
    "write_native_message",
]
