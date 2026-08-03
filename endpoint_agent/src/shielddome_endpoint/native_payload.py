from dataclasses import dataclass
from datetime import datetime
import re

from .domain import MailObservation
from .native_protocol import NATIVE_LIMITS, PROTOCOL_VERSION, NativeProtocolError


@dataclass(frozen=True, slots=True)
class PingRequest:
    protocol_version: str = PROTOCOL_VERSION
    message_type: str = "ping"


@dataclass(frozen=True, slots=True)
class AttachmentFact:
    name: str
    declared_type: str | None
    displayed_size: str | None


@dataclass(frozen=True, slots=True)
class DetectMailRequest:
    source_message_id: str
    subject: str
    sender: str
    reply_to: str | None
    recipient_summary: tuple[str, ...]
    sanitized_body_text: str
    normalized_links: tuple[str, ...]
    attachment_metadata: tuple[AttachmentFact, ...]
    language_hint: str | None


_ROOT_FIELDS = {"protocol_version", "message_type", "mail"}
_MAIL_FIELDS = {
    "source_message_id",
    "subject",
    "sender",
    "reply_to",
    "recipient_summary",
    "sanitized_body_text",
    "normalized_links",
    "attachment_metadata",
    "language_hint",
}
_ATTACHMENT_FIELDS = {"name", "declared_type", "displayed_size"}
_SOURCE_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_LANGUAGE_HINTS = {"zh", "en", "mixed", "other"}


def _exact_fields(value: dict[str, object], expected: set[str]) -> None:
    actual = set(value)
    if actual - expected:
        raise NativeProtocolError("unknown_field")
    if actual != expected:
        raise NativeProtocolError("invalid_field_type")


def _bounded_string(value: object, limit: int) -> str:
    if not isinstance(value, str):
        raise NativeProtocolError("invalid_field_type")
    if len(value) > limit:
        raise NativeProtocolError("payload_limit_exceeded")
    return value


def _optional_bounded_string(value: object, limit: int) -> str | None:
    if value is None:
        return None
    return _bounded_string(value, limit)


def _string_list(value: object, *, items: int, characters: int) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise NativeProtocolError("invalid_field_type")
    if len(value) > items:
        raise NativeProtocolError("payload_limit_exceeded")
    return tuple(_bounded_string(item, characters) for item in value)


def _attachments(value: object) -> tuple[AttachmentFact, ...]:
    if not isinstance(value, list):
        raise NativeProtocolError("invalid_field_type")
    if len(value) > NATIVE_LIMITS.attachment_items:
        raise NativeProtocolError("payload_limit_exceeded")
    result: list[AttachmentFact] = []
    for item in value:
        if not isinstance(item, dict):
            raise NativeProtocolError("invalid_field_type")
        _exact_fields(item, _ATTACHMENT_FIELDS)
        result.append(
            AttachmentFact(
                name=_bounded_string(
                    item["name"], NATIVE_LIMITS.attachment_name_characters
                ),
                declared_type=_optional_bounded_string(
                    item["declared_type"],
                    NATIVE_LIMITS.attachment_type_characters,
                ),
                displayed_size=_optional_bounded_string(
                    item["displayed_size"],
                    NATIVE_LIMITS.attachment_size_characters,
                ),
            )
        )
    return tuple(result)


def parse_native_request(message: dict[str, object]) -> PingRequest | DetectMailRequest:
    if not isinstance(message, dict):
        raise NativeProtocolError("invalid_message")
    if message.get("protocol_version") != PROTOCOL_VERSION:
        raise NativeProtocolError("unsupported_protocol_version")
    message_type = message.get("message_type")
    if message_type == "ping":
        if set(message) != {"protocol_version", "message_type"}:
            raise NativeProtocolError("unknown_field")
        return PingRequest()
    if message_type == "detect_mail":
        _exact_fields(message, _ROOT_FIELDS)
        mail = message["mail"]
        if not isinstance(mail, dict):
            raise NativeProtocolError("invalid_field_type")
        _exact_fields(mail, _MAIL_FIELDS)
        source_message_id = _bounded_string(
            mail["source_message_id"],
            NATIVE_LIMITS.source_message_id_characters,
        )
        if _SOURCE_DIGEST.fullmatch(source_message_id) is None:
            raise NativeProtocolError("invalid_field_type")
        language_hint = mail["language_hint"]
        if language_hint is not None and language_hint not in _LANGUAGE_HINTS:
            raise NativeProtocolError("invalid_field_type")
        return DetectMailRequest(
            source_message_id=source_message_id,
            subject=_bounded_string(
                mail["subject"], NATIVE_LIMITS.subject_characters
            ),
            sender=_bounded_string(
                mail["sender"], NATIVE_LIMITS.address_characters
            ),
            reply_to=_optional_bounded_string(
                mail["reply_to"], NATIVE_LIMITS.address_characters
            ),
            recipient_summary=_string_list(
                mail["recipient_summary"],
                items=NATIVE_LIMITS.recipient_items,
                characters=NATIVE_LIMITS.recipient_characters,
            ),
            sanitized_body_text=_bounded_string(
                mail["sanitized_body_text"], NATIVE_LIMITS.body_characters
            ),
            normalized_links=_string_list(
                mail["normalized_links"],
                items=NATIVE_LIMITS.link_items,
                characters=NATIVE_LIMITS.link_characters,
            ),
            attachment_metadata=_attachments(mail["attachment_metadata"]),
            language_hint=language_hint,
        )
    raise NativeProtocolError("unknown_message_type")


def to_mail_observation(
    request: DetectMailRequest,
    observed_at: datetime,
) -> MailObservation:
    attachment_pairs: list[tuple[str, str]] = []
    for attachment in request.attachment_metadata:
        attachment_pairs.append(("name", attachment.name))
        if attachment.declared_type is not None:
            attachment_pairs.append(("declared_type", attachment.declared_type))
        if attachment.displayed_size is not None:
            attachment_pairs.append(("displayed_size", attachment.displayed_size))
    return MailObservation(
        source_kind="browser_native",
        source_message_id=request.source_message_id,
        subject=request.subject,
        sender=request.sender,
        reply_to=request.reply_to,
        recipient_summary=request.recipient_summary,
        sanitized_body_text=request.sanitized_body_text,
        authentication_observations=(),
        normalized_links=request.normalized_links,
        attachment_metadata=tuple(attachment_pairs),
        language_hint=request.language_hint,
        observed_at=observed_at,
    )


__all__ = [
    "AttachmentFact",
    "DetectMailRequest",
    "PingRequest",
    "parse_native_request",
    "to_mail_observation",
]
