from collections.abc import Callable
from datetime import datetime, timezone
import sys
from typing import BinaryIO
import uuid

from .local_detection import LocalDetectionService
from .native_payload import DetectMailRequest, PingRequest, parse_native_request, to_mail_observation
from .native_protocol import (
    PROTOCOL_VERSION,
    NativeProtocolError,
    read_native_message,
    write_native_message,
)


NATIVE_HOST_NAME = "cn.shielddome.endpoint_agent"
DEVELOPMENT_EXTENSION_ID = "hchaloelgnennaojaiikeebhajcoccih"
DEVELOPMENT_EXTENSION_ORIGIN = (
    f"chrome-extension://{DEVELOPMENT_EXTENSION_ID}/"
)


class NativeHostHandler:
    def __init__(
        self,
        extension_origin: str,
        *,
        detection_service: LocalDetectionService | None = None,
        clock: Callable[[], datetime] | None = None,
        event_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._extension_origin = extension_origin
        self._detection_service = detection_service or LocalDetectionService()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._event_id_factory = event_id_factory or (
            lambda: f"event-{uuid.uuid4()}"
        )

    def __call__(self, message: dict[str, object]) -> dict[str, object]:
        if self._extension_origin != DEVELOPMENT_EXTENSION_ORIGIN:
            raise NativeProtocolError("invalid_extension_origin")
        request = parse_native_request(message)
        if isinstance(request, PingRequest):
            return {"protocol_version": PROTOCOL_VERSION, "message_type": "pong"}
        if isinstance(request, DetectMailRequest):
            observed_at = self._clock()
            observation = to_mail_observation(request, observed_at)
            outcome = self._detection_service.detect(
                observation,
                local_event_id=self._event_id_factory(),
                observed_now=observed_at,
            )
            return dict(outcome.minimal_plugin_projection)
        raise NativeProtocolError("invalid_message")


def run_native_host(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    handler: Callable[[dict[str, object]], dict[str, object]],
) -> None:
    while True:
        try:
            message = read_native_message(input_stream)
        except NativeProtocolError as error:
            write_native_message(output_stream, {"error_code": error.error_code})
            if error.fatal:
                return
            continue
        if message is None:
            return
        try:
            response = handler(message)
        except NativeProtocolError as error:
            response = {"error_code": error.error_code}
        except Exception:
            response = {"error_code": "handler_error"}
        write_native_message(output_stream, response)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv if argv is None else argv
    origin = arguments[1] if len(arguments) > 1 else ""
    run_native_host(
        sys.stdin.buffer,
        sys.stdout.buffer,
        NativeHostHandler(origin),
    )
    return 0


__all__ = [
    "DEVELOPMENT_EXTENSION_ID",
    "DEVELOPMENT_EXTENSION_ORIGIN",
    "NATIVE_HOST_NAME",
    "NativeHostHandler",
    "main",
    "run_native_host",
]


if __name__ == "__main__":
    raise SystemExit(main())
