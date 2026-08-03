from datetime import datetime, timezone
from io import BytesIO
import json
from pathlib import Path
import struct
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

OBSERVED_AT = datetime(2026, 8, 3, 8, 0, tzinfo=timezone.utc)


def frame(message):
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    return struct.pack("<I", len(payload)) + payload


def decode_frames(data):
    from shielddome_endpoint.native_protocol import read_native_message

    stream = BytesIO(data)
    messages = []
    while True:
        message = read_native_message(stream)
        if message is None:
            return messages
        messages.append(message)


def detect_message(**mail_changes):
    mail = {
        "source_message_id": "b" * 64,
        "subject": "Routine notice",
        "sender": "sender@example.test",
        "reply_to": "sender@example.test",
        "recipient_summary": ["current-user"],
        "sanitized_body_text": "Use the normal company process.",
        "normalized_links": [],
        "attachment_metadata": [],
        "language_hint": "en",
    }
    mail.update(mail_changes)
    return {"protocol_version": "1.0", "message_type": "detect_mail", "mail": mail}


class NativeHostTests(unittest.TestCase):
    def test_run_native_host_handles_ping_through_bytesio(self):
        from shielddome_endpoint.native_host import (
            DEVELOPMENT_EXTENSION_ORIGIN,
            NativeHostHandler,
            run_native_host,
        )

        output = BytesIO()
        run_native_host(
            BytesIO(frame({"protocol_version": "1.0", "message_type": "ping"})),
            output,
            NativeHostHandler(DEVELOPMENT_EXTENSION_ORIGIN),
        )

        self.assertEqual(
            decode_frames(output.getvalue()),
            [{"message_type": "pong", "protocol_version": "1.0"}],
        )

    def test_detect_mail_runs_local_detection_and_returns_only_projection(self):
        from shielddome_endpoint.native_host import (
            DEVELOPMENT_EXTENSION_ORIGIN,
            NativeHostHandler,
            run_native_host,
        )

        output = BytesIO()
        handler = NativeHostHandler(
            DEVELOPMENT_EXTENSION_ORIGIN,
            clock=lambda: OBSERVED_AT,
            event_id_factory=lambda: "event-native-test",
        )
        run_native_host(BytesIO(frame(detect_message())), output, handler)

        response = decode_frames(output.getvalue())[0]
        self.assertEqual(
            response,
            {
                "local_event_id": "event-native-test",
                "risk_level": "low",
                "execution_state": "model_unavailable",
                "generic_action": "continue",
            },
        )
        self.assertEqual(
            set(response),
            {"local_event_id", "risk_level", "execution_state", "generic_action"},
        )

    def test_invalid_extension_origin_is_rejected_without_trusting_json(self):
        from shielddome_endpoint.native_host import NativeHostHandler, run_native_host

        message = detect_message()
        message["origin"] = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        output = BytesIO()
        run_native_host(
            BytesIO(frame(message)),
            output,
            NativeHostHandler("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"),
        )

        self.assertEqual(
            decode_frames(output.getvalue()),
            [{"error_code": "invalid_extension_origin"}],
        )

    def test_handler_exception_returns_stable_error_without_exception_text(self):
        from shielddome_endpoint.native_host import run_native_host

        output = BytesIO()

        def failing_handler(_message):
            raise RuntimeError("private body token=fictional-secret")

        run_native_host(
            BytesIO(frame({"protocol_version": "1.0", "message_type": "ping"})),
            output,
            failing_handler,
        )

        self.assertEqual(decode_frames(output.getvalue()), [{"error_code": "handler_error"}])
        self.assertNotIn(b"fictional-secret", output.getvalue())

    def test_protocol_errors_are_framed_and_fatal_oversize_stops_loop(self):
        from shielddome_endpoint.native_host import run_native_host
        from shielddome_endpoint.native_protocol import NATIVE_LIMITS

        output = BytesIO()
        oversized = struct.pack("<I", NATIVE_LIMITS.frame_bytes + 1)
        run_native_host( BytesIO(oversized + frame({"protocol_version": "1.0", "message_type": "ping"})), output, lambda message: message)

        self.assertEqual(decode_frames(output.getvalue()), [{"error_code": "frame_too_large"}])

    def test_multiple_requests_do_not_leak_data_between_responses(self):
        from shielddome_endpoint.native_host import (
            DEVELOPMENT_EXTENSION_ORIGIN,
            NativeHostHandler,
            run_native_host,
        )

        first = detect_message()
        first["mail"]["Token"] = "private-token-value"
        second = {"protocol_version": "1.0", "message_type": "ping"}
        output = BytesIO()
        run_native_host(
            BytesIO(frame(first) + frame(second)),
            output,
            NativeHostHandler(DEVELOPMENT_EXTENSION_ORIGIN),
        )

        self.assertEqual(
            decode_frames(output.getvalue()),
            [
                {"error_code": "unknown_field"},
                {"message_type": "pong", "protocol_version": "1.0"},
            ],
        )
        self.assertNotIn(b"private-token-value", output.getvalue())

    def test_clean_eof_writes_nothing(self):
        from shielddome_endpoint.native_host import run_native_host

        output = BytesIO()
        run_native_host(BytesIO(), output, lambda message: message)
        self.assertEqual(output.getvalue(), b"")


if __name__ == "__main__":
    unittest.main()
