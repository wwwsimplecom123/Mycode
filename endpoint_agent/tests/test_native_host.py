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


class RecordingEvidenceStore:
    def __init__(self):
        self.records = []
        self.cleanup_times = []

    def cleanup_expired(self, *, now):
        self.cleanup_times.append(now)
        return 0

    def put(self, record):
        self.records.append(record)


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
        evidence_store = RecordingEvidenceStore()
        handler = NativeHostHandler(
            DEVELOPMENT_EXTENSION_ORIGIN,
            clock=lambda: OBSERVED_AT,
            event_id_factory=lambda: "event-native-test",
            evidence_store_factory=lambda: evidence_store,
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
        self.assertEqual(len(evidence_store.records), 1)
        self.assertEqual(
            evidence_store.records[0].local_event_id,
            "event-native-test",
        )
        self.assertEqual(evidence_store.records[0].source_kind, "browser_native")
        self.assertEqual(evidence_store.cleanup_times, [OBSERVED_AT])

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

    def test_storage_failure_does_not_block_or_leak_the_detection_result(self):
        from shielddome_endpoint.native_host import (
            DEVELOPMENT_EXTENSION_ORIGIN,
            NativeHostHandler,
            run_native_host,
        )

        class FailingEvidenceStore:
            def put(self, _record):
                raise RuntimeError(
                    "private subject body key nonce ciphertext tag traceback"
                )

        output = BytesIO()
        handler = NativeHostHandler(
            DEVELOPMENT_EXTENSION_ORIGIN,
            evidence_store_factory=lambda: FailingEvidenceStore(),
            clock=lambda: OBSERVED_AT,
            event_id_factory=lambda: "event-storage-failure",
        )
        message = detect_message(
            subject="private subject",
            sanitized_body_text="private body",
        )

        run_native_host(BytesIO(frame(message)), output, handler)

        response = decode_frames(output.getvalue())[0]
        self.assertEqual(
            set(response),
            {"local_event_id", "risk_level", "execution_state", "generic_action"},
        )
        for forbidden in (
            b"private subject",
            b"private body",
            b"key",
            b"nonce",
            b"ciphertext",
            b"tag",
            b"traceback",
        ):
            self.assertNotIn(forbidden, output.getvalue().lower())

    def test_consecutive_detections_persist_separate_event_records(self):
        from shielddome_endpoint.native_host import (
            DEVELOPMENT_EXTENSION_ORIGIN,
            NativeHostHandler,
            run_native_host,
        )

        event_ids = iter(("event-first-store", "event-second-store"))
        evidence_store = RecordingEvidenceStore()
        handler = NativeHostHandler(
            DEVELOPMENT_EXTENSION_ORIGIN,
            evidence_store_factory=lambda: evidence_store,
            clock=lambda: OBSERVED_AT,
            event_id_factory=event_ids.__next__,
        )
        second = detect_message(
            attachment_metadata=[
                {
                    "name": "synthetic.pdf.exe",
                    "declared_type": "application/octet-stream",
                    "displayed_size": "1 KB",
                }
            ]
        )
        output = BytesIO()

        run_native_host(
            BytesIO(frame(detect_message()) + frame(second)),
            output,
            handler,
        )

        responses = decode_frames(output.getvalue())
        self.assertEqual(
            tuple(record.local_event_id for record in evidence_store.records),
            ("event-first-store", "event-second-store"),
        )
        self.assertEqual(
            tuple(record.risk_level.value for record in evidence_store.records),
            tuple(response["risk_level"] for response in responses),
        )


if __name__ == "__main__":
    unittest.main()
