import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ENDPOINT_ROOT / "src"
ENTRY_POINT = ENDPOINT_ROOT / "packaging" / "native_host_entry.py"
PACKAGED_HOST = ENDPOINT_ROOT / "dist" / "native-host" / "ShieldDomeEndpointHost.exe"
DEVELOPMENT_ORIGIN = "chrome-extension://hchaloelgnennaojaiikeebhajcoccih/"


def frame(message):
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return struct.pack("<I", len(payload)) + payload


def decode_frames(data):
    messages = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise AssertionError("stdout contains a partial Native Messaging header")
        (length,) = struct.unpack("<I", data[offset : offset + 4])
        offset += 4
        payload = data[offset : offset + length]
        if len(payload) != length:
            raise AssertionError("stdout contains a partial Native Messaging payload")
        offset += length
        messages.append(json.loads(payload.decode("utf-8")))
    return messages


def detect_message(source_id="a" * 64, subject="Routine notice", body="Normal process"):
    return {
        "protocol_version": "1.0",
        "message_type": "detect_mail",
        "mail": {
            "source_message_id": source_id,
            "subject": subject,
            "sender": "sender@example.test",
            "reply_to": None,
            "recipient_summary": ["current-user"],
            "sanitized_body_text": body,
            "normalized_links": [],
            "attachment_metadata": [],
            "language_hint": "en",
        },
    }


class _NativeHostProcessContract:
    def host_command(self):
        raise NotImplementedError

    def host_environment(self):
        return os.environ.copy()

    def run_host(self, input_bytes):
        with TemporaryDirectory() as local_app_data:
            environment = self.host_environment()
            environment["LOCALAPPDATA"] = local_app_data
            result = subprocess.run(
                self.host_command(),
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=ENDPOINT_ROOT.parent,
                timeout=20,
                check=False,
            )
        return result, decode_frames(result.stdout)

    def test_ping_and_minimum_detect_mail_use_protocol_stdout(self):
        result, responses = self.run_host(
            frame({"protocol_version": "1.0", "message_type": "ping"})
            + frame(detect_message())
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        self.assertEqual(
            responses[0],
            {"message_type": "pong", "protocol_version": "1.0"},
        )
        self.assertEqual(
            set(responses[1]),
            {"local_event_id", "risk_level", "execution_state", "generic_action"},
        )
        self.assertEqual(responses[1]["risk_level"], "low")
        self.assertEqual(responses[1]["execution_state"], "model_unavailable")
        self.assertEqual(result.stderr, b"")

    def test_consecutive_requests_do_not_leak_previous_mail(self):
        secret_values = (
            "first-private-subject",
            "first-private-body",
            "sender@example.test",
            "current-user",
        )
        result, responses = self.run_host(
            frame(detect_message(subject=secret_values[0], body=secret_values[1]))
            + frame(detect_message(source_id="b" * 64, subject="Second", body="Second body"))
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(responses), 2)
        self.assertNotEqual(responses[0]["local_event_id"], responses[1]["local_event_id"])
        combined = result.stdout + result.stderr
        for value in secret_values:
            self.assertNotIn(value.encode("utf-8"), combined)

    def test_invalid_json_and_unknown_field_return_stable_errors_then_continue(self):
        invalid_json = b'{"private":"mail-body-token"'
        unknown = detect_message()
        unknown["mail"]["Token"] = "mail-body-token"
        result, responses = self.run_host(
            struct.pack("<I", len(invalid_json))
            + invalid_json
            + frame(unknown)
            + frame({"protocol_version": "1.0", "message_type": "ping"})
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            responses,
            [
                {"error_code": "invalid_json"},
                {"error_code": "unknown_field"},
                {"message_type": "pong", "protocol_version": "1.0"},
            ],
        )
        self.assertNotIn(b"mail-body-token", result.stdout + result.stderr)
        self.assertNotIn(b"Traceback", result.stdout)

    def test_invalid_and_oversized_lengths_stop_after_one_error_frame(self):
        cases = (
            (struct.pack("<I", 0), "invalid_frame_length"),
            (struct.pack("<I", 262_145), "frame_too_large"),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected):
                result, responses = self.run_host(payload)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(responses, [{"error_code": expected}])
                self.assertEqual(result.stderr, b"")

    @unittest.skipUnless(sys.platform == "win32", "Windows listener check")
    def test_host_creates_no_tcp_or_udp_socket(self):
        with TemporaryDirectory() as local_app_data:
            environment = self.host_environment()
            environment["LOCALAPPDATA"] = local_app_data
            process = subprocess.Popen(
                self.host_command(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=ENDPOINT_ROOT.parent,
            )
            try:
                time.sleep(0.4)
                check = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        (
                            f"$tcp = @(Get-NetTCPConnection -OwningProcess {process.pid} "
                            "-ErrorAction SilentlyContinue).Count; "
                            f"$udp = @(Get-NetUDPEndpoint -OwningProcess {process.pid} "
                            "-ErrorAction SilentlyContinue).Count; "
                            "'{0},{1}' -f $tcp,$udp"
                        ),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(check.returncode, 0, check.stderr)
                self.assertEqual(check.stdout.strip(), "0,0")
            finally:
                if process.stdin:
                    process.stdin.close()
                process.wait(timeout=10)
                if process.stdout:
                    self.assertEqual(process.stdout.read(), b"")
                    process.stdout.close()
                if process.stderr:
                    self.assertEqual(process.stderr.read(), b"")
                    process.stderr.close()


class SourceNativeHostProcessTests(_NativeHostProcessContract, unittest.TestCase):
    def host_command(self):
        return [sys.executable, str(ENTRY_POINT), DEVELOPMENT_ORIGIN]

    def host_environment(self):
        environment = super().host_environment()
        environment["PYTHONPATH"] = str(SOURCE_ROOT)
        return environment


class PackagedNativeHostProcessTests(_NativeHostProcessContract, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PACKAGED_HOST.is_file():
            raise unittest.SkipTest("packaged Host unavailable")

    def host_command(self):
        return [str(PACKAGED_HOST), DEVELOPMENT_ORIGIN]


if __name__ == "__main__":
    unittest.main()
