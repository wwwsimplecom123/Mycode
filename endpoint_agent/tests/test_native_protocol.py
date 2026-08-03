from io import BytesIO
import json
from pathlib import Path
import struct
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))


class SegmentedBytesIO(BytesIO):
    def read(self, size=-1):
        if size < 0:
            size = 1
        return super().read(min(size, 1))


class NativeProtocolTests(unittest.TestCase):
    def test_reads_normal_little_endian_utf8_json_frame(self):
        from shielddome_endpoint.native_protocol import read_native_message

        payload = json.dumps(
            {"protocol_version": "1.0", "message_type": "ping"},
            ensure_ascii=False,
        ).encode("utf-8")
        stream = BytesIO(struct.pack("<I", len(payload)) + payload)

        self.assertEqual(
            read_native_message(stream),
            {"protocol_version": "1.0", "message_type": "ping"},
        )

    def test_reads_segmented_header_and_payload(self):
        from shielddome_endpoint.native_protocol import read_native_message

        payload = b'{"protocol_version":"1.0","message_type":"ping"}'
        stream = SegmentedBytesIO(struct.pack("<I", len(payload)) + payload)

        self.assertEqual(read_native_message(stream)["message_type"], "ping")

    def test_clean_eof_returns_none(self):
        from shielddome_endpoint.native_protocol import read_native_message

        self.assertIsNone(read_native_message(BytesIO()))

    def test_partial_frame_is_fatal_unexpected_eof(self):
        from shielddome_endpoint.native_protocol import (
            NativeProtocolError,
            read_native_message,
        )

        for framed in (b"\x01\x00", struct.pack("<I", 12) + b"short"):
            with self.subTest(framed=framed):
                with self.assertRaises(NativeProtocolError) as caught:
                    read_native_message(BytesIO(framed))
                self.assertEqual(caught.exception.error_code, "unexpected_eof")
                self.assertTrue(caught.exception.fatal)

    def test_rejects_zero_and_oversized_frame_lengths_before_payload_read(self):
        from shielddome_endpoint.native_protocol import (
            NATIVE_LIMITS,
            NativeProtocolError,
            read_native_message,
        )

        cases = ((0, "invalid_frame_length"), (NATIVE_LIMITS.frame_bytes + 1, "frame_too_large"))
        for length, expected in cases:
            with self.subTest(length=length):
                with self.assertRaises(NativeProtocolError) as caught:
                    read_native_message(BytesIO(struct.pack("<I", length)))
                self.assertEqual(caught.exception.error_code, expected)
                self.assertTrue(caught.exception.fatal)

    def test_rejects_invalid_utf8_json_root_and_duplicate_keys(self):
        from shielddome_endpoint.native_protocol import (
            NativeProtocolError,
            read_native_message,
        )

        cases = (
            (b"\xff", "invalid_utf8"),
            (b"{broken", "invalid_json"),
            (b"[]", "invalid_json"),
            (b'{"a":1,"a":2}', "invalid_json"),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected):
                frame = struct.pack("<I", len(payload)) + payload
                with self.assertRaises(NativeProtocolError) as caught:
                    read_native_message(BytesIO(frame))
                self.assertEqual(caught.exception.error_code, expected)
                self.assertEqual(str(caught.exception), expected)
                decoded_payload = payload.decode("utf-8", "ignore")
                if decoded_payload:
                    self.assertNotIn(decoded_payload, repr(caught.exception))

    def test_writes_one_deterministic_protocol_frame(self):
        from shielddome_endpoint.native_protocol import write_native_message

        output = BytesIO()
        write_native_message(output, {"message_type": "pong", "protocol_version": "1.0"})

        framed = output.getvalue()
        (length,) = struct.unpack("<I", framed[:4])
        self.assertEqual(length, len(framed[4:]))
        self.assertEqual(
            framed[4:],
            b'{"message_type":"pong","protocol_version":"1.0"}',
        )


if __name__ == "__main__":
    unittest.main()
