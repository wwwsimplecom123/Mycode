from datetime import datetime, timezone
from pathlib import Path
import os
import sys
from tempfile import TemporaryDirectory
import unittest

ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.safe_eml_intake import (
    ATTACHMENT_MAX_ITEMS, BODY_MAX_CHARACTERS, FILE_MAX_BYTES,
    HEADER_LINE_MAX_BYTES, HEADER_TOTAL_MAX_BYTES, MIME_DEPTH_MAX,
    MIME_PART_MAX_ITEMS, RECIPIENT_MAX_ITEMS, URL_MAX_ITEMS,
    SafeEmlIntakeError, SafeEmlReader,
)

NOW = datetime(2026, 8, 10, 9, 0, tzinfo=timezone.utc)


class SafeEmlReaderTests(unittest.TestCase):
    def write(self, root, payload, name="synthetic.eml"):
        path = Path(root) / name
        path.write_bytes(payload)
        return path

    def test_plain_message_is_bounded_observation_with_private_identity(self):
        payload = (b"From: sender@example.test\r\nTo: recipient@example.test\r\n"
                   b"Subject: Synthetic notice\r\nAuthentication-Results: mx.test; spf=pass; dkim=fail; dmarc=none\r\n"
                   b"Content-Type: text/plain; charset=utf-8\r\n\r\nVisit https://example.test/a?token=secret")
        with TemporaryDirectory() as root:
            path = self.write(root, payload, "private-name.EML")
            value = SafeEmlReader().read_explicit(path, observed_at=NOW)
        self.assertEqual("manual_local", value.source_kind)
        self.assertEqual(NOW, value.observed_at)
        self.assertNotIn("private-name", value.source_message_id)
        self.assertNotIn("secret", repr(value.normalized_links))
        self.assertEqual((('spf', 'pass'), ('dkim', 'fail'), ('dmarc', 'none')), value.authentication_observations)

    def test_rejects_unsupported_missing_directory_and_unsafe_lexical_paths(self):
        with TemporaryDirectory() as root:
            cases = ((Path(root)/"x.txt", "unsupported_file"), (Path(root)/"missing.eml", "file_not_found"), (Path(root), "unsupported_file"),
                     (r"\\server\share\x.eml", "unsafe_path"), (r"\\?\C:\x.eml", "unsafe_path"), (r"C:\mail.eml:stream", "unsafe_path"))
            for path, code in cases:
                with self.subTest(path=path), self.assertRaises(SafeEmlIntakeError) as caught:
                    SafeEmlReader().read_explicit(path, observed_at=NOW)
                self.assertEqual(code, caught.exception.code)
                self.assertEqual(code, str(caught.exception))

    def test_rejects_symlink_and_size_over_limit(self):
        with TemporaryDirectory() as root:
            target = self.write(root, b"Subject: x\r\n\r\nbody")
            link = Path(root)/"link.eml"
            try: link.symlink_to(target)
            except OSError: link = None
            if link is not None:
                with self.assertRaises(SafeEmlIntakeError) as caught: SafeEmlReader().read_explicit(link, observed_at=NOW)
                self.assertEqual("unsafe_path", caught.exception.code)
            huge = Path(root)/"huge.eml"
            with huge.open("wb") as stream: stream.truncate(FILE_MAX_BYTES + 1)
            with self.assertRaises(SafeEmlIntakeError) as caught: SafeEmlReader().read_explicit(huge, observed_at=NOW)
            self.assertEqual("file_too_large", caught.exception.code)

    def test_central_limits_are_enforced(self):
        cases = [
            (b"X: "+b"a"*(HEADER_LINE_MAX_BYTES+1)+b"\r\n\r\nx", "mime_limit_exceeded"),
            (b"X: a\r\n"*((HEADER_TOTAL_MAX_BYTES//6)+2)+b"\r\nx", "mime_limit_exceeded"),
            (b"To: "+b", ".join(b"u%d@example.test"%i for i in range(RECIPIENT_MAX_ITEMS+1))+b"\r\n\r\nx", "mime_limit_exceeded"),
        ]
        with TemporaryDirectory() as root:
            for index,(payload,code) in enumerate(cases):
                with self.subTest(index=index), self.assertRaises(SafeEmlIntakeError) as caught:
                    SafeEmlReader().read_explicit(self.write(root,payload,f"x{index}.eml"), observed_at=NOW)
                self.assertEqual(code,caught.exception.code)

    def test_body_urls_parts_depth_and_attachments_are_bounded_and_inert(self):
        boundary="b"
        parts=[]
        for i in range(ATTACHMENT_MAX_ITEMS+1):
            parts.append(f"--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=../../secret{i}.exe\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!\r\n")
        payload=(f"Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n"+"".join(parts)+f"--{boundary}--\r\n").encode()
        with TemporaryDirectory() as root:
            with self.assertRaises(SafeEmlIntakeError) as caught: SafeEmlReader().read_explicit(self.write(root,payload), observed_at=NOW)
            self.assertEqual("mime_limit_exceeded",caught.exception.code)
            html=("Content-Type: text/html; charset=utf-8\r\n\r\n<script>BAD()</script><style>x</style>"+
                  "<img src='https://tracker.test/pixel'>"+" ".join(f"https://x.test/{i}?token=s" for i in range(URL_MAX_ITEMS+10)) + "x"*(BODY_MAX_CHARACTERS+10)).encode()
            value=SafeEmlReader().read_explicit(self.write(root,html,"html.eml"), observed_at=NOW)
            self.assertLessEqual(len(value.sanitized_body_text), BODY_MAX_CHARACTERS)
            self.assertLessEqual(len(value.normalized_links), URL_MAX_ITEMS)
            self.assertNotIn("BAD", value.sanitized_body_text)
            self.assertNotIn("token", repr(value.normalized_links))

    def test_nested_message_attachment_is_not_walked(self):
        payload=(b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: message/rfc822\r\n"
                 b"Content-Disposition: attachment; filename=inner.eml\r\n\r\nSubject: inner\r\n\r\nPRIVATE BODY\r\n--x--\r\n")
        with TemporaryDirectory() as root:
            value=SafeEmlReader().read_explicit(self.write(root,payload), observed_at=NOW)
        self.assertNotIn("PRIVATE", value.sanitized_body_text)
        self.assertNotIn("inner", repr(value.attachment_metadata))


if __name__ == '__main__': unittest.main()
