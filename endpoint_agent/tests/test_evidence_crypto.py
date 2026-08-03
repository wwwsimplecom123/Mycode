from datetime import timezone
from dataclasses import replace
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from test_evidence_record import DETECTED_AT, make_outcome
from shielddome_endpoint.evidence_record import EndpointEvidenceRecord


def make_record():
    return EndpointEvidenceRecord.from_detection_outcome(
        make_outcome(),
        detected_at=DETECTED_AT.astimezone(timezone.utc),
        source_kind="browser_native",
    )


class EvidenceCipherTests(unittest.TestCase):
    def test_same_record_uses_a_fresh_nonce_and_ciphertext_each_time(self):
        from shielddome_endpoint.evidence_crypto import EvidenceCipher

        cipher = EvidenceCipher(b"k" * 32)
        record = make_record()

        first = cipher.encrypt(record, associated_data=b"event-evidence-record")
        second = cipher.encrypt(record, associated_data=b"event-evidence-record")

        self.assertNotEqual(first.nonce, second.nonce)
        self.assertNotEqual(first.ciphertext, second.ciphertext)
        self.assertEqual(
            cipher.decrypt(first, associated_data=b"event-evidence-record"),
            record,
        )
        self.assertEqual(
            cipher.decrypt(second, associated_data=b"event-evidence-record"),
            record,
        )

    def test_tampered_nonce_ciphertext_tag_aad_and_wrong_key_fail_closed(self):
        from shielddome_endpoint.evidence_crypto import (
            EvidenceCipher,
            EvidenceCryptoError,
        )

        cipher = EvidenceCipher(b"k" * 32)
        encrypted = cipher.encrypt(
            make_record(),
            associated_data=b"event-evidence-record",
        )
        cases = (
            (
                cipher,
                replace(
                    encrypted,
                    nonce=bytes([encrypted.nonce[0] ^ 1]) + encrypted.nonce[1:],
                ),
                b"event-evidence-record",
            ),
            (
                cipher,
                replace(
                    encrypted,
                    ciphertext=(
                        bytes([encrypted.ciphertext[0] ^ 1])
                        + encrypted.ciphertext[1:]
                    ),
                ),
                b"event-evidence-record",
            ),
            (
                cipher,
                replace(
                    encrypted,
                    authentication_tag=(
                        bytes([encrypted.authentication_tag[0] ^ 1])
                        + encrypted.authentication_tag[1:]
                    ),
                ),
                b"event-evidence-record",
            ),
            (cipher, encrypted, b"other-event"),
            (EvidenceCipher(b"z" * 32), encrypted, b"event-evidence-record"),
        )

        for decryptor, value, associated_data in cases:
            with self.subTest(associated_data=associated_data):
                with self.assertRaisesRegex(
                    EvidenceCryptoError,
                    "^evidence_decryption_failed$",
                ):
                    decryptor.decrypt(value, associated_data=associated_data)


if __name__ == "__main__":
    unittest.main()
