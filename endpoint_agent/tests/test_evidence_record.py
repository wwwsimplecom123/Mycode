from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.domain import MailObservation
from shielddome_endpoint.local_detection import LocalDetectionService


DETECTED_AT = datetime(2026, 8, 3, 9, 0, tzinfo=timezone.utc)


def make_outcome():
    observation = MailObservation(
        source_kind="browser_native",
        source_message_id="a" * 64,
        subject="Routine notice",
        sender="sender@corp.test",
        reply_to="other@outside.test",
        recipient_summary=("current-user",),
        sanitized_body_text="Use the normal company process.",
        authentication_observations=(),
        normalized_links=(),
        attachment_metadata=(),
        language_hint="en",
        observed_at=DETECTED_AT,
    )
    return LocalDetectionService().detect(
        observation,
        local_event_id="event-evidence-record",
        observed_now=DETECTED_AT,
    )


class EndpointEvidenceRecordTests(unittest.TestCase):
    def test_projects_only_structured_detection_evidence(self):
        from shielddome_endpoint.evidence_record import EndpointEvidenceRecord

        outcome = make_outcome()

        record = EndpointEvidenceRecord.from_detection_outcome(
            outcome,
            detected_at=DETECTED_AT,
            source_kind="browser_native",
        )

        self.assertEqual(record.local_event_id, outcome.local_event_id)
        self.assertEqual(record.detected_at, DETECTED_AT)
        self.assertEqual(
            record.retention_until,
            DETECTED_AT + timedelta(days=15),
        )
        self.assertEqual(record.rule_codes, ("sender_reply_domain_mismatch",))
        self.assertTrue(record.degraded)
        self.assertFalse(record.abstained)

    def test_canonical_json_round_trip_preserves_the_record(self):
        from shielddome_endpoint.evidence_record import EndpointEvidenceRecord

        record = EndpointEvidenceRecord.from_detection_outcome(
            make_outcome(),
            detected_at=DETECTED_AT,
            source_kind="browser_native",
        )

        encoded = record.to_json_bytes()

        self.assertEqual(EndpointEvidenceRecord.from_json_bytes(encoded), record)
        self.assertEqual(encoded, record.to_json_bytes())

    def test_rejects_illegal_schema_unknown_fields_and_overlong_values(self):
        from shielddome_endpoint.evidence_record import (
            EndpointEvidenceRecord,
            EvidenceRecordValidationError,
        )

        record = EndpointEvidenceRecord.from_detection_outcome(
            make_outcome(),
            detected_at=DETECTED_AT,
            source_kind="browser_native",
        )
        payload = json.loads(record.to_json_bytes())
        cases = (
            {**payload, "schema_version": "future"},
            {**payload, "subject": "private subject"},
            {**payload, "source_kind": "x" * 33},
            {**payload, "rule_codes": ["x" * 65]},
        )

        for invalid in cases:
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    EvidenceRecordValidationError,
                    "^invalid_evidence_record$",
                ):
                    EndpointEvidenceRecord.from_json_bytes(
                        json.dumps(invalid).encode("utf-8")
                    )


if __name__ == "__main__":
    unittest.main()
