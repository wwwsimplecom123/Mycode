from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.domain import MailObservation
from shielddome_endpoint.feature_pipeline import FeaturePipeline


CONFIRMED_AT = datetime(2026, 8, 3, 10, 0, tzinfo=timezone.utc)


def make_vector(*, subject: str = "Routine notice", body: str = "Use the normal company process."):
    observation = MailObservation(
        source_kind="browser_native",
        source_message_id="confirmed-example-fixture",
        subject=subject,
        sender="sender@corp.test",
        reply_to="sender@corp.test",
        recipient_summary=("current-user",),
        sanitized_body_text=body,
        authentication_observations=(
            ("spf", "pass"),
            ("dkim", "pass"),
            ("dmarc", "pass"),
        ),
        normalized_links=(),
        attachment_metadata=(),
        language_hint="en",
        observed_at=CONFIRMED_AT,
    )
    return FeaturePipeline().transform(observation)


class ConfirmedExampleTests(unittest.TestCase):
    def test_record_is_immutable_and_round_trips_canonical_sanitized_features(self):
        from shielddome_endpoint.confirmed_examples import (
            ConfirmedExample,
            ExampleLabel,
            ExampleSource,
        )

        vector = make_vector()
        record = ConfirmedExample.create(
            vector,
            label=ExampleLabel.BENIGN,
            source=ExampleSource.BROWSER_NATIVE,
            confirmed_at=CONFIRMED_AT,
            keyed_fingerprint="a" * 64,
        )

        self.assertEqual(record.feature_vector, vector)
        self.assertEqual(record.schema_version, "1.0")
        self.assertEqual(
            ConfirmedExample.from_json_bytes(record.to_json_bytes()),
            record,
        )
        self.assertEqual(record.to_json_bytes(), record.to_json_bytes())
        with self.assertRaises(FrozenInstanceError):
            record.label = ExampleLabel.PHISHING

    def test_rejects_unknown_fields_illegal_enums_versions_and_raw_text(self):
        from shielddome_endpoint.confirmed_examples import (
            ConfirmedExample,
            ConfirmedExampleValidationError,
            ExampleLabel,
            ExampleSource,
        )

        record = ConfirmedExample.create(
            make_vector(),
            label=ExampleLabel.BENIGN,
            source=ExampleSource.BROWSER_NATIVE,
            confirmed_at=CONFIRMED_AT,
            keyed_fingerprint="b" * 64,
        )
        payload = json.loads(record.to_json_bytes())
        cases = (
            {**payload, "subject": "private subject"},
            {**payload, "label": "unknown"},
            {**payload, "source": "mailbox_auto"},
            {**payload, "schema_version": "future"},
            {**payload, "feature_schema_version": "future"},
            {
                **payload,
                "feature_vector": {
                    **payload["feature_vector"],
                    "text_input": "private body",
                },
            },
            {
                **payload,
                "feature_vector": {
                    **payload["feature_vector"],
                    "categorical_features": [
                        ["sender_domain_state", "private.user@example.test"],
                        *payload["feature_vector"]["categorical_features"][1:],
                    ],
                },
            },
            {
                **payload,
                "feature_vector": {
                    **payload["feature_vector"],
                    "categorical_features": [
                        ["sender_domain_state", "x" * 65],
                        *payload["feature_vector"]["categorical_features"][1:],
                    ],
                },
            },
            {**payload, "keyed_fingerprint": "a" * 65},
        )

        for invalid in cases:
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    ConfirmedExampleValidationError,
                    "^invalid_confirmed_example$",
                ):
                    ConfirmedExample.from_json_bytes(
                        json.dumps(invalid).encode("utf-8")
                    )

    def test_user_confirmation_action_maps_to_label_and_fingerprint_is_user_keyed(self):
        from shielddome_endpoint.confirmed_examples import (
            ConfirmedExampleValidationError,
            ExampleLabel,
            UserConfirmationAction,
            keyed_feature_fingerprint,
            label_for_confirmation_action,
        )

        vector = make_vector()
        first = keyed_feature_fingerprint(vector, b"a" * 32)
        second = keyed_feature_fingerprint(vector, b"b" * 32)

        self.assertEqual(len(first), 64)
        self.assertEqual(first, keyed_feature_fingerprint(vector, b"a" * 32))
        self.assertNotEqual(first, second)
        self.assertIs(
            label_for_confirmation_action(
                UserConfirmationAction.CONFIRM_BENIGN
            ),
            ExampleLabel.BENIGN,
        )
        self.assertIs(
            label_for_confirmation_action(
                UserConfirmationAction.CONFIRM_PHISHING
            ),
            ExampleLabel.PHISHING,
        )
        with self.assertRaisesRegex(
            ConfirmedExampleValidationError,
            "^invalid_confirmation$",
        ):
            label_for_confirmation_action("confirm_benign")


if __name__ == "__main__":
    unittest.main()
