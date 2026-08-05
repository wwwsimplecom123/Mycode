from pathlib import Path
from datetime import timedelta
from dataclasses import replace
import sys
from tempfile import TemporaryDirectory
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from test_confirmed_examples import CONFIRMED_AT, make_vector

from shielddome_endpoint.confirmed_examples import (
    ExampleSource,
    UserConfirmationAction,
)
from shielddome_endpoint.example_store import ExampleStore


class ExampleCalibratorTests(unittest.TestCase):
    def test_invalid_feature_vector_is_rejected_before_store_lookup(self):
        from shielddome_endpoint.example_calibration import ExampleCalibrator

        class EmptyStore:
            def find_exact(self, _feature_vector):
                return ()

            def list_for_calibration(self):
                return ()

        with self.assertRaisesRegex(ValueError, "^invalid_calibration_input$"):
            ExampleCalibrator(EmptyStore()).calibrate(
                replace(make_vector(), text_input="private raw body")
            )

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_one_unconflicted_exact_confirmation_applies_bounded_adjustment(self):
        from shielddome_endpoint.example_calibration import (
            ExampleCalibrationStatus,
            ExampleCalibrator,
        )

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            vector = make_vector()
            store.confirm(
                vector,
                action=UserConfirmationAction.CONFIRM_BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )

            calibration = ExampleCalibrator(store).calibrate(vector)

            self.assertIs(
                calibration.status,
                ExampleCalibrationStatus.EXACT_APPLIED,
            )
            self.assertEqual(calibration.adjustment, -8)
            self.assertEqual(calibration.supporting_examples, 1)

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_conflicting_exact_labels_never_participate_in_calibration(self):
        from shielddome_endpoint.example_calibration import (
            ExampleCalibrationStatus,
            ExampleCalibrator,
        )

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            vector = make_vector()
            for action in (
                UserConfirmationAction.CONFIRM_BENIGN,
                UserConfirmationAction.CONFIRM_PHISHING,
            ):
                store.confirm(
                    vector,
                    action=action,
                    source=ExampleSource.BROWSER_NATIVE,
                    confirmed_at=CONFIRMED_AT,
                )

            calibration = ExampleCalibrator(store).calibrate(vector)

            self.assertIs(
                calibration.status,
                ExampleCalibrationStatus.REJECTED_CONFLICT,
            )
            self.assertEqual(calibration.adjustment, 0)
            self.assertEqual(calibration.supporting_examples, 0)

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_three_distinct_high_similarity_phishing_examples_apply_bounded_risk(self):
        from shielddome_endpoint.example_calibration import (
            ExampleCalibrationStatus,
            ExampleCalibrator,
        )

        body = "routine company process " * 80
        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            for index, subject in enumerate(
                (
                    "Routine notice alpha",
                    "Routine notice beta",
                    "Routine notice gamma",
                )
            ):
                store.confirm(
                    make_vector(subject=subject, body=body),
                    action=UserConfirmationAction.CONFIRM_PHISHING,
                    source=ExampleSource.BROWSER_NATIVE,
                    confirmed_at=CONFIRMED_AT + timedelta(minutes=index),
                )

            calibration = ExampleCalibrator(store).calibrate(
                make_vector(subject="Routine notice target", body=body)
            )

            self.assertIs(
                calibration.status,
                ExampleCalibrationStatus.SIMILAR_APPLIED,
            )
            self.assertEqual(calibration.adjustment, 18)
            self.assertEqual(calibration.supporting_examples, 3)

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_low_similarity_and_insufficient_support_are_rejected(self):
        from shielddome_endpoint.example_calibration import (
            ExampleCalibrationStatus,
            ExampleCalibrator,
        )

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            store.confirm(
                make_vector(
                    subject="Unrelated credential emergency",
                    body="password wire immediately executive login " * 40,
                ),
                action=UserConfirmationAction.CONFIRM_PHISHING,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )
            low = ExampleCalibrator(store).calibrate(
                make_vector(
                    subject="Routine cafeteria menu",
                    body="lunch menu and office shuttle schedule " * 40,
                )
            )

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            body = "routine company process " * 80
            for index in range(2):
                store.confirm(
                    make_vector(subject=f"Routine notice {index}", body=body),
                    action=UserConfirmationAction.CONFIRM_BENIGN,
                    source=ExampleSource.BROWSER_NATIVE,
                    confirmed_at=CONFIRMED_AT + timedelta(minutes=index),
                )
            insufficient = ExampleCalibrator(store).calibrate(
                make_vector(subject="Routine notice target", body=body)
            )

        self.assertIs(
            low.status,
            ExampleCalibrationStatus.REJECTED_LOW_SIMILARITY,
        )
        self.assertEqual(low.adjustment, 0)
        self.assertIs(
            insufficient.status,
            ExampleCalibrationStatus.REJECTED_INSUFFICIENT,
        )
        self.assertEqual(insufficient.adjustment, 0)

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_opposite_labels_among_near_matches_reject_calibration(self):
        from shielddome_endpoint.example_calibration import (
            ExampleCalibrationStatus,
            ExampleCalibrator,
        )

        body = "routine company process " * 80
        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            actions = (
                UserConfirmationAction.CONFIRM_BENIGN,
                UserConfirmationAction.CONFIRM_BENIGN,
                UserConfirmationAction.CONFIRM_PHISHING,
            )
            for index, action in enumerate(actions):
                store.confirm(
                    make_vector(subject=f"Routine notice {index}", body=body),
                    action=action,
                    source=ExampleSource.BROWSER_NATIVE,
                    confirmed_at=CONFIRMED_AT + timedelta(minutes=index),
                )

            calibration = ExampleCalibrator(store).calibrate(
                make_vector(subject="Routine notice target", body=body)
            )

            self.assertIs(
                calibration.status,
                ExampleCalibrationStatus.REJECTED_CONFLICT,
            )
            self.assertEqual(calibration.adjustment, 0)
            self.assertEqual(calibration.supporting_examples, 0)


if __name__ == "__main__":
    unittest.main()
