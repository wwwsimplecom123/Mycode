from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))


class PackageImportTests(unittest.TestCase):
    def test_package_exposes_version(self):
        import shielddome_endpoint

        self.assertEqual(shielddome_endpoint.__version__, "0.1.0")

    def test_package_reexports_public_domain_contracts(self):
        from shielddome_endpoint import (
            DETECTION_OUTCOME_SCHEMA_VERSION,
            FEATURE_SCHEMA_VERSION,
            MAIL_OBSERVATION_SCHEMA_VERSION,
            DetectionOutcome,
            FeatureVector,
            MailObservation,
            ModelAssessment,
        )

        self.assertIsNotNone(MailObservation)
        self.assertIsNotNone(FeatureVector)
        self.assertIsNotNone(ModelAssessment)
        self.assertIsNotNone(DetectionOutcome)
        self.assertEqual(MAIL_OBSERVATION_SCHEMA_VERSION, "1.0")
        self.assertEqual(FEATURE_SCHEMA_VERSION, "1.0")
        self.assertEqual(DETECTION_OUTCOME_SCHEMA_VERSION, "1.0")
