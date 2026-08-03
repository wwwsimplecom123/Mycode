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
            MODEL_ASSESSMENT_SCHEMA_VERSION,
            DetectionExecutionState,
            DetectionOutcome,
            FeatureVector,
            GenericAction,
            MailObservation,
            ModelAssessment,
            ModelConfidenceState,
            ModelExecutionStatus,
            PrivateRuleEvidence,
            RiskLevel,
            RuleAssessment,
            RuleCategory,
            RuleSeverity,
            StructuredPrivateEvidence,
        )

        self.assertIsNotNone(MailObservation)
        self.assertIsNotNone(FeatureVector)
        self.assertIsNotNone(ModelAssessment)
        self.assertIsNotNone(DetectionOutcome)
        self.assertEqual(MAIL_OBSERVATION_SCHEMA_VERSION, "1.0")
        self.assertEqual(FEATURE_SCHEMA_VERSION, "2.0")
        self.assertEqual(MODEL_ASSESSMENT_SCHEMA_VERSION, "1.0")
        self.assertEqual(DETECTION_OUTCOME_SCHEMA_VERSION, "2.0")
        for public_type in (
            DetectionExecutionState,
            GenericAction,
            ModelConfidenceState,
            ModelExecutionStatus,
            PrivateRuleEvidence,
            RiskLevel,
            RuleAssessment,
            RuleCategory,
            RuleSeverity,
            StructuredPrivateEvidence,
        ):
            self.assertIsNotNone(public_type)

    def test_package_reexports_phase_four_a_interfaces(self):
        from shielddome_endpoint import (
            DetectionKernel,
            InferenceContext,
            LocalInference,
            UnavailableModelAdapter,
        )

        for public_type in (
            DetectionKernel,
            InferenceContext,
            LocalInference,
            UnavailableModelAdapter,
        ):
            self.assertIsNotNone(public_type)

    def test_package_reexports_phase_four_a_one_interfaces(self):
        from shielddome_endpoint import (
            FeatureVectorValidationError,
            LocalDetectionService,
            LocalRuleEvaluator,
        )

        for public_type in (
            FeatureVectorValidationError,
            LocalDetectionService,
            LocalRuleEvaluator,
        ):
            self.assertIsNotNone(public_type)

    def test_package_reexports_phase_one_public_interfaces(self):
        from shielddome_endpoint import (
            CORPUS_SCHEMA_VERSION,
            CORPUS_MAX_CANDIDATES,
            FEATURE_ATTACHMENT_MAX_ITEMS,
            FEATURE_AUTHENTICATION_MAX_ITEMS,
            FEATURE_TEXT_MAX_CHARACTERS,
            FEATURE_URL_MAX_ITEMS,
            NEAR_DUPLICATE_FINGERPRINT_VERSION,
            NEAR_DUPLICATE_MAX_CHARACTERS,
            TEXT_HASH_DIMENSION,
            ApprovedCorpusItem,
            AuthorizationStatus,
            CorpusCandidate,
            CorpusGovernance,
            CorpusLabel,
            CorpusManifest,
            CorpusManifestEntry,
            CorpusRejection,
            CorpusSplitPolicy,
            CorpusSnapshot,
            DatasetSplit,
            FeaturePipeline,
            PrivacyScanResult,
            PrivacyScanner,
            PrivacyReviewStatus,
            ReviewStatus,
            SourceLabel,
        )

        self.assertEqual(CORPUS_SCHEMA_VERSION, "3.0")
        self.assertEqual(TEXT_HASH_DIMENSION, 64)
        self.assertEqual(FEATURE_TEXT_MAX_CHARACTERS, 8192)
        self.assertEqual(FEATURE_URL_MAX_ITEMS, 256)
        self.assertEqual(FEATURE_ATTACHMENT_MAX_ITEMS, 256)
        self.assertEqual(FEATURE_AUTHENTICATION_MAX_ITEMS, 64)
        self.assertEqual(NEAR_DUPLICATE_FINGERPRINT_VERSION, "1.0")
        self.assertEqual(NEAR_DUPLICATE_MAX_CHARACTERS, 4096)
        self.assertEqual(CORPUS_MAX_CANDIDATES, 4096)
        for public_type in (
            ApprovedCorpusItem,
            AuthorizationStatus,
            CorpusCandidate,
            CorpusGovernance,
            CorpusLabel,
            CorpusManifest,
            CorpusManifestEntry,
            CorpusRejection,
            CorpusSplitPolicy,
            CorpusSnapshot,
            DatasetSplit,
            FeaturePipeline,
            PrivacyScanResult,
            PrivacyScanner,
            PrivacyReviewStatus,
            ReviewStatus,
            SourceLabel,
        ):
            with self.subTest(public_type=public_type):
                self.assertIsNotNone(public_type)

    def test_package_reexports_phase_five_a_host_seams(self):
        from shielddome_endpoint import NativeHostHandler, run_native_host

        self.assertIsNotNone(NativeHostHandler)
        self.assertIsNotNone(run_native_host)
