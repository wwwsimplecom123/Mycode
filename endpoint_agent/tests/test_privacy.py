from dataclasses import fields, replace
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.corpus import (
    AuthorizationStatus,
    CORPUS_SCHEMA_VERSION,
    CorpusCandidate,
    CorpusGovernance,
    CorpusLabel,
    CorpusManifest,
    CorpusManifestEntry,
    DatasetSplit,
    PrivacyReviewStatus,
    ReviewStatus,
    SourceLabel,
)
from shielddome_endpoint.domain import (
    FEATURE_SCHEMA_VERSION,
    DetectionExecutionState,
    DetectionOutcome,
    FeatureVector,
    GenericAction,
    PrivateRuleEvidence,
    RiskLevel,
    RuleCategory,
    StructuredPrivateEvidence,
    MailObservation,
)
from shielddome_endpoint.feature_pipeline import FeaturePipeline
from shielddome_endpoint.local_detection import LocalDetectionService
from shielddome_endpoint.privacy import PrivacyScanner
from shielddome_endpoint.rule_evaluator import LocalRuleEvaluator


class PrivacyScannerTests(unittest.TestCase):
    def test_local_rule_and_detection_outputs_do_not_expose_observation_values(self):
        private_values = (
            "Urgent password=fictional-secret CEO request",
            "private.user@example.test",
            "outside.user@outside.test",
            "http://192.0.2.10/login?token=fictional-token",
            "invoice-private.pdf.exe",
            "C:\\Users\\Private\\mail.eml",
        )
        observation = MailObservation(
            source_kind="browser",
            source_message_id="synthetic-private-rules",
            subject=private_values[-1],
            sender=private_values[1],
            reply_to=private_values[2],
            recipient_summary=("current-user",),
            sanitized_body_text=private_values[0],
            authentication_observations=(
                ("spf", "fail"),
                ("dkim", "fail"),
                ("dmarc", "fail"),
            ),
            normalized_links=(private_values[3],),
            attachment_metadata=(("name", private_values[4]),),
            language_hint="en",
            observed_at=datetime(2026, 7, 31, tzinfo=timezone.utc),
        )
        vector = FeaturePipeline().transform(observation)
        rules = LocalRuleEvaluator().evaluate(vector)
        outcome = LocalDetectionService().detect(
            observation,
            local_event_id="event-private-local-rules",
            observed_now=datetime(2026, 7, 31, tzinfo=timezone.utc),
        )

        rule_scan = PrivacyScanner().scan_rule_assessments(
            rules,
            forbidden_values=private_values,
        )
        outcome_scan = PrivacyScanner().scan_detection_outcome(
            outcome,
            forbidden_values=private_values,
        )

        self.assertTrue(rule_scan.safe)
        self.assertEqual(rule_scan.violations, ())
        self.assertTrue(outcome_scan.safe)
        self.assertEqual(outcome_scan.violations, ())
        for private_value in private_values:
            self.assertNotIn(private_value, repr(rules))
            self.assertNotIn(private_value, repr(outcome))

    def test_feature_vector_does_not_expose_mail_or_secret_values(self):
        raw_body = "password=fictional-secret token=fictional-token"
        sender = "private.user@example.test"
        full_url = "https://portal.example.test/login?token=fictional-token"
        observation = MailObservation(
            source_kind="browser",
            source_message_id="synthetic-private-001",
            subject="Synthetic account notice",
            sender=sender,
            reply_to=None,
            recipient_summary=("current-user",),
            sanitized_body_text=raw_body,
            authentication_observations=(),
            normalized_links=(full_url,),
            attachment_metadata=(),
            language_hint="en",
            observed_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
        )

        vector = FeaturePipeline().transform(observation)
        result = PrivacyScanner().scan_feature_vector(
            vector,
            forbidden_values=(raw_body, sender, full_url),
        )

        self.assertIsNone(vector.text_input)
        self.assertTrue(result.safe)
        self.assertEqual(result.violations, ())

    def test_corpus_manifest_omits_candidate_content_and_private_metadata(self):
        representation = (
            "password=fictional-secret token=fictional-token "
            "https://corpus.example.test/item?id=fictional "
            "C:\\Users\\Fictional\\private-mail.eml"
        )
        raw_hash = hashlib.sha256(b"privacy-raw").hexdigest()
        normalized_hash = hashlib.sha256(b"privacy-normalized").hexdigest()
        license_source = "company-authorized-synthetic"
        candidate = CorpusCandidate(
            item_id="safe-item-001",
            final_label=CorpusLabel.PHISHING,
            original_label=SourceLabel.PHISHING,
            label_source="human-review",
            label_guideline_version="label-guide-v1",
            label_evidence_id="label-evidence-safe-001",
            reviewer_id="reviewer-fictional-001",
            reviewed_at=datetime(2026, 7, 29, tzinfo=timezone.utc),
            review_status=ReviewStatus.APPROVED,
            review_policy_version="review-policy-v1",
            license_source=license_source,
            source_dataset_id="dataset-fictional-001",
            source_version="dataset-version-v1",
            source_evidence_digest=hashlib.sha256(
                b"source-evidence-fictional-001"
            ).hexdigest(),
            authorization_basis_id="authorization-fictional-001",
            authorization_status=AuthorizationStatus.ACTIVE,
            internal_training_allowed=True,
            endpoint_weight_distribution_allowed=True,
            authorization_approved_at=datetime(2026, 7, 28, tzinfo=timezone.utc),
            authorization_expires_at=datetime(2027, 7, 30, tzinfo=timezone.utc),
            authorization_no_expiry=False,
            privacy_review_status=PrivacyReviewStatus.APPROVED,
            sanitization_policy_version="sanitization-policy-v1",
            privacy_reviewed_at=datetime(2026, 7, 29, 12, tzinfo=timezone.utc),
            privacy_evidence_digest=hashlib.sha256(
                b"privacy-evidence-fictional-001"
            ).hexdigest(),
            raw_hash=raw_hash,
            normalized_hash=normalized_hash,
            template_group="safe-template",
            campaign_group="safe-campaign",
            language_group="mixed",
            source_group="synthetic",
            ingested_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            sanitized_training_representation=representation,
            sanitized_representation_digest=hashlib.sha256(
                representation.encode("utf-8")
            ).hexdigest(),
        )

        manifest = CorpusGovernance().prepare((candidate,)).manifest
        result = PrivacyScanner().scan_manifest(
            manifest,
            forbidden_values=(
                representation,
                "fictional-secret",
                "fictional-token",
                "https://corpus.example.test/item?id=fictional",
                "C:\\Users\\Fictional\\private-mail.eml",
            ),
        )

        self.assertTrue(result.safe)
        self.assertEqual(result.violations, ())
        self.assertEqual(
            tuple(field.name for field in fields(type(manifest.entries[0]))),
            (
                "item_id",
                "original_label",
                "final_label",
                "label_source",
                "label_guideline_version",
                "label_evidence_id",
                "reviewer_id",
                "reviewed_at_utc",
                "review_status",
                "review_policy_version",
                "license_identifier",
                "source_dataset_id",
                "source_version",
                "source_evidence_digest",
                "authorization_basis_id",
                "authorization_status",
                "internal_training_allowed",
                "endpoint_weight_distribution_allowed",
                "authorization_approved_at_utc",
                "authorization_expires_at_utc",
                "authorization_no_expiry",
                "privacy_review_status",
                "sanitization_policy_version",
                "privacy_reviewed_at_utc",
                "privacy_evidence_digest",
                "ingested_at_utc",
                "raw_content_digest",
                "normalized_content_digest",
                "sanitized_representation_digest",
                "source_group",
                "language_group",
                "template_group",
                "campaign_group",
                "duplicate_group",
                "near_duplicate_group",
                "feature_schema_version",
                "corpus_schema_version",
                "split",
            ),
        )
        self.assertEqual(manifest.entries[0].raw_content_digest, raw_hash)
        self.assertEqual(
            manifest.entries[0].normalized_content_digest,
            normalized_hash,
        )
        self.assertEqual(
            manifest.entries[0].sanitized_representation_digest,
            hashlib.sha256(representation.encode("utf-8")).hexdigest(),
        )
        self.assertNotIn(representation, repr(manifest))

    def test_scanner_returns_only_stable_codes_for_unsafe_structured_fields(self):
        unsafe_vector = FeatureVector(
            numeric_features=(),
            categorical_features=(),
            text_input="synthetic raw body",
            text_vector=(0.0,) * 64,
            missing_value_mask=(),
        )
        unsafe_manifest = CorpusManifest(
            entries=(
                CorpusManifestEntry(
                    item_id="safe-item-unsafe-001",
                    original_label=SourceLabel.PHISHING,
                    final_label=CorpusLabel.PHISHING,
                    label_source="human-review",
                    label_guideline_version="label-guide-v1",
                    label_evidence_id="line-one\nline-two",
                    reviewer_id="fictional.reviewer@example.test",
                    reviewed_at_utc="2026-07-29T00:00:00+00:00",
                    review_status=ReviewStatus.APPROVED,
                    review_policy_version="review-policy-v1",
                    license_identifier="company-authorized-synthetic",
                    source_dataset_id="https://example.test/data?token=fictional",
                    source_version="dataset-version-v1",
                    source_evidence_digest=hashlib.sha256(
                        b"unsafe-source-evidence"
                    ).hexdigest(),
                    authorization_basis_id="password=fictional-secret",
                    authorization_status=AuthorizationStatus.ACTIVE,
                    internal_training_allowed=True,
                    endpoint_weight_distribution_allowed=True,
                    authorization_approved_at_utc="2026-07-28T00:00:00+00:00",
                    authorization_expires_at_utc="2027-07-30T00:00:00+00:00",
                    authorization_no_expiry=False,
                    privacy_review_status=PrivacyReviewStatus.APPROVED,
                    sanitization_policy_version="C:\\Fictional\\policy.txt",
                    privacy_reviewed_at_utc="2026-07-29T12:00:00+00:00",
                    privacy_evidence_digest=hashlib.sha256(
                        b"unsafe-privacy-evidence"
                    ).hexdigest(),
                    ingested_at_utc="2026-07-30T00:00:00+00:00",
                    raw_content_digest=hashlib.sha256(b"unsafe-raw").hexdigest(),
                    normalized_content_digest=hashlib.sha256(
                        b"unsafe-normalized"
                    ).hexdigest(),
                    sanitized_representation_digest=hashlib.sha256(
                        b"unsafe-representation"
                    ).hexdigest(),
                    source_group="synthetic",
                    language_group="mixed",
                    template_group="template-fictional",
                    campaign_group="campaign-fictional",
                    duplicate_group="dup-fictional",
                    near_duplicate_group="near-v1-fictional",
                    feature_schema_version=FEATURE_SCHEMA_VERSION,
                    corpus_schema_version=CORPUS_SCHEMA_VERSION,
                    split=DatasetSplit.TEST,
                ),
            )
        )

        vector_result = PrivacyScanner().scan_feature_vector(unsafe_vector)
        manifest_result = PrivacyScanner().scan_manifest(unsafe_manifest)

        safe_candidate = CorpusCandidate(
            item_id="safe-candidate-001",
            final_label=CorpusLabel.PHISHING,
            original_label=SourceLabel.PHISHING,
            label_source="human-review",
            label_guideline_version="label-guide-v1",
            label_evidence_id="label-evidence-safe-001",
            reviewer_id="reviewer-fictional-001",
            reviewed_at=datetime(2026, 7, 29, tzinfo=timezone.utc),
            review_status=ReviewStatus.APPROVED,
            review_policy_version="review-policy-v1",
            license_source="company-authorized-synthetic",
            source_dataset_id="dataset-fictional-001",
            source_version="dataset-version-v1",
            source_evidence_digest=hashlib.sha256(b"candidate-source").hexdigest(),
            authorization_basis_id="authorization-fictional-001",
            authorization_status=AuthorizationStatus.ACTIVE,
            internal_training_allowed=True,
            endpoint_weight_distribution_allowed=True,
            authorization_approved_at=datetime(2026, 7, 28, tzinfo=timezone.utc),
            authorization_expires_at=datetime(2027, 7, 30, tzinfo=timezone.utc),
            authorization_no_expiry=False,
            privacy_review_status=PrivacyReviewStatus.APPROVED,
            sanitization_policy_version="sanitization-policy-v1",
            privacy_reviewed_at=datetime(2026, 7, 29, 12, tzinfo=timezone.utc),
            privacy_evidence_digest=hashlib.sha256(b"candidate-privacy").hexdigest(),
            raw_hash=hashlib.sha256(b"candidate-raw").hexdigest(),
            normalized_hash=hashlib.sha256(b"candidate-normalized").hexdigest(),
            template_group="template-fictional",
            campaign_group="campaign-fictional",
            language_group="mixed",
            source_group="synthetic",
            ingested_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            sanitized_training_representation="fictional sanitized representation",
            sanitized_representation_digest=hashlib.sha256(
                b"fictional sanitized representation"
            ).hexdigest(),
        )
        unsafe_candidate = replace(
            safe_candidate,
            reviewer_id="fictional.reviewer@example.test",
            source_dataset_id="https://example.test/data?token=fictional",
            authorization_basis_id="token=fictional-token",
            sanitization_policy_version="C:\\Fictional\\policy.txt",
        )
        candidate_result = PrivacyScanner().scan_candidate(unsafe_candidate)

        self.assertFalse(vector_result.safe)
        self.assertEqual(vector_result.violations, ("raw_text_field",))
        self.assertFalse(manifest_result.safe)
        self.assertEqual(
            manifest_result.violations,
            (
                "credential_assignment",
                "email_address",
                "line_break",
                "private_path",
                "url_query",
            ),
        )
        self.assertFalse(candidate_result.safe)
        self.assertEqual(
            candidate_result.violations,
            (
                "credential_assignment",
                "email_address",
                "private_path",
                "url_query",
            ),
        )
        for private_value in (
            "fictional-token",
            "fictional.reviewer@example.test",
            "https://example.test/data?token=fictional",
            "C:\\Fictional\\policy.txt",
        ):
            self.assertNotIn(private_value, repr(manifest_result))
            self.assertNotIn(private_value, repr(candidate_result))

    def test_detection_outcome_scanner_detects_private_structured_values_without_echo(self):
        private_value = (
            "private.user@example.test\n"
            "https://portal.example.test/login?token=fictional "
            "password=fictional C:\\Users\\Private\\model.onnx"
        )
        outcome = DetectionOutcome(
            local_event_id="event-privacy-scan",
            final_risk_score=20,
            risk_level=RiskLevel.LOW,
            generic_action=GenericAction.VERIFY_SENDER,
            execution_state=DetectionExecutionState.RULES_ONLY,
            structured_private_evidence=StructuredPrivateEvidence(
                rule_evidence=(
                    PrivateRuleEvidence(
                        evidence_code=private_value,
                        category=RuleCategory.OTHER,
                        status="active",
                        score_contribution=20,
                        strong_evidence=False,
                    ),
                ),
                rule_score=20,
                model_adjustment=0,
                risk_floor=0,
                model_execution_status=None,
                execution_state=DetectionExecutionState.RULES_ONLY,
                degraded=False,
                error_code=None,
                assessment_schema_version=None,
                model_version=None,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                detection_outcome_schema_version="2.0",
            ),
            minimal_plugin_projection=(
                ("local_event_id", "event-privacy-scan"),
                ("risk_level", "low"),
                ("execution_state", "rules_only"),
                ("generic_action", "verify_sender"),
            ),
            evidence_retention_until=datetime(2026, 8, 14, tzinfo=timezone.utc),
        )

        result = PrivacyScanner().scan_detection_outcome(outcome)

        self.assertFalse(result.safe)
        self.assertEqual(
            result.violations,
            (
                "credential_assignment",
                "email_address",
                "line_break",
                "private_path",
                "url_query",
            ),
        )
        self.assertNotIn(private_value, repr(result))
