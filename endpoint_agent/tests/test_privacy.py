from dataclasses import fields
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.corpus import (
    CORPUS_SCHEMA_VERSION,
    CorpusCandidate,
    CorpusGovernance,
    CorpusLabel,
    CorpusManifest,
    CorpusManifestEntry,
    DatasetSplit,
    ReviewStatus,
    SourceLabel,
)
from shielddome_endpoint.domain import FEATURE_SCHEMA_VERSION, FeatureVector, MailObservation
from shielddome_endpoint.feature_pipeline import FeaturePipeline
from shielddome_endpoint.privacy import PrivacyScanner


class PrivacyScannerTests(unittest.TestCase):
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
            review_status=ReviewStatus.APPROVED,
            license_source=license_source,
            raw_hash=raw_hash,
            normalized_hash=normalized_hash,
            template_group="safe-template",
            campaign_group="safe-campaign",
            language_group="mixed",
            source_group="synthetic",
            ingested_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            sanitized_training_representation=representation,
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
                "review_status",
                "license_identifier",
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

    def test_scanner_rejects_raw_text_and_bearer_tokens(self):
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
                    item_id="Bearer fictional-token",
                    original_label=SourceLabel.PHISHING,
                    final_label=CorpusLabel.PHISHING,
                    label_source="human-review",
                    review_status=ReviewStatus.APPROVED,
                    license_identifier="company-authorized-synthetic",
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

        self.assertFalse(vector_result.safe)
        self.assertEqual(vector_result.violations, ("raw_text_field",))
        self.assertFalse(manifest_result.safe)
        self.assertEqual(manifest_result.violations, ("credential_assignment",))
