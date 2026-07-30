from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.corpus import (
    AuthorizationStatus,
    CORPUS_SCHEMA_VERSION,
    CORPUS_MAX_CANDIDATES,
    CorpusCandidate,
    CorpusGovernance,
    CorpusLabel,
    CorpusRejection,
    CorpusSplitPolicy,
    DatasetSplit,
    PrivacyReviewStatus,
    ReviewStatus,
    SourceLabel,
)
from shielddome_endpoint.domain import FEATURE_SCHEMA_VERSION


def make_candidate(item_id: str = "item-001", **changes) -> CorpusCandidate:
    ingested_at = changes.get(
        "ingested_at",
        datetime(2026, 7, 30, tzinfo=timezone.utc),
    )
    timeline_anchor = (
        ingested_at
        if isinstance(ingested_at, datetime)
        else datetime(2026, 7, 30, tzinfo=timezone.utc)
    )
    values = dict(
        item_id=item_id,
        final_label=CorpusLabel.PHISHING,
        original_label=SourceLabel.PHISHING,
        label_source="human-review",
        label_guideline_version="label-guide-v1",
        label_evidence_id=f"label-evidence-{item_id}",
        reviewer_id="reviewer-fictional-001",
        reviewed_at=timeline_anchor - timedelta(days=1),
        review_status=ReviewStatus.APPROVED,
        review_policy_version="review-policy-v1",
        license_source="company-authorized-synthetic",
        source_dataset_id="dataset-fictional-001",
        source_version="dataset-version-v1",
        source_evidence_digest=synthetic_digest("source-evidence-fictional-001"),
        authorization_basis_id="authorization-fictional-001",
        authorization_status=AuthorizationStatus.ACTIVE,
        internal_training_allowed=True,
        endpoint_weight_distribution_allowed=True,
        authorization_approved_at=timeline_anchor - timedelta(days=2),
        authorization_expires_at=timeline_anchor + timedelta(days=365),
        authorization_no_expiry=False,
        privacy_review_status=PrivacyReviewStatus.APPROVED,
        sanitization_policy_version="sanitization-policy-v1",
        privacy_reviewed_at=timeline_anchor - timedelta(hours=12),
        privacy_evidence_digest=synthetic_digest("privacy-evidence-fictional-001"),
        raw_hash=synthetic_digest(f"raw:{item_id}"),
        normalized_hash=synthetic_digest(f"normalized:{item_id}"),
        template_group=f"template-{item_id}",
        campaign_group=f"campaign-{item_id}",
        language_group="mixed",
        source_group="synthetic",
        ingested_at=ingested_at,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        sanitized_training_representation=f"synthetic representation {item_id}",
    )
    values.update(changes)
    if "sanitized_representation_digest" not in changes:
        values["sanitized_representation_digest"] = synthetic_digest(
            values["sanitized_training_representation"]
        )
    return CorpusCandidate(**values)


def synthetic_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class CorpusGovernanceTests(unittest.TestCase):
    def test_prepare_requires_approved_privacy_review_and_sanitization_evidence(self):
        candidates = (
            make_candidate(
                "invalid-privacy-digest",
                privacy_evidence_digest="privacy-evidence",
            ),
            make_candidate(
                "invalid-privacy-review-time",
                privacy_reviewed_at=datetime(2026, 7, 29),
            ),
            make_candidate(
                "invalid-sanitization-policy",
                sanitization_policy_version="https://example.test/policy",
            ),
            make_candidate(
                "invalid-sanitized-digest",
                sanitized_representation_digest="B" * 64,
            ),
            make_candidate(
                "mismatched-sanitized-digest",
                sanitized_representation_digest=synthetic_digest("different-value"),
            ),
            make_candidate(
                "missing-privacy-review-time",
                privacy_reviewed_at=None,
            ),
            make_candidate(
                "missing-sanitization-policy",
                sanitization_policy_version="",
            ),
            make_candidate(
                "missing-sanitized-representation",
                sanitized_training_representation=None,
                sanitized_representation_digest=synthetic_digest(
                    "unused-fictional-representation"
                ),
            ),
            make_candidate(
                "privacy-review-future",
                privacy_reviewed_at=datetime(2026, 7, 31, tzinfo=timezone.utc),
            ),
            make_candidate(
                "privacy-review-pending",
                privacy_review_status=PrivacyReviewStatus.PENDING,
            ),
        )

        snapshot = CorpusGovernance().prepare(candidates)

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("invalid-privacy-digest", "invalid_privacy_evidence_digest"),
                ("invalid-privacy-review-time", "invalid_privacy_review_time"),
                (
                    "invalid-sanitization-policy",
                    "invalid_sanitization_policy_version",
                ),
                (
                    "invalid-sanitized-digest",
                    "invalid_sanitized_representation_digest",
                ),
                (
                    "mismatched-sanitized-digest",
                    "sanitized_representation_digest_mismatch",
                ),
                ("missing-privacy-review-time", "invalid_privacy_review_time"),
                (
                    "missing-sanitization-policy",
                    "missing_sanitization_policy_version",
                ),
                ("missing-sanitized-representation", "missing_metadata"),
                ("privacy-review-future", "invalid_privacy_review_time"),
                ("privacy-review-pending", "privacy_not_approved"),
            ),
        )

    def test_prepare_rejects_invalid_or_expired_authorization_times(self):
        candidates = (
            make_candidate(
                "authorization-expired",
                authorization_expires_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
            ),
            make_candidate(
                "authorization-expired-before",
                authorization_expires_at=datetime(2026, 7, 29, tzinfo=timezone.utc),
            ),
            make_candidate(
                "authorization-future-approval",
                authorization_approved_at=datetime(2026, 7, 31, tzinfo=timezone.utc),
            ),
            make_candidate(
                "authorization-naive-approval",
                authorization_approved_at=datetime(2026, 7, 28),
            ),
            make_candidate(
                "authorization-naive-expiry",
                authorization_expires_at=datetime(2027, 7, 30),
            ),
            make_candidate(
                "authorization-no-expiry-conflict",
                authorization_no_expiry=True,
            ),
            make_candidate(
                "authorization-no-expiry-unspecified",
                authorization_no_expiry=None,
            ),
            make_candidate(
                "authorization-missing-approval",
                authorization_approved_at=None,
            ),
            make_candidate(
                "authorization-missing-expiry",
                authorization_expires_at=None,
            ),
        )

        snapshot = CorpusGovernance().prepare(candidates)

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("authorization-expired", "authorization_expired"),
                ("authorization-expired-before", "authorization_expired"),
                (
                    "authorization-future-approval",
                    "invalid_authorization_approval_time",
                ),
                (
                    "authorization-missing-approval",
                    "invalid_authorization_approval_time",
                ),
                ("authorization-missing-expiry", "missing_authorization_expiry"),
                (
                    "authorization-naive-approval",
                    "invalid_authorization_approval_time",
                ),
                (
                    "authorization-naive-expiry",
                    "invalid_authorization_expiry",
                ),
                (
                    "authorization-no-expiry-conflict",
                    "conflicting_authorization_expiry",
                ),
                (
                    "authorization-no-expiry-unspecified",
                    "conflicting_authorization_expiry",
                ),
            ),
        )

    def test_prepare_admits_explicit_perpetual_authorization(self):
        candidate = make_candidate(
            "authorization-perpetual",
            authorization_expires_at=None,
            authorization_no_expiry=True,
        )

        snapshot = CorpusGovernance().prepare((candidate,))

        self.assertEqual(
            tuple(item.candidate.item_id for item in snapshot.approved_items),
            ("authorization-perpetual",),
        )

    def test_prepare_requires_safe_source_and_authorization_evidence(self):
        candidates = (
            make_candidate(
                "authorization-inactive",
                authorization_status=AuthorizationStatus.PENDING,
            ),
            make_candidate(
                "invalid-authorization-basis",
                authorization_basis_id="authorization=fictional-secret",
            ),
            make_candidate(
                "invalid-source-dataset",
                source_dataset_id="https://example.test/dataset",
            ),
            make_candidate(
                "invalid-source-digest",
                source_evidence_digest="A" * 64,
            ),
            make_candidate("invalid-source-version", source_version="bad\nversion"),
            make_candidate("missing-authorization-basis", authorization_basis_id=""),
            make_candidate("missing-source-dataset", source_dataset_id=""),
            make_candidate("missing-source-version", source_version=""),
        )

        snapshot = CorpusGovernance().prepare(candidates)

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("authorization-inactive", "authorization_not_active"),
                ("invalid-authorization-basis", "invalid_authorization_basis_id"),
                ("invalid-source-dataset", "invalid_source_dataset_id"),
                ("invalid-source-digest", "invalid_source_evidence_digest"),
                ("invalid-source-version", "invalid_source_version"),
                ("missing-authorization-basis", "missing_authorization_basis_id"),
                ("missing-source-dataset", "missing_source_dataset_id"),
                ("missing-source-version", "missing_source_version"),
            ),
        )

    def test_prepare_requires_separate_explicit_training_and_distribution_rights(self):
        active = make_candidate("active-authorization")
        approved = make_candidate(
            "approved-authorization",
            authorization_status=AuthorizationStatus.APPROVED,
        )
        distribution_denied = make_candidate(
            "distribution-denied",
            endpoint_weight_distribution_allowed=False,
        )
        distribution_unspecified = make_candidate(
            "distribution-unspecified",
            endpoint_weight_distribution_allowed=None,
        )
        training_denied = make_candidate(
            "training-denied",
            internal_training_allowed=False,
        )
        training_unspecified = make_candidate(
            "training-unspecified",
            internal_training_allowed=None,
        )

        snapshot = CorpusGovernance().prepare(
            (
                distribution_unspecified,
                training_denied,
                active,
                distribution_denied,
                approved,
                training_unspecified,
            )
        )

        self.assertEqual(
            tuple(item.candidate.item_id for item in snapshot.approved_items),
            ("active-authorization", "approved-authorization"),
        )
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("distribution-denied", "endpoint_weight_distribution_not_allowed"),
                (
                    "distribution-unspecified",
                    "endpoint_weight_distribution_not_allowed",
                ),
                ("training-denied", "internal_training_not_allowed"),
                ("training-unspecified", "internal_training_not_allowed"),
            ),
        )

    def test_prepare_requires_safe_complete_human_review_governance(self):
        candidates = (
            make_candidate(
                "credential-like-label-evidence",
                label_evidence_id="token:fictional-value",
            ),
            make_candidate(
                "invalid-label-guideline",
                label_guideline_version="C:\\Fictional\\guide.txt",
            ),
            make_candidate("invalid-label-evidence", label_evidence_id="bad\nvalue"),
            make_candidate("invalid-review-policy", review_policy_version="x" * 129),
            make_candidate("invalid-reviewed-at", reviewed_at=datetime(2026, 7, 29)),
            make_candidate("invalid-reviewer", reviewer_id="https://example.test/reviewer"),
            make_candidate("missing-label-evidence", label_evidence_id=""),
            make_candidate("missing-label-guideline", label_guideline_version=""),
            make_candidate("missing-review-policy", review_policy_version=""),
            make_candidate("missing-reviewed-at", reviewed_at=None),
            make_candidate("missing-reviewer", reviewer_id=""),
            make_candidate(
                "reviewed-after-admission",
                reviewed_at=datetime(2026, 7, 31, tzinfo=timezone.utc),
            ),
        )

        snapshot = CorpusGovernance().prepare(candidates)

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("credential-like-label-evidence", "invalid_label_evidence_id"),
                ("invalid-label-evidence", "invalid_label_evidence_id"),
                ("invalid-label-guideline", "invalid_label_guideline_version"),
                ("invalid-review-policy", "invalid_review_policy_version"),
                ("invalid-reviewed-at", "invalid_review_time"),
                ("invalid-reviewer", "invalid_reviewer_id"),
                ("missing-label-evidence", "missing_label_evidence_id"),
                ("missing-label-guideline", "missing_label_guideline_version"),
                ("missing-review-policy", "missing_review_policy_version"),
                ("missing-reviewed-at", "invalid_review_time"),
                ("missing-reviewer", "missing_reviewer_id"),
                ("reviewed-after-admission", "invalid_review_time"),
            ),
        )

    def test_conservative_near_duplicates_share_group_and_split(self):
        first_representation = (
            "Invoice notice reference 202607300001 is ready at "
            "https://billing.example.test/invoice/202607300001?session=alpha"
        )
        second_representation = (
            "Invoice notice reference 202607309999 is ready at "
            "https://billing.example.test/invoice/202607309999?session=beta"
        )
        first = make_candidate(
            "near-first",
            normalized_hash=synthetic_digest("near-first-normalized"),
            template_group="near-first-template",
            campaign_group="near-first-campaign",
            sanitized_training_representation=first_representation,
        )
        second = make_candidate(
            "near-second",
            normalized_hash=synthetic_digest("near-second-normalized"),
            template_group="near-second-template",
            campaign_group="near-second-campaign",
            source_group="held-out-source",
            sanitized_training_representation=second_representation,
        )

        snapshot = CorpusGovernance().prepare(
            (second, first),
            split_policy=CorpusSplitPolicy(
                test_source_groups=("held-out-source",)
            ),
        )

        self.assertEqual(len(snapshot.approved_items), 2)
        self.assertEqual(
            {item.near_duplicate_group for item in snapshot.approved_items},
            {snapshot.approved_items[0].near_duplicate_group},
        )
        self.assertTrue(
            snapshot.approved_items[0].near_duplicate_group.startswith("near-v1-")
        )
        self.assertEqual(
            {item.split for item in snapshot.approved_items},
            {DatasetSplit.TEST},
        )
        self.assertNotIn(first_representation, repr(snapshot.manifest))
        self.assertNotIn(second_representation, repr(snapshot.manifest))

    def test_near_duplicate_fingerprint_keeps_clearly_different_samples_apart(self):
        credential_notice = make_candidate(
            "clearly-different-credential",
            sanitized_training_representation=(
                "Account credential verification notice for the employee portal."
            ),
        )
        facilities_notice = make_candidate(
            "clearly-different-facilities",
            sanitized_training_representation=(
                "The west office elevator inspection is scheduled for Friday."
            ),
        )

        snapshot = CorpusGovernance().prepare(
            (facilities_notice, credential_notice)
        )

        self.assertEqual(
            len(
                {
                    item.near_duplicate_group
                    for item in snapshot.approved_items
                }
            ),
            2,
        )

    def test_near_duplicate_fingerprint_ignores_text_beyond_character_limit(self):
        common_prefix = "A" * 4096
        first = make_candidate(
            "bounded-near-first",
            sanitized_training_representation=common_prefix + " first private tail",
        )
        second = make_candidate(
            "bounded-near-second",
            sanitized_training_representation=common_prefix + " second private tail",
        )

        snapshot = CorpusGovernance().prepare((first, second))

        self.assertEqual(
            len(
                {
                    item.near_duplicate_group
                    for item in snapshot.approved_items
                }
            ),
            1,
        )

    def test_prepare_rejects_candidates_beyond_public_processing_limit(self):
        candidates = tuple(
            make_candidate(f"limit-{index:04d}")
            for index in range(CORPUS_MAX_CANDIDATES + 1)
        )

        snapshot = CorpusGovernance().prepare(tuple(reversed(candidates)))

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(len(snapshot.rejections), CORPUS_MAX_CANDIDATES + 1)
        self.assertEqual(
            snapshot.rejections[0],
            CorpusRejection("limit-0000", "candidate_limit_exceeded"),
        )
        self.assertEqual(
            snapshot.rejections[-1],
            CorpusRejection(
                f"limit-{CORPUS_MAX_CANDIDATES:04d}",
                "candidate_limit_exceeded",
            ),
        )

    def test_manifest_contains_deterministic_non_sensitive_training_provenance(self):
        representation = "sanitized provenance representation"
        candidate = make_candidate(
            "manifest-provenance",
            raw_hash=synthetic_digest("manifest-provenance-raw"),
            normalized_hash=synthetic_digest("manifest-provenance-normalized"),
            ingested_at=datetime(
                2026,
                7,
                30,
                8,
                15,
                tzinfo=timezone(timedelta(hours=8)),
            ),
            sanitized_training_representation=representation,
        )

        first = CorpusGovernance().prepare((candidate,)).manifest
        second = CorpusGovernance().prepare((candidate,)).manifest
        entry = first.entries[0]

        self.assertEqual(first, second)
        self.assertEqual(CORPUS_SCHEMA_VERSION, "3.0")
        self.assertEqual(first.schema_version, "3.0")
        self.assertEqual(
            tuple(field.name for field in fields(type(entry))),
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
        self.assertEqual(entry.original_label, SourceLabel.PHISHING)
        self.assertEqual(entry.final_label, CorpusLabel.PHISHING)
        self.assertEqual(entry.label_source, "human-review")
        self.assertEqual(entry.label_guideline_version, "label-guide-v1")
        self.assertEqual(entry.label_evidence_id, "label-evidence-manifest-provenance")
        self.assertEqual(entry.reviewer_id, "reviewer-fictional-001")
        self.assertEqual(entry.reviewed_at_utc, "2026-07-29T00:15:00+00:00")
        self.assertEqual(entry.review_status, ReviewStatus.APPROVED)
        self.assertEqual(entry.review_policy_version, "review-policy-v1")
        self.assertEqual(entry.license_identifier, "company-authorized-synthetic")
        self.assertEqual(entry.source_dataset_id, "dataset-fictional-001")
        self.assertEqual(entry.source_version, "dataset-version-v1")
        self.assertEqual(entry.source_evidence_digest, candidate.source_evidence_digest)
        self.assertEqual(entry.authorization_basis_id, "authorization-fictional-001")
        self.assertEqual(entry.authorization_status, AuthorizationStatus.ACTIVE)
        self.assertIs(entry.internal_training_allowed, True)
        self.assertIs(entry.endpoint_weight_distribution_allowed, True)
        self.assertEqual(
            entry.authorization_approved_at_utc,
            "2026-07-28T00:15:00+00:00",
        )
        self.assertEqual(
            entry.authorization_expires_at_utc,
            "2027-07-30T00:15:00+00:00",
        )
        self.assertIs(entry.authorization_no_expiry, False)
        self.assertEqual(entry.privacy_review_status, PrivacyReviewStatus.APPROVED)
        self.assertEqual(entry.sanitization_policy_version, "sanitization-policy-v1")
        self.assertEqual(entry.privacy_reviewed_at_utc, "2026-07-29T12:15:00+00:00")
        self.assertEqual(entry.privacy_evidence_digest, candidate.privacy_evidence_digest)
        self.assertEqual(entry.ingested_at_utc, "2026-07-30T00:15:00+00:00")
        self.assertEqual(entry.raw_content_digest, candidate.raw_hash)
        self.assertEqual(entry.normalized_content_digest, candidate.normalized_hash)
        self.assertEqual(
            entry.sanitized_representation_digest,
            "47ac5ca9f2335485293302cd0081a9ccf2fffb736a6bcbd62fb5e28707231a54",
        )
        self.assertEqual(entry.feature_schema_version, FEATURE_SCHEMA_VERSION)
        self.assertEqual(entry.corpus_schema_version, CORPUS_SCHEMA_VERSION)
        self.assertNotIn(representation, repr(first))
        self.assertRegex(first.digest, r"^[0-9a-f]{64}$")

    def test_manifest_digest_is_order_independent_and_covers_governance_facts(self):
        first_candidate = make_candidate("manifest-digest-a")
        second_candidate = make_candidate("manifest-digest-b")

        forward = CorpusGovernance().prepare(
            (first_candidate, second_candidate)
        ).manifest
        reverse = CorpusGovernance().prepare(
            (second_candidate, first_candidate)
        ).manifest
        base = CorpusGovernance().prepare((first_candidate,)).manifest
        valid_changes = (
            {"label_guideline_version": "label-guide-v2"},
            {"source_version": "dataset-version-v2"},
            {"authorization_status": AuthorizationStatus.APPROVED},
            {"authorization_basis_id": "authorization-fictional-002"},
            {"privacy_evidence_digest": synthetic_digest("privacy-evidence-v2")},
            {"sanitization_policy_version": "sanitization-policy-v2"},
        )

        self.assertEqual(forward, reverse)
        self.assertEqual(forward.digest, reverse.digest)
        for changes in valid_changes:
            with self.subTest(changes=changes):
                changed = CorpusGovernance().prepare(
                    (replace(first_candidate, **changes),)
                ).manifest
                self.assertNotEqual(changed.digest, base.digest)

    def test_prepare_rejects_noncanonical_sha256_digests(self):
        invalid_raw_short = make_candidate(
            "invalid-raw-short",
            raw_hash="short-digest",
            normalized_hash=synthetic_digest("valid-normalized-short"),
        )
        invalid_raw_uppercase = make_candidate(
            "invalid-raw-uppercase",
            raw_hash=synthetic_digest("uppercase-raw").upper(),
            normalized_hash=synthetic_digest("valid-normalized-uppercase"),
        )
        invalid_raw_hex = make_candidate(
            "invalid-raw-hex",
            raw_hash="g" * 64,
            normalized_hash=synthetic_digest("valid-normalized-hex"),
        )
        invalid_normalized = make_candidate(
            "invalid-normalized",
            raw_hash=synthetic_digest("valid-raw-normalized-case"),
            normalized_hash="not-a-sha256",
        )

        snapshot = CorpusGovernance().prepare(
            (
                invalid_raw_short,
                invalid_raw_uppercase,
                invalid_raw_hex,
                invalid_normalized,
            )
        )

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("invalid-normalized", "invalid_normalized_digest"),
                ("invalid-raw-hex", "invalid_raw_digest"),
                ("invalid-raw-short", "invalid_raw_digest"),
                ("invalid-raw-uppercase", "invalid_raw_digest"),
            ),
        )

    def test_prepare_rejects_unsafe_license_identifiers_and_naive_times(self):
        credential_license = make_candidate(
            "credential-license",
            license_source="secret:fictional-value",
        )
        private_path_license = make_candidate(
            "private-path-license",
            license_source="C:\\Users\\Fictional\\license.txt",
        )
        network_license = make_candidate(
            "network-license",
            license_source="https://license.example.test/authorization",
        )
        naive_time = make_candidate(
            "naive-time",
            ingested_at=datetime(2026, 7, 30),
        )

        snapshot = CorpusGovernance().prepare(
            (private_path_license, network_license, naive_time, credential_license)
        )

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("credential-license", "invalid_license_identifier"),
                ("naive-time", "invalid_ingestion_time"),
                ("network-license", "invalid_license_identifier"),
                ("private-path-license", "invalid_license_identifier"),
            ),
        )

    def test_prepare_rejects_unsafe_identifiers_projected_into_manifest(self):
        unsafe_credential_source = make_candidate(
            "unsafe-credential-source",
            source_group="token:fictional-value",
        )
        unsafe_source = make_candidate(
            "unsafe-source-identifier",
            source_group="C:\\Users\\Fictional\\corpus",
        )
        unsafe_label_source = make_candidate(
            "unsafe-label-source",
            label_source="https://review.example.test/item?id=fictional",
        )
        unsafe_campaign = make_candidate(
            "unsafe-campaign",
            campaign_group="/home/fictional/private-campaign",
        )

        snapshot = CorpusGovernance().prepare(
            (
                unsafe_source,
                unsafe_label_source,
                unsafe_campaign,
                unsafe_credential_source,
            )
        )

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("unsafe-campaign", "invalid_manifest_identifier"),
                ("unsafe-credential-source", "invalid_manifest_identifier"),
                ("unsafe-label-source", "invalid_manifest_identifier"),
                ("unsafe-source-identifier", "invalid_manifest_identifier"),
            ),
        )

    def test_source_holdout_forces_entire_connected_group_to_test(self):
        policy = CorpusSplitPolicy(test_source_groups=("held-out-source",))
        held_out = make_candidate(
            "source-held-out",
            source_group="held-out-source",
            template_group="source-shared-template",
        )
        connected = make_candidate(
            "source-connected",
            source_group="development-source",
            template_group="source-shared-template",
        )

        snapshot = CorpusGovernance().prepare(
            (held_out, connected),
            split_policy=policy,
        )

        self.assertEqual(
            {item.split for item in snapshot.approved_items},
            {DatasetSplit.TEST},
        )
        with self.assertRaises(FrozenInstanceError):
            policy.test_source_groups = ()

    def test_time_holdout_forces_entire_connected_group_to_test(self):
        cutoff = datetime(2026, 7, 1, tzinfo=timezone.utc)
        historical = make_candidate(
            "time-before",
            campaign_group="time-shared-campaign",
            ingested_at=cutoff,
        )
        future = make_candidate(
            "time-after",
            campaign_group="time-shared-campaign",
            ingested_at=cutoff + timedelta(microseconds=1),
        )

        snapshot = CorpusGovernance().prepare(
            (future, historical),
            split_policy=CorpusSplitPolicy(test_after=cutoff),
        )

        self.assertEqual(
            {item.split for item in snapshot.approved_items},
            {DatasetSplit.TEST},
        )

    def test_split_policy_rejects_paths_network_addresses_and_naive_time(self):
        candidate = make_candidate("policy-candidate")
        invalid_policies = (
            CorpusSplitPolicy(test_source_groups=("C:\\Users\\private",)),
            CorpusSplitPolicy(
                test_source_groups=("https://source.example.test/corpus",)
            ),
            CorpusSplitPolicy(test_source_groups=("token:fictional-value",)),
            CorpusSplitPolicy(test_source_groups=("x" * 129,)),
            CorpusSplitPolicy(test_after=datetime(2026, 7, 1)),
        )

        for policy in invalid_policies:
            with self.subTest(policy=policy):
                with self.assertRaisesRegex(ValueError, "^invalid_split_policy$"):
                    CorpusGovernance().prepare(
                        (candidate,),
                        split_policy=policy,
                    )

    def test_holdout_on_exact_duplicate_forces_canonical_to_test(self):
        shared_raw_digest = synthetic_digest("holdout-exact-duplicate")
        canonical = make_candidate(
            "canonical-source",
            raw_hash=shared_raw_digest,
            source_group="development-source",
        )
        held_out_duplicate = make_candidate(
            "held-out-duplicate",
            raw_hash=shared_raw_digest,
            source_group="held-out-source",
        )

        snapshot = CorpusGovernance().prepare(
            (held_out_duplicate, canonical),
            split_policy=CorpusSplitPolicy(
                test_source_groups=("held-out-source",)
            ),
        )

        self.assertEqual(
            tuple(item.candidate.item_id for item in snapshot.approved_items),
            ("canonical-source",),
        )
        self.assertEqual(snapshot.approved_items[0].split, DatasetSplit.TEST)

    def test_prepare_rejects_entire_raw_duplicate_group_with_conflicting_final_labels(self):
        shared_raw_digest = synthetic_digest("shared-raw-conflict")
        phishing = make_candidate(
            "raw-phishing",
            raw_hash=shared_raw_digest,
            final_label=CorpusLabel.PHISHING,
            original_label=SourceLabel.PHISHING,
        )
        benign = make_candidate(
            "raw-benign",
            raw_hash=shared_raw_digest,
            final_label=CorpusLabel.BENIGN,
            original_label=SourceLabel.BENIGN,
        )

        forward = CorpusGovernance().prepare((phishing, benign))
        reverse = CorpusGovernance().prepare((benign, phishing))

        for snapshot in (forward, reverse):
            self.assertEqual(snapshot.approved_items, ())
            self.assertEqual(
                tuple((item.item_id, item.reason) for item in snapshot.rejections),
                (
                    ("raw-benign", "raw_label_conflict"),
                    ("raw-phishing", "raw_label_conflict"),
                ),
            )

    def test_prepare_rejects_entire_normalized_group_with_conflicting_final_labels(self):
        shared_normalized_digest = synthetic_digest("shared-normalized-conflict")
        phishing = make_candidate(
            "normalized-phishing",
            raw_hash=synthetic_digest("raw-normalized-phishing"),
            normalized_hash=shared_normalized_digest,
            final_label=CorpusLabel.PHISHING,
            original_label=SourceLabel.PHISHING,
        )
        benign = make_candidate(
            "normalized-benign",
            raw_hash=synthetic_digest("raw-normalized-benign"),
            normalized_hash=shared_normalized_digest,
            final_label=CorpusLabel.BENIGN,
            original_label=SourceLabel.BENIGN,
        )

        snapshot = CorpusGovernance().prepare((phishing, benign))

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("normalized-benign", "normalized_label_conflict"),
                ("normalized-phishing", "normalized_label_conflict"),
            ),
        )

    def test_prepare_admits_only_sourced_licensed_human_approved_candidates(self):
        valid = make_candidate("valid")
        missing_source = make_candidate("missing-source", source_group="")
        missing_license = make_candidate("missing-license", license_source="")
        pending = make_candidate(
            "pending",
            review_status=ReviewStatus.PENDING,
        )

        snapshot = CorpusGovernance().prepare(
            (pending, missing_license, valid, missing_source)
        )

        self.assertEqual(
            tuple(item.candidate.item_id for item in snapshot.approved_items),
            ("valid",),
        )
        self.assertEqual(
            snapshot.manifest.entries[0].feature_schema_version,
            FEATURE_SCHEMA_VERSION,
        )
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("missing-license", "missing_license"),
                ("missing-source", "missing_source"),
                ("pending", "not_human_approved"),
            ),
        )

    def test_prepare_does_not_automatically_upgrade_spam_or_ham_labels(self):
        automatic_spam = make_candidate(
            "automatic-spam",
            original_label=SourceLabel.SPAM,
            final_label=CorpusLabel.PHISHING,
            label_source="source-label",
        )
        automatic_ham = make_candidate(
            "automatic-ham",
            original_label=SourceLabel.HAM,
            final_label=CorpusLabel.BENIGN,
            label_source="source-label",
        )
        reviewed_spam = make_candidate(
            "reviewed-spam",
            original_label=SourceLabel.SPAM,
            final_label=CorpusLabel.PHISHING,
            label_source="human-review",
        )
        reviewed_ham = make_candidate(
            "reviewed-ham",
            original_label=SourceLabel.HAM,
            final_label=CorpusLabel.BENIGN,
            label_source="analyst-confirmed",
        )

        snapshot = CorpusGovernance().prepare(
            (reviewed_spam, automatic_spam, reviewed_ham, automatic_ham)
        )

        self.assertEqual(
            tuple(item.candidate.item_id for item in snapshot.approved_items),
            ("reviewed-ham", "reviewed-spam"),
        )
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("automatic-ham", "ambiguous_source_label"),
                ("automatic-spam", "ambiguous_source_label"),
            ),
        )

    def test_prepare_rejects_conflicts_with_explicit_source_labels(self):
        phishing_as_benign = make_candidate(
            "phishing-as-benign",
            original_label=SourceLabel.PHISHING,
            final_label=CorpusLabel.BENIGN,
            label_source="human-review",
        )
        benign_as_phishing = make_candidate(
            "benign-as-phishing",
            original_label=SourceLabel.BENIGN,
            final_label=CorpusLabel.PHISHING,
            label_source="human-review",
        )

        snapshot = CorpusGovernance().prepare(
            (phishing_as_benign, benign_as_phishing)
        )

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("benign-as-phishing", "label_conflict"),
                ("phishing-as-benign", "label_conflict"),
            ),
        )

    def test_prepare_keeps_one_stable_canonical_for_exact_duplicates(self):
        canonical = make_candidate(
            "canonical",
            raw_hash=synthetic_digest("same-raw-hash"),
            normalized_hash=synthetic_digest("normalized-canonical"),
        )
        duplicate = make_candidate(
            "duplicate",
            raw_hash=synthetic_digest("same-raw-hash"),
            normalized_hash=synthetic_digest("normalized-duplicate"),
        )

        forward = CorpusGovernance().prepare((duplicate, canonical))
        reverse = CorpusGovernance().prepare((canonical, duplicate))

        for snapshot in (forward, reverse):
            self.assertEqual(
                tuple(item.candidate.item_id for item in snapshot.approved_items),
                ("canonical",),
            )
            self.assertEqual(
                tuple((item.item_id, item.reason) for item in snapshot.rejections),
                (("duplicate", "exact_duplicate"),),
            )

    def test_prepare_groups_normalized_duplicates_without_exposing_hashes(self):
        first = make_candidate(
            "normalized-first",
            raw_hash=synthetic_digest("raw-first"),
            normalized_hash=synthetic_digest("same-normalized-hash"),
        )
        second = make_candidate(
            "normalized-second",
            raw_hash=synthetic_digest("raw-second"),
            normalized_hash=synthetic_digest("same-normalized-hash"),
        )

        snapshot = CorpusGovernance().prepare((second, first))

        self.assertEqual(len(snapshot.approved_items), 2)
        groups = tuple(item.duplicate_group for item in snapshot.approved_items)
        self.assertEqual(len(set(groups)), 1)
        self.assertTrue(groups[0].startswith("dup-"))
        self.assertNotEqual(groups[0], "same-normalized-hash")

    def test_prepare_assigns_group_isolated_deterministic_splits(self):
        template_a = make_candidate(
            "template-a",
            template_group="shared-template",
        )
        template_b = make_candidate(
            "template-b",
            template_group="shared-template",
            campaign_group="shared-campaign",
        )
        campaign_c = make_candidate(
            "campaign-c",
            campaign_group="shared-campaign",
        )
        duplicate_d = make_candidate(
            "duplicate-d",
            normalized_hash=synthetic_digest("shared-normalized"),
        )
        duplicate_e = make_candidate(
            "duplicate-e",
            normalized_hash=synthetic_digest("shared-normalized"),
        )
        independent_g = make_candidate("independent-g")
        independent_k = make_candidate("independent-k")
        candidates = (
            independent_k,
            duplicate_e,
            template_b,
            independent_g,
            campaign_c,
            duplicate_d,
            template_a,
        )

        forward = CorpusGovernance().prepare(candidates)
        repeated = CorpusGovernance().prepare(candidates)
        reverse = CorpusGovernance().prepare(tuple(reversed(candidates)))

        def split_projection(snapshot):
            return tuple(
                (
                    item.candidate.item_id,
                    item.split,
                    item.duplicate_group,
                )
                for item in snapshot.approved_items
            )

        self.assertEqual(split_projection(forward), split_projection(repeated))
        self.assertEqual(split_projection(forward), split_projection(reverse))
        splits = {
            item.candidate.item_id: item.split for item in forward.approved_items
        }
        self.assertEqual(
            {splits[name] for name in ("template-a", "template-b", "campaign-c")},
            {DatasetSplit.TRAIN},
        )
        self.assertEqual(
            {splits[name] for name in ("duplicate-d", "duplicate-e")},
            {DatasetSplit.TRAIN},
        )
        self.assertEqual(splits["independent-g"], DatasetSplit.TEST)
        self.assertEqual(splits["independent-k"], DatasetSplit.VALIDATION)
