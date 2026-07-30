from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.corpus import (
    CORPUS_SCHEMA_VERSION,
    CORPUS_MAX_CANDIDATES,
    CorpusCandidate,
    CorpusGovernance,
    CorpusLabel,
    CorpusRejection,
    CorpusSplitPolicy,
    DatasetSplit,
    ReviewStatus,
    SourceLabel,
)
from shielddome_endpoint.domain import FEATURE_SCHEMA_VERSION


def make_candidate(item_id: str = "item-001", **changes) -> CorpusCandidate:
    candidate = CorpusCandidate(
        item_id=item_id,
        final_label=CorpusLabel.PHISHING,
        original_label=SourceLabel.PHISHING,
        label_source="human-review",
        review_status=ReviewStatus.APPROVED,
        license_source="company-authorized-synthetic",
        raw_hash=synthetic_digest(f"raw:{item_id}"),
        normalized_hash=synthetic_digest(f"normalized:{item_id}"),
        template_group=f"template-{item_id}",
        campaign_group=f"campaign-{item_id}",
        language_group="mixed",
        source_group="synthetic",
        ingested_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        sanitized_training_representation=f"synthetic representation {item_id}",
    )
    return replace(candidate, **changes)


def synthetic_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class CorpusGovernanceTests(unittest.TestCase):
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
        self.assertEqual(CORPUS_SCHEMA_VERSION, "2.0")
        self.assertEqual(first.schema_version, "2.0")
        self.assertEqual(
            tuple(field.name for field in fields(type(entry))),
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
        self.assertEqual(entry.original_label, SourceLabel.PHISHING)
        self.assertEqual(entry.final_label, CorpusLabel.PHISHING)
        self.assertEqual(entry.label_source, "human-review")
        self.assertEqual(entry.review_status, ReviewStatus.APPROVED)
        self.assertEqual(entry.license_identifier, "company-authorized-synthetic")
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
            (private_path_license, network_license, naive_time)
        )

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("naive-time", "invalid_ingestion_time"),
                ("network-license", "invalid_license_identifier"),
                ("private-path-license", "invalid_license_identifier"),
            ),
        )

    def test_prepare_rejects_unsafe_identifiers_projected_into_manifest(self):
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
            (unsafe_source, unsafe_label_source, unsafe_campaign)
        )

        self.assertEqual(snapshot.approved_items, ())
        self.assertEqual(
            tuple((item.item_id, item.reason) for item in snapshot.rejections),
            (
                ("unsafe-campaign", "invalid_manifest_identifier"),
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
