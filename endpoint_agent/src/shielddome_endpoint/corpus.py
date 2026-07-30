from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import re
import unicodedata

from .domain import FEATURE_SCHEMA_VERSION


CORPUS_SCHEMA_VERSION = "3.0"
NEAR_DUPLICATE_FINGERPRINT_VERSION = "1.0"
NEAR_DUPLICATE_MAX_CHARACTERS = 4096
CORPUS_MAX_CANDIDATES = 4096
SAFE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
IDENTIFIER_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(?:password|passwd|token|api[_-]?key|authorization|secret):"
)
HUMAN_LABEL_SOURCES = frozenset(
    {"human-review", "analyst-confirmed", "security-review"}
)


class CorpusLabel(StrEnum):
    BENIGN = "benign"
    PHISHING = "phishing"


class SourceLabel(StrEnum):
    SPAM = "spam"
    HAM = "ham"
    PHISHING = "phishing"
    BENIGN = "benign"


class ReviewStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class AuthorizationStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class PrivacyReviewStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class DatasetSplit(StrEnum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


@dataclass(frozen=True, slots=True)
class CorpusSplitPolicy:
    test_source_groups: tuple[str, ...] = ()
    test_after: datetime | None = None


@dataclass(frozen=True, slots=True)
class CorpusCandidate:
    item_id: str
    final_label: CorpusLabel
    original_label: SourceLabel
    label_source: str
    label_guideline_version: str
    label_evidence_id: str
    reviewer_id: str
    reviewed_at: datetime
    review_status: ReviewStatus
    review_policy_version: str
    license_source: str
    source_dataset_id: str
    source_version: str
    source_evidence_digest: str
    authorization_basis_id: str
    authorization_status: AuthorizationStatus
    internal_training_allowed: bool
    endpoint_weight_distribution_allowed: bool
    authorization_approved_at: datetime
    authorization_expires_at: datetime | None
    authorization_no_expiry: bool
    privacy_review_status: PrivacyReviewStatus
    sanitization_policy_version: str
    privacy_reviewed_at: datetime
    privacy_evidence_digest: str
    raw_hash: str
    normalized_hash: str
    template_group: str
    campaign_group: str
    language_group: str
    source_group: str
    ingested_at: datetime
    feature_schema_version: str
    sanitized_training_representation: str
    sanitized_representation_digest: str


@dataclass(frozen=True, slots=True)
class CorpusRejection:
    item_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class ApprovedCorpusItem:
    candidate: CorpusCandidate
    duplicate_group: str
    near_duplicate_group: str
    split: DatasetSplit


@dataclass(frozen=True, slots=True)
class CorpusManifestEntry:
    item_id: str
    original_label: SourceLabel
    final_label: CorpusLabel
    label_source: str
    label_guideline_version: str
    label_evidence_id: str
    reviewer_id: str
    reviewed_at_utc: str
    review_status: ReviewStatus
    review_policy_version: str
    license_identifier: str
    source_dataset_id: str
    source_version: str
    source_evidence_digest: str
    authorization_basis_id: str
    authorization_status: AuthorizationStatus
    internal_training_allowed: bool
    endpoint_weight_distribution_allowed: bool
    authorization_approved_at_utc: str
    authorization_expires_at_utc: str | None
    authorization_no_expiry: bool
    privacy_review_status: PrivacyReviewStatus
    sanitization_policy_version: str
    privacy_reviewed_at_utc: str
    privacy_evidence_digest: str
    ingested_at_utc: str
    raw_content_digest: str
    normalized_content_digest: str
    sanitized_representation_digest: str
    source_group: str
    language_group: str
    template_group: str
    campaign_group: str
    duplicate_group: str
    near_duplicate_group: str
    feature_schema_version: str
    corpus_schema_version: str
    split: DatasetSplit


@dataclass(frozen=True, slots=True)
class CorpusManifest:
    entries: tuple[CorpusManifestEntry, ...]
    schema_version: str = CORPUS_SCHEMA_VERSION
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "digest", _manifest_digest(self))


@dataclass(frozen=True, slots=True)
class CorpusSnapshot:
    approved_items: tuple[ApprovedCorpusItem, ...]
    rejections: tuple[CorpusRejection, ...]
    manifest: CorpusManifest
    schema_version: str = CORPUS_SCHEMA_VERSION


def _validate_split_policy(split_policy: CorpusSplitPolicy) -> None:
    if any(
        not _is_safe_identifier(source_group)
        for source_group in split_policy.test_source_groups
    ):
        raise ValueError("invalid_split_policy")
    if split_policy.test_after is not None and (
        split_policy.test_after.tzinfo is None
        or split_policy.test_after.utcoffset() is None
    ):
        raise ValueError("invalid_split_policy")


def _is_aware_datetime(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def _is_missing_identifier(value: object) -> bool:
    return not isinstance(value, str) or not value.strip()


def _is_safe_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and SAFE_IDENTIFIER_PATTERN.fullmatch(value) is not None
        and IDENTIFIER_CREDENTIAL_PATTERN.search(value) is None
    )


def _is_canonical_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _manifest_digest(manifest: CorpusManifest) -> str:
    canonical_payload = json.dumps(
        {
            "entries": [asdict(entry) for entry in manifest.entries],
            "schema_version": manifest.schema_version,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical_payload).hexdigest()


def _admission_rejection(candidate: CorpusCandidate) -> str | None:
    if _is_missing_identifier(candidate.label_source) or _is_missing_identifier(
        candidate.source_group
    ):
        return "missing_source"
    if _is_missing_identifier(candidate.license_source):
        return "missing_license"
    if not _is_safe_identifier(candidate.license_source):
        return "invalid_license_identifier"
    if not _is_aware_datetime(candidate.ingested_at):
        return "invalid_ingestion_time"
    if _is_missing_identifier(candidate.label_guideline_version):
        return "missing_label_guideline_version"
    if not _is_safe_identifier(candidate.label_guideline_version):
        return "invalid_label_guideline_version"
    if _is_missing_identifier(candidate.label_evidence_id):
        return "missing_label_evidence_id"
    if not _is_safe_identifier(candidate.label_evidence_id):
        return "invalid_label_evidence_id"
    if _is_missing_identifier(candidate.reviewer_id):
        return "missing_reviewer_id"
    if not _is_safe_identifier(candidate.reviewer_id):
        return "invalid_reviewer_id"
    if not _is_aware_datetime(candidate.reviewed_at) or (
        candidate.reviewed_at > candidate.ingested_at
    ):
        return "invalid_review_time"
    if _is_missing_identifier(candidate.review_policy_version):
        return "missing_review_policy_version"
    if not _is_safe_identifier(candidate.review_policy_version):
        return "invalid_review_policy_version"
    if candidate.review_status is not ReviewStatus.APPROVED:
        return "not_human_approved"
    if _is_missing_identifier(candidate.source_dataset_id):
        return "missing_source_dataset_id"
    if not _is_safe_identifier(candidate.source_dataset_id):
        return "invalid_source_dataset_id"
    if _is_missing_identifier(candidate.source_version):
        return "missing_source_version"
    if not _is_safe_identifier(candidate.source_version):
        return "invalid_source_version"
    if not _is_canonical_sha256(candidate.source_evidence_digest):
        return "invalid_source_evidence_digest"
    if _is_missing_identifier(candidate.authorization_basis_id):
        return "missing_authorization_basis_id"
    if not _is_safe_identifier(candidate.authorization_basis_id):
        return "invalid_authorization_basis_id"
    if not (
        candidate.authorization_status is AuthorizationStatus.APPROVED
        or candidate.authorization_status is AuthorizationStatus.ACTIVE
    ):
        return "authorization_not_active"
    if candidate.internal_training_allowed is not True:
        return "internal_training_not_allowed"
    if candidate.endpoint_weight_distribution_allowed is not True:
        return "endpoint_weight_distribution_not_allowed"
    if not _is_aware_datetime(candidate.authorization_approved_at) or (
        candidate.authorization_approved_at > candidate.ingested_at
    ):
        return "invalid_authorization_approval_time"
    if candidate.authorization_no_expiry is True:
        if candidate.authorization_expires_at is not None:
            return "conflicting_authorization_expiry"
    elif candidate.authorization_no_expiry is False:
        if candidate.authorization_expires_at is None:
            return "missing_authorization_expiry"
        if not _is_aware_datetime(candidate.authorization_expires_at):
            return "invalid_authorization_expiry"
        if candidate.authorization_expires_at <= candidate.ingested_at:
            return "authorization_expired"
    else:
        return "conflicting_authorization_expiry"
    if candidate.privacy_review_status is not PrivacyReviewStatus.APPROVED:
        return "privacy_not_approved"
    if _is_missing_identifier(candidate.sanitization_policy_version):
        return "missing_sanitization_policy_version"
    if not _is_safe_identifier(candidate.sanitization_policy_version):
        return "invalid_sanitization_policy_version"
    if not _is_aware_datetime(candidate.privacy_reviewed_at) or (
        candidate.privacy_reviewed_at > candidate.ingested_at
    ):
        return "invalid_privacy_review_time"
    if not _is_canonical_sha256(candidate.privacy_evidence_digest):
        return "invalid_privacy_evidence_digest"
    if not (
        isinstance(candidate.sanitized_training_representation, str)
        and candidate.sanitized_training_representation.strip()
    ):
        return "missing_metadata"
    if not _is_canonical_sha256(candidate.sanitized_representation_digest):
        return "invalid_sanitized_representation_digest"
    if candidate.sanitized_representation_digest != hashlib.sha256(
        candidate.sanitized_training_representation.encode("utf-8")
    ).hexdigest():
        return "sanitized_representation_digest_mismatch"
    if (
        candidate.original_label in {SourceLabel.SPAM, SourceLabel.HAM}
        and candidate.label_source.strip().casefold() not in HUMAN_LABEL_SOURCES
    ):
        return "ambiguous_source_label"
    if (
        candidate.original_label is SourceLabel.PHISHING
        and candidate.final_label is not CorpusLabel.PHISHING
    ) or (
        candidate.original_label is SourceLabel.BENIGN
        and candidate.final_label is not CorpusLabel.BENIGN
    ):
        return "label_conflict"
    if candidate.feature_schema_version != FEATURE_SCHEMA_VERSION:
        return "feature_schema_mismatch"
    if not _is_canonical_sha256(candidate.raw_hash):
        return "invalid_raw_digest"
    if not _is_canonical_sha256(candidate.normalized_hash):
        return "invalid_normalized_digest"
    if any(
        _is_missing_identifier(value)
        for value in (
            candidate.item_id,
            candidate.raw_hash,
            candidate.normalized_hash,
            candidate.template_group,
            candidate.campaign_group,
            candidate.language_group,
        )
    ):
        return "missing_metadata"
    if any(
        not _is_safe_identifier(value)
        for value in (
            candidate.item_id,
            candidate.label_source,
            candidate.template_group,
            candidate.campaign_group,
            candidate.language_group,
            candidate.source_group,
        )
    ):
        return "invalid_manifest_identifier"
    return None


def _duplicate_group(normalized_hash: str) -> str:
    digest = hashlib.sha256(normalized_hash.encode("utf-8")).hexdigest()
    return f"dup-{digest[:16]}"


def _near_duplicate_group(representation: str) -> str:
    normalized = unicodedata.normalize(
        "NFKC", representation[:NEAR_DUPLICATE_MAX_CHARACTERS]
    ).casefold()
    normalized = re.sub(r"\b[a-z][a-z0-9+.-]*://\S+", "<url>", normalized)
    normalized = re.sub(
        r"\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\b",
        "<email>",
        normalized,
    )
    normalized = re.sub(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "<id>",
        normalized,
    )
    normalized = re.sub(r"\b[0-9a-f]{16,}\b|\b\d{6,}\b", "<id>", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    version = NEAR_DUPLICATE_FINGERPRINT_VERSION.split(".", 1)[0]
    return f"near-v{version}-{digest[:16]}"


def _split_for_component(component_key: str) -> DatasetSplit:
    digest = hashlib.sha256(component_key.encode("utf-8")).digest()
    bucket = int.from_bytes(digest[:8], "big") % 100
    if bucket < 70:
        return DatasetSplit.TRAIN
    if bucket < 85:
        return DatasetSplit.VALIDATION
    return DatasetSplit.TEST


def _matches_test_holdout(
    candidate: CorpusCandidate,
    split_policy: CorpusSplitPolicy,
) -> bool:
    return candidate.source_group in split_policy.test_source_groups or (
        split_policy.test_after is not None
        and candidate.ingested_at > split_policy.test_after
    )


def _assign_splits(
    items: list[ApprovedCorpusItem],
    split_policy: CorpusSplitPolicy,
    heldout_raw_hashes: frozenset[str],
) -> list[ApprovedCorpusItem]:
    parents = list(range(len(items)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for group_value in (
        lambda item: item.candidate.template_group,
        lambda item: item.candidate.campaign_group,
        lambda item: item.duplicate_group,
        lambda item: item.near_duplicate_group,
    ):
        first_index_by_group: dict[str, int] = {}
        for index, item in enumerate(items):
            key = group_value(item)
            if key in first_index_by_group:
                union(first_index_by_group[key], index)
            else:
                first_index_by_group[key] = index

    component_indices: dict[int, list[int]] = {}
    for index in range(len(items)):
        component_indices.setdefault(find(index), []).append(index)

    splits_by_index: dict[int, DatasetSplit] = {}
    for indices in component_indices.values():
        component_key = "|".join(
            sorted(items[index].candidate.item_id for index in indices)
        )
        if any(
            _matches_test_holdout(items[index].candidate, split_policy)
            or items[index].candidate.raw_hash in heldout_raw_hashes
            for index in indices
        ):
            split = DatasetSplit.TEST
        else:
            split = _split_for_component(component_key)
        for index in indices:
            splits_by_index[index] = split

    return [
        ApprovedCorpusItem(
            candidate=item.candidate,
            duplicate_group=item.duplicate_group,
            near_duplicate_group=item.near_duplicate_group,
            split=splits_by_index[index],
        )
        for index, item in enumerate(items)
    ]


class CorpusGovernance:
    def prepare(
        self,
        candidates: tuple[CorpusCandidate, ...],
        split_policy: CorpusSplitPolicy = CorpusSplitPolicy(),
    ) -> CorpusSnapshot:
        _validate_split_policy(split_policy)
        ordered_candidates = tuple(
            sorted(candidates, key=lambda item: item.item_id)
        )
        if len(ordered_candidates) > CORPUS_MAX_CANDIDATES:
            return CorpusSnapshot(
                approved_items=(),
                rejections=tuple(
                    CorpusRejection(
                        candidate.item_id,
                        "candidate_limit_exceeded",
                    )
                    for candidate in ordered_candidates
                ),
                manifest=CorpusManifest(entries=()),
            )
        approved_items: list[ApprovedCorpusItem] = []
        rejections: list[CorpusRejection] = []
        seen_raw_hashes: set[str] = set()
        admitted_candidates: list[CorpusCandidate] = []

        for candidate in ordered_candidates:
            rejection = _admission_rejection(candidate)
            if rejection is not None:
                rejections.append(CorpusRejection(candidate.item_id, rejection))
                continue
            admitted_candidates.append(candidate)

        raw_labels: dict[str, set[CorpusLabel]] = {}
        for candidate in admitted_candidates:
            raw_labels.setdefault(candidate.raw_hash, set()).add(candidate.final_label)
        conflicting_raw_hashes = {
            raw_hash for raw_hash, labels in raw_labels.items() if len(labels) > 1
        }
        normalized_labels: dict[str, set[CorpusLabel]] = {}
        for candidate in admitted_candidates:
            normalized_labels.setdefault(candidate.normalized_hash, set()).add(
                candidate.final_label
            )
        conflicting_normalized_hashes = {
            normalized_hash
            for normalized_hash, labels in normalized_labels.items()
            if len(labels) > 1
        }

        for candidate in admitted_candidates:
            if candidate.raw_hash in conflicting_raw_hashes:
                rejections.append(
                    CorpusRejection(candidate.item_id, "raw_label_conflict")
                )
                continue
            if candidate.normalized_hash in conflicting_normalized_hashes:
                rejections.append(
                    CorpusRejection(candidate.item_id, "normalized_label_conflict")
                )
                continue
            if candidate.raw_hash in seen_raw_hashes:
                rejections.append(
                    CorpusRejection(candidate.item_id, "exact_duplicate")
                )
                continue
            seen_raw_hashes.add(candidate.raw_hash)
            approved_items.append(
                ApprovedCorpusItem(
                    candidate=candidate,
                    duplicate_group=_duplicate_group(candidate.normalized_hash),
                    near_duplicate_group=_near_duplicate_group(
                        candidate.sanitized_training_representation
                    ),
                    split=DatasetSplit.TRAIN,
                )
            )

        rejections.sort(key=lambda item: item.item_id)
        heldout_raw_hashes = frozenset(
            candidate.raw_hash
            for candidate in admitted_candidates
            if _matches_test_holdout(candidate, split_policy)
        )
        approved_items = _assign_splits(
            approved_items,
            split_policy,
            heldout_raw_hashes,
        )

        manifest = CorpusManifest(
            entries=tuple(
                CorpusManifestEntry(
                    item_id=item.candidate.item_id,
                    original_label=item.candidate.original_label,
                    final_label=item.candidate.final_label,
                    label_source=item.candidate.label_source,
                    label_guideline_version=item.candidate.label_guideline_version,
                    label_evidence_id=item.candidate.label_evidence_id,
                    reviewer_id=item.candidate.reviewer_id,
                    reviewed_at_utc=_utc_iso(item.candidate.reviewed_at),
                    review_status=item.candidate.review_status,
                    review_policy_version=item.candidate.review_policy_version,
                    license_identifier=item.candidate.license_source,
                    source_dataset_id=item.candidate.source_dataset_id,
                    source_version=item.candidate.source_version,
                    source_evidence_digest=item.candidate.source_evidence_digest,
                    authorization_basis_id=item.candidate.authorization_basis_id,
                    authorization_status=item.candidate.authorization_status,
                    internal_training_allowed=item.candidate.internal_training_allowed,
                    endpoint_weight_distribution_allowed=(
                        item.candidate.endpoint_weight_distribution_allowed
                    ),
                    authorization_approved_at_utc=_utc_iso(
                        item.candidate.authorization_approved_at
                    ),
                    authorization_expires_at_utc=(
                        _utc_iso(item.candidate.authorization_expires_at)
                        if item.candidate.authorization_expires_at is not None
                        else None
                    ),
                    authorization_no_expiry=item.candidate.authorization_no_expiry,
                    privacy_review_status=item.candidate.privacy_review_status,
                    sanitization_policy_version=(
                        item.candidate.sanitization_policy_version
                    ),
                    privacy_reviewed_at_utc=_utc_iso(
                        item.candidate.privacy_reviewed_at
                    ),
                    privacy_evidence_digest=item.candidate.privacy_evidence_digest,
                    ingested_at_utc=_utc_iso(item.candidate.ingested_at),
                    raw_content_digest=item.candidate.raw_hash,
                    normalized_content_digest=item.candidate.normalized_hash,
                    sanitized_representation_digest=(
                        item.candidate.sanitized_representation_digest
                    ),
                    source_group=item.candidate.source_group,
                    language_group=item.candidate.language_group,
                    template_group=item.candidate.template_group,
                    campaign_group=item.candidate.campaign_group,
                    duplicate_group=item.duplicate_group,
                    near_duplicate_group=item.near_duplicate_group,
                    feature_schema_version=item.candidate.feature_schema_version,
                    corpus_schema_version=CORPUS_SCHEMA_VERSION,
                    split=item.split,
                )
                for item in approved_items
            )
        )
        return CorpusSnapshot(
            approved_items=tuple(approved_items),
            rejections=tuple(rejections),
            manifest=manifest,
        )
