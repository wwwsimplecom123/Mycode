from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import sys


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))
sys.path.insert(0, str(ENDPOINT_ROOT / "training"))

from shielddome_endpoint.corpus import CORPUS_SCHEMA_VERSION, DatasetSplit
from shielddome_endpoint.domain import FEATURE_SCHEMA_VERSION, FeatureVector
from shielddome_endpoint.feature_pipeline import (
    CATEGORICAL_FEATURE_NAMES,
    NUMERIC_FEATURE_NAMES,
    TEXT_HASH_DIMENSION,
)
from shielddome_training import TrainingDataset, TrainingLabel, TrainingSample


def make_feature_vector(**changes) -> FeatureVector:
    vector = FeatureVector(
        numeric_features=tuple(
            (name, float(index % 5))
            for index, name in enumerate(NUMERIC_FEATURE_NAMES)
        ),
        categorical_features=(
            ("sender_domain_state", "present"),
            ("reply_to_domain_state", "present"),
            ("auth_spf_value", "pass"),
            ("auth_dkim_value", "pass"),
            ("auth_dmarc_value", "pass"),
            ("language", "mixed"),
        ),
        text_input=None,
        text_vector=tuple(
            1.0 if index == 0 else 0.0
            for index in range(TEXT_HASH_DIMENSION)
        ),
        missing_value_mask=(),
        schema_version=FEATURE_SCHEMA_VERSION,
    )
    return replace(vector, **changes)


def make_labeled_feature_vector(
    label: TrainingLabel,
    variant: int,
) -> FeatureVector:
    vector = make_feature_vector()
    numeric = dict(vector.numeric_features)
    phishing = label is TrainingLabel.PHISHING
    numeric.update(
        {
            "sender_reply_domain_match": 0.0 if phishing else 1.0,
            "auth_spf_present": 1.0,
            "auth_dkim_present": 1.0,
            "auth_dmarc_present": 1.0,
            "url_count": float((3 + variant) if phishing else (variant % 2)),
            "ip_literal_url_count": float(1 + variant % 2) if phishing else 0.0,
            "suspicious_port_url_count": 1.0 if phishing else 0.0,
            "dangerous_extension_count": float(variant % 2) if phishing else 0.0,
            "intent_credential_count": float(2 + variant) if phishing else 0.0,
            "intent_payment_count": float(1 + variant % 2) if phishing else 0.0,
            "intent_urgency_count": float(2 + variant % 2) if phishing else 0.0,
            "intent_impersonation_count": 1.0 if phishing else 0.0,
        }
    )
    text_values = [0.0] * TEXT_HASH_DIMENSION
    text_values[0 if phishing else 1] = 0.9
    text_values[2 + variant] = 0.1
    auth_value = "fail" if phishing else "pass"
    return replace(
        vector,
        numeric_features=tuple(
            (name, numeric[name]) for name in NUMERIC_FEATURE_NAMES
        ),
        categorical_features=(
            ("sender_domain_state", "present"),
            ("reply_to_domain_state", "present"),
            ("auth_spf_value", auth_value),
            ("auth_dkim_value", auth_value),
            ("auth_dmarc_value", auth_value),
            ("language", ("zh", "en", "mixed", "other")[variant]),
        ),
        text_vector=tuple(text_values),
    )


def utc_time(day: int) -> datetime:
    return datetime(2026, 7, day, 12, tzinfo=timezone.utc)


def make_training_sample(
    item_id: str,
    split: DatasetSplit,
    label: TrainingLabel,
    variant: int = 0,
    **changes,
) -> TrainingSample:
    sample = TrainingSample(
        item_id=item_id,
        feature_vector=make_labeled_feature_vector(label, variant),
        label=label,
        split=split,
        language_group=("zh", "en", "mixed", "other")[variant],
        source_group=("browser", "eml", "public-source", "synthetic")[variant],
        ingested_at=utc_time(
            25 if split is DatasetSplit.TEST else 15 if split is DatasetSplit.VALIDATION else 10
        ),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        corpus_schema_version=CORPUS_SCHEMA_VERSION,
        duplicate_group=f"duplicate-{item_id}",
        near_duplicate_group=f"near-{item_id}",
        template_group=f"template-{item_id}",
        campaign_group=f"campaign-{item_id}",
    )
    return replace(sample, **changes)


def make_minimal_dataset() -> TrainingDataset:
    samples = tuple(
        make_training_sample(
            f"{split.value}-{label.value}-{index}",
            split,
            label,
            variant=index,
        )
        for split in DatasetSplit
        for label in TrainingLabel
        for index in range(4)
    )
    return TrainingDataset(samples=samples, synthetic_only=True)
