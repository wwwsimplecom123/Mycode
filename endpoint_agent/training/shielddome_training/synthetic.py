from datetime import datetime, timezone

from shielddome_endpoint.corpus import CORPUS_SCHEMA_VERSION, DatasetSplit
from shielddome_endpoint.domain import MailObservation
from shielddome_endpoint.feature_pipeline import FeaturePipeline

from .contracts import TrainingDataset, TrainingLabel, TrainingSample


_LANGUAGES = ("zh", "en", "mixed", "other")
_SOURCES = ("browser", "eml", "public-source", "synthetic")


def _observation(
    label: TrainingLabel,
    split: DatasetSplit,
    variant: int,
) -> MailObservation:
    phishing = label is TrainingLabel.PHISHING
    if variant == 0:
        body = "请立即验证账户密码并联系财务。" if phishing else "团队例会安排已更新。"
    elif variant == 1:
        body = (
            "Urgent login password and invoice payment verification."
            if phishing
            else "The synthetic team meeting schedule is available."
        )
    elif variant == 2:
        body = (
            "紧急 urgent login 密码 payment verification."
            if phishing
            else "团队 team schedule 已更新."
        )
    else:
        body = "20260730 998877" if phishing else "20260730 112233"
    sender_domain = "alerts.example.test" if phishing else "corp.example.test"
    reply_domain = "support.example.test" if phishing else sender_domain
    auth_value = "fail" if phishing else "pass"
    attachment = "notice.pdf.exe" if phishing else "agenda.txt"
    day = 25 if split is DatasetSplit.TEST else 15 if split is DatasetSplit.VALIDATION else 10
    return MailObservation(
        source_kind=_SOURCES[variant],
        source_message_id=f"synthetic-{split.value}-{label.value}-{variant}",
        subject=(
            "Synthetic urgent verification"
            if phishing
            else "Synthetic team notice"
        ),
        sender=f"sender@{sender_domain}",
        reply_to=f"reply@{reply_domain}",
        recipient_summary=("synthetic-current-user",),
        sanitized_body_text=body,
        authentication_observations=(
            ("spf", auth_value),
            ("dkim", auth_value),
            ("dmarc", auth_value),
        ),
        normalized_links=("portal.example.test/item",) if phishing else (),
        attachment_metadata=(("name", attachment),),
        language_hint=_LANGUAGES[variant] if variant < 3 else None,
        observed_at=datetime(2026, 7, day, 12, tzinfo=timezone.utc),
    )


def build_synthetic_dataset() -> TrainingDataset:
    pipeline = FeaturePipeline()
    samples: list[TrainingSample] = []
    for split in DatasetSplit:
        for label in TrainingLabel:
            for variant in range(4):
                item_id = f"{split.value}-{label.value}-{variant}"
                observation = _observation(label, split, variant)
                vector = pipeline.transform(observation)
                samples.append(
                    TrainingSample(
                        item_id=item_id,
                        feature_vector=vector,
                        label=label,
                        split=split,
                        language_group=_LANGUAGES[variant],
                        source_group=_SOURCES[variant],
                        ingested_at=observation.observed_at,
                        feature_schema_version=vector.schema_version,
                        corpus_schema_version=CORPUS_SCHEMA_VERSION,
                        duplicate_group=f"duplicate-{item_id}",
                        near_duplicate_group=f"near-{item_id}",
                        template_group=f"template-{item_id}",
                        campaign_group=f"campaign-{item_id}",
                    )
                )
    return TrainingDataset(samples=tuple(samples), synthetic_only=True)
