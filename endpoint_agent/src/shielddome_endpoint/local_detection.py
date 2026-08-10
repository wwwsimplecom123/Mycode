from collections.abc import Callable
from datetime import datetime

from .detection_kernel import DetectionKernel
from .example_calibration import ExampleCalibration, ExampleCalibrator
from .domain import (
    MAIL_OBSERVATION_SCHEMA_VERSION,
    DetectionOutcome,
    MailObservation,
)
from .feature_pipeline import FeaturePipeline
from .inference import InferenceContext, LocalInference, UnavailableModelAdapter
from .rule_evaluator import LocalRuleEvaluator


LOCAL_INFERENCE_BUDGET_MS = 3_000


def _is_string_pair_tuple(value: object) -> bool:
    return isinstance(value, tuple) and all(
        isinstance(item, tuple)
        and len(item) == 2
        and all(isinstance(part, str) for part in item)
        for item in value
    )


def _validate_observation(observation: MailObservation) -> None:
    if (
        not isinstance(observation, MailObservation)
        or observation.schema_version != MAIL_OBSERVATION_SCHEMA_VERSION
        or not isinstance(observation.source_kind, str)
        or not isinstance(observation.source_message_id, str)
        or not isinstance(observation.subject, str)
        or not isinstance(observation.sender, str)
        or not (
            observation.reply_to is None
            or isinstance(observation.reply_to, str)
        )
        or not isinstance(observation.recipient_summary, tuple)
        or not all(
            isinstance(recipient, str)
            for recipient in observation.recipient_summary
        )
        or not isinstance(observation.sanitized_body_text, str)
        or not _is_string_pair_tuple(observation.authentication_observations)
        or not isinstance(observation.normalized_links, tuple)
        or not all(
            isinstance(link, str) for link in observation.normalized_links
        )
        or not _is_string_pair_tuple(observation.attachment_metadata)
        or not (
            observation.language_hint is None
            or isinstance(observation.language_hint, str)
        )
        or not isinstance(observation.observed_at, datetime)
        or observation.observed_at.tzinfo is None
        or observation.observed_at.utcoffset() is None
    ):
        raise ValueError("invalid_mail_observation")


class LocalDetectionService:
    def __init__(
        self,
        inference: LocalInference | None = None,
        *,
        example_calibrator: ExampleCalibrator | None = None,
        feature_sink: Callable[[str, object, datetime], None] | None = None,
    ) -> None:
        adapter = inference if inference is not None else UnavailableModelAdapter()
        self._feature_pipeline = FeaturePipeline()
        self._rule_evaluator = LocalRuleEvaluator()
        self._kernel = DetectionKernel(adapter)
        self._example_calibrator = example_calibrator
        self._feature_sink = feature_sink

    def detect(
        self,
        observation: MailObservation,
        *,
        local_event_id: str,
        observed_now: datetime,
    ) -> DetectionOutcome:
        _validate_observation(observation)
        features = self._feature_pipeline.transform(observation)
        if self._feature_sink is not None:
            try:
                self._feature_sink(local_event_id, features, observed_now)
            except Exception:
                pass
        rules = self._rule_evaluator.evaluate(features)
        calibration = None
        if self._example_calibrator is not None:
            try:
                candidate = self._example_calibrator.calibrate(features)
                calibration = (
                    candidate
                    if isinstance(candidate, ExampleCalibration)
                    else ExampleCalibration.failed()
                )
            except Exception:
                calibration = ExampleCalibration.failed()
        return self._kernel.detect(
            features,
            rules,
            local_event_id=local_event_id,
            detected_at=observed_now,
            inference_context=InferenceContext(LOCAL_INFERENCE_BUDGET_MS),
            example_calibration=calibration,
        )


def default_local_detection_service(*, feature_sink=None) -> LocalDetectionService:
    from .example_store import ExampleStore

    return LocalDetectionService(
        example_calibrator=ExampleCalibrator(ExampleStore()),
        feature_sink=feature_sink,
    )


__all__ = [
    "LOCAL_INFERENCE_BUDGET_MS",
    "LocalDetectionService",
    "default_local_detection_service",
]
