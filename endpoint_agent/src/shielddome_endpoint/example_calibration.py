from dataclasses import dataclass
from enum import StrEnum
import math

from .confirmed_examples import (
    ConfirmedExampleValidationError,
    ExampleLabel,
    validate_example_feature_vector,
)
from .domain import FeatureVector
from .example_store import ExampleStore


EXAMPLE_APPROXIMATE_MIN_MATCHES = 3
EXAMPLE_APPROXIMATE_SIMILARITY_THRESHOLD = 0.94
EXAMPLE_BENIGN_ADJUSTMENT = -8
EXAMPLE_PHISHING_ADJUSTMENT = 18


class ExampleCalibrationStatus(StrEnum):
    NO_EXAMPLES = "no_examples"
    EXACT_APPLIED = "exact_applied"
    SIMILAR_APPLIED = "similar_applied"
    REJECTED_LOW_SIMILARITY = "rejected_low_similarity"
    REJECTED_INSUFFICIENT = "rejected_insufficient"
    REJECTED_CONFLICT = "rejected_conflict"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ExampleCalibration:
    status: ExampleCalibrationStatus
    adjustment: int
    supporting_examples: int

    def __post_init__(self) -> None:
        exact_valid = (
            self.status is ExampleCalibrationStatus.EXACT_APPLIED
            and self.adjustment
            in {EXAMPLE_BENIGN_ADJUSTMENT, EXAMPLE_PHISHING_ADJUSTMENT}
            and self.supporting_examples == 1
        )
        similar_valid = (
            self.status is ExampleCalibrationStatus.SIMILAR_APPLIED
            and self.adjustment
            in {EXAMPLE_BENIGN_ADJUSTMENT, EXAMPLE_PHISHING_ADJUSTMENT}
            and self.supporting_examples >= EXAMPLE_APPROXIMATE_MIN_MATCHES
        )
        rejected_valid = (
            self.status
            in {
                ExampleCalibrationStatus.NO_EXAMPLES,
                ExampleCalibrationStatus.REJECTED_LOW_SIMILARITY,
                ExampleCalibrationStatus.REJECTED_INSUFFICIENT,
                ExampleCalibrationStatus.REJECTED_CONFLICT,
                ExampleCalibrationStatus.FAILED,
            }
            and self.adjustment == 0
            and self.supporting_examples == 0
        )
        if not (exact_valid or similar_valid or rejected_valid):
            raise ValueError("invalid_example_calibration")

    @classmethod
    def failed(cls) -> "ExampleCalibration":
        return cls(
            status=ExampleCalibrationStatus.FAILED,
            adjustment=0,
            supporting_examples=0,
        )


class ExampleCalibrator:
    def __init__(self, store: ExampleStore) -> None:
        self._store = store

    def calibrate(self, feature_vector: FeatureVector) -> ExampleCalibration:
        try:
            validate_example_feature_vector(feature_vector)
        except ConfirmedExampleValidationError:
            raise ValueError("invalid_calibration_input") from None
        exact = self._store.find_exact(feature_vector)
        if len(exact) == 1:
            adjustment = (
                EXAMPLE_BENIGN_ADJUSTMENT
                if exact[0].label is ExampleLabel.BENIGN
                else EXAMPLE_PHISHING_ADJUSTMENT
            )
            return ExampleCalibration(
                status=ExampleCalibrationStatus.EXACT_APPLIED,
                adjustment=adjustment,
                supporting_examples=1,
            )
        if len(exact) > 1:
            return ExampleCalibration(
                status=ExampleCalibrationStatus.REJECTED_CONFLICT,
                adjustment=0,
                supporting_examples=0,
            )
        candidates = self._store.list_for_calibration()
        if not candidates:
            return ExampleCalibration(
                status=ExampleCalibrationStatus.NO_EXAMPLES,
                adjustment=0,
                supporting_examples=0,
            )
        grouped = {}
        for candidate in candidates:
            grouped.setdefault(candidate.keyed_fingerprint, []).append(candidate)
        qualifying_labels = []
        conflict = False
        for examples in grouped.values():
            if (
                _feature_similarity(feature_vector, examples[0].feature_vector)
                < EXAMPLE_APPROXIMATE_SIMILARITY_THRESHOLD
            ):
                continue
            labels = {example.label for example in examples}
            if len(labels) != 1:
                conflict = True
            else:
                qualifying_labels.append(next(iter(labels)))
        if not qualifying_labels and not conflict:
            return ExampleCalibration(
                status=ExampleCalibrationStatus.REJECTED_LOW_SIMILARITY,
                adjustment=0,
                supporting_examples=0,
            )
        if conflict or len(set(qualifying_labels)) != 1:
            return ExampleCalibration(
                status=ExampleCalibrationStatus.REJECTED_CONFLICT,
                adjustment=0,
                supporting_examples=0,
            )
        if len(qualifying_labels) < EXAMPLE_APPROXIMATE_MIN_MATCHES:
            return ExampleCalibration(
                status=ExampleCalibrationStatus.REJECTED_INSUFFICIENT,
                adjustment=0,
                supporting_examples=0,
            )
        label = qualifying_labels[0]
        return ExampleCalibration(
            status=ExampleCalibrationStatus.SIMILAR_APPLIED,
            adjustment=(
                EXAMPLE_BENIGN_ADJUSTMENT
                if label is ExampleLabel.BENIGN
                else EXAMPLE_PHISHING_ADJUSTMENT
            ),
            supporting_examples=len(qualifying_labels),
        )


def _feature_similarity(first: FeatureVector, second: FeatureVector) -> float:
    first_text = first.text_vector or ()
    second_text = second.text_vector or ()
    first_norm = math.sqrt(sum(value * value for value in first_text))
    second_norm = math.sqrt(sum(value * value for value in second_text))
    if first_norm == 0.0 and second_norm == 0.0:
        cosine = 1.0
    elif first_norm == 0.0 or second_norm == 0.0:
        cosine = 0.0
    else:
        cosine = sum(
            left * right for left, right in zip(first_text, second_text)
        ) / (first_norm * second_norm)
    numeric_similarity = sum(
        1.0 - abs(left - right) / max(1.0, abs(left), abs(right))
        for (_, left), (_, right) in zip(
            first.numeric_features,
            second.numeric_features,
        )
    ) / len(first.numeric_features)
    categorical_similarity = sum(
        left == right
        for (_, left), (_, right) in zip(
            first.categorical_features,
            second.categorical_features,
        )
    ) / len(first.categorical_features)
    return (
        0.75 * max(0.0, cosine)
        + 0.15 * numeric_similarity
        + 0.10 * categorical_similarity
    )


__all__ = [
    "EXAMPLE_APPROXIMATE_MIN_MATCHES",
    "EXAMPLE_APPROXIMATE_SIMILARITY_THRESHOLD",
    "EXAMPLE_BENIGN_ADJUSTMENT",
    "EXAMPLE_PHISHING_ADJUSTMENT",
    "ExampleCalibration",
    "ExampleCalibrationStatus",
    "ExampleCalibrator",
]
