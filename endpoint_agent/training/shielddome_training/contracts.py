from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
import json
import math
from typing import TYPE_CHECKING

import numpy as np
from sklearn.metrics import (
    auc,
    brier_score_loss,
    precision_recall_curve,
    roc_auc_score,
)

from shielddome_endpoint.corpus import DatasetSplit
from shielddome_endpoint.domain import FeatureVector

if TYPE_CHECKING:
    from .baseline_experiment import CalibratedProbabilityModel


class TrainingLabel(StrEnum):
    BENIGN = "benign"
    PHISHING = "phishing"


class ConfidenceState(StrEnum):
    CONFIDENT_BENIGN = "confident-benign"
    UNCERTAIN = "uncertain"
    CONFIDENT_PHISHING = "confident-phishing"


@dataclass(frozen=True, slots=True)
class TrainingSample:
    item_id: str
    feature_vector: FeatureVector
    label: TrainingLabel
    split: DatasetSplit
    language_group: str
    source_group: str
    ingested_at: datetime
    feature_schema_version: str
    corpus_schema_version: str
    duplicate_group: str
    near_duplicate_group: str
    template_group: str
    campaign_group: str


@dataclass(frozen=True, slots=True)
class TrainingDataset:
    samples: tuple[TrainingSample, ...]
    synthetic_only: bool


@dataclass(frozen=True, slots=True)
class BaselineExperimentConfig:
    artifact_directory: Path
    random_seed: int = 20260730
    max_iterations: int = 1000
    onnx_opset: int = 17
    onnx_probability_tolerance: float = 1e-6
    calibration_improvement_tolerance: float = 1e-12
    minimum_release_evaluation_group_size: int | None = None
    time_test_cutoff: datetime | None = None


@dataclass(frozen=True, slots=True)
class AbstentionThresholds:
    benign_threshold: float
    phishing_threshold: float
    selection_objective: str
    selection_split: DatasetSplit

    def __post_init__(self) -> None:
        if not (
            0.0 <= self.benign_threshold < self.phishing_threshold <= 1.0
        ):
            raise ValueError("invalid_abstention_thresholds")
        if self.selection_split is not DatasetSplit.VALIDATION:
            raise ValueError("invalid_abstention_selection_split")

    def classify(self, probability: float) -> ConfidenceState:
        if not 0.0 <= probability <= 1.0:
            raise ValueError("invalid_probability")
        if probability <= self.benign_threshold:
            return ConfidenceState.CONFIDENT_BENIGN
        if probability >= self.phishing_threshold:
            return ConfidenceState.CONFIDENT_PHISHING
        return ConfidenceState.UNCERTAIN


@dataclass(frozen=True, slots=True)
class CalibrationSelection:
    candidate_method: str
    selected_method: str
    selection_reason: str
    improvement_tolerance: float
    brier_before: float
    brier_candidate: float
    brier_selected: float
    fitted_split: DatasetSplit
    validation_sample_count: int
    candidate_parameters: tuple[tuple[str, float], ...]


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    status: str
    sample_count: int
    classified_count: int
    total_phishing_count: int
    total_benign_count: int
    confident_benign_count: int
    confident_phishing_count: int
    uncertain_count: int
    uncertain_phishing_count: int
    uncertain_benign_count: int
    phishing_recall: float | None
    benign_false_positive_rate: float | None
    precision: float | None
    f1: float | None
    roc_auc: float | None
    pr_auc: float | None
    brier_score: float | None
    high_confidence_phishing_precision: float | None
    abstention_rate: float | None
    phishing_abstention_rate: float | None
    benign_abstention_rate: float | None
    confusion_matrix: tuple[tuple[int, int, int], tuple[int, int, int]] | None
    inference_duration_ms: tuple[tuple[str, float], ...] | None

    @classmethod
    def from_predictions(
        cls,
        labels: tuple[TrainingLabel, ...],
        probabilities: tuple[float, ...],
        states: tuple[ConfidenceState, ...],
        inference_durations_ms: tuple[float, ...],
        *,
        status: str,
    ) -> "EvaluationMetrics":
        if not (
            len(labels)
            == len(probabilities)
            == len(states)
            == len(inference_durations_ms)
        ):
            raise ValueError("evaluation_input_length_mismatch")
        if not labels:
            return cls(
                status="not_evaluated",
                sample_count=0,
                classified_count=0,
                total_phishing_count=0,
                total_benign_count=0,
                confident_benign_count=0,
                confident_phishing_count=0,
                uncertain_count=0,
                uncertain_phishing_count=0,
                uncertain_benign_count=0,
                phishing_recall=None,
                benign_false_positive_rate=None,
                precision=None,
                f1=None,
                roc_auc=None,
                pr_auc=None,
                brier_score=None,
                high_confidence_phishing_precision=None,
                abstention_rate=None,
                phishing_abstention_rate=None,
                benign_abstention_rate=None,
                confusion_matrix=None,
                inference_duration_ms=None,
            )
        if any(
            not math.isfinite(value) or not 0.0 <= value <= 1.0
            for value in probabilities
        ) or any(
            not math.isfinite(value) or value < 0.0
            for value in inference_durations_ms
        ):
            raise ValueError("invalid_evaluation_input")

        total_phishing = sum(label is TrainingLabel.PHISHING for label in labels)
        total_benign = len(labels) - total_phishing
        confident_benign = sum(
            state is ConfidenceState.CONFIDENT_BENIGN for state in states
        )
        confident_phishing = sum(
            state is ConfidenceState.CONFIDENT_PHISHING for state in states
        )
        uncertain = len(states) - confident_benign - confident_phishing
        uncertain_phishing = sum(
            label is TrainingLabel.PHISHING
            and state is ConfidenceState.UNCERTAIN
            for label, state in zip(labels, states, strict=True)
        )
        uncertain_benign = sum(
            label is TrainingLabel.BENIGN
            and state is ConfidenceState.UNCERTAIN
            for label, state in zip(labels, states, strict=True)
        )
        benign_confident_benign = sum(
            label is TrainingLabel.BENIGN
            and state is ConfidenceState.CONFIDENT_BENIGN
            for label, state in zip(labels, states, strict=True)
        )
        benign_confident_phishing = sum(
            label is TrainingLabel.BENIGN
            and state is ConfidenceState.CONFIDENT_PHISHING
            for label, state in zip(labels, states, strict=True)
        )
        phishing_confident_benign = sum(
            label is TrainingLabel.PHISHING
            and state is ConfidenceState.CONFIDENT_BENIGN
            for label, state in zip(labels, states, strict=True)
        )
        phishing_confident_phishing = sum(
            label is TrainingLabel.PHISHING
            and state is ConfidenceState.CONFIDENT_PHISHING
            for label, state in zip(labels, states, strict=True)
        )
        recall = (
            phishing_confident_phishing / total_phishing
            if total_phishing
            else None
        )
        false_positive_rate = (
            benign_confident_phishing / total_benign if total_benign else None
        )
        precision = (
            phishing_confident_phishing / confident_phishing
            if confident_phishing
            else None
        )
        f1 = (
            2.0 * precision * recall / (precision + recall)
            if precision is not None
            and recall is not None
            and precision + recall
            else None
        )
        numeric_labels = np.asarray(
            [int(label is TrainingLabel.PHISHING) for label in labels],
            dtype=np.int64,
        )
        unique_labels = set(int(value) for value in numeric_labels)
        roc_auc = (
            float(roc_auc_score(numeric_labels, probabilities))
            if len(unique_labels) == 2
            else None
        )
        if len(unique_labels) == 2:
            curve_precision, curve_recall, _ = precision_recall_curve(
                numeric_labels, probabilities
            )
            pr_auc = float(auc(curve_recall, curve_precision))
        else:
            pr_auc = None
        ordered_durations = tuple(sorted(inference_durations_ms))
        percentile_index = min(
            len(ordered_durations) - 1,
            math.ceil(len(ordered_durations) * 0.95) - 1,
        )
        duration_summary = (
            ("minimum", float(ordered_durations[0])),
            ("mean", float(sum(ordered_durations) / len(ordered_durations))),
            ("p95", float(ordered_durations[percentile_index])),
            ("maximum", float(ordered_durations[-1])),
        )
        return cls(
            status=status,
            sample_count=len(labels),
            classified_count=confident_benign + confident_phishing,
            total_phishing_count=total_phishing,
            total_benign_count=total_benign,
            confident_benign_count=confident_benign,
            confident_phishing_count=confident_phishing,
            uncertain_count=uncertain,
            uncertain_phishing_count=uncertain_phishing,
            uncertain_benign_count=uncertain_benign,
            phishing_recall=recall,
            benign_false_positive_rate=false_positive_rate,
            precision=precision,
            f1=f1,
            roc_auc=roc_auc,
            pr_auc=pr_auc,
            brier_score=float(brier_score_loss(numeric_labels, probabilities)),
            high_confidence_phishing_precision=precision,
            abstention_rate=float(uncertain / len(labels)),
            phishing_abstention_rate=(
                uncertain_phishing / total_phishing if total_phishing else None
            ),
            benign_abstention_rate=(
                uncertain_benign / total_benign if total_benign else None
            ),
            confusion_matrix=(
                (
                    benign_confident_benign,
                    uncertain_benign,
                    benign_confident_phishing,
                ),
                (
                    phishing_confident_benign,
                    uncertain_phishing,
                    phishing_confident_phishing,
                ),
            ),
            inference_duration_ms=duration_summary,
        )

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "sample_count": self.sample_count,
            "classified_count": self.classified_count,
            "total_phishing_count": self.total_phishing_count,
            "total_benign_count": self.total_benign_count,
            "confident_benign_count": self.confident_benign_count,
            "confident_phishing_count": self.confident_phishing_count,
            "uncertain_count": self.uncertain_count,
            "uncertain_phishing_count": self.uncertain_phishing_count,
            "uncertain_benign_count": self.uncertain_benign_count,
            "phishing_recall": self.phishing_recall,
            "benign_false_positive_rate": self.benign_false_positive_rate,
            "precision": self.precision,
            "f1": self.f1,
            "roc_auc": self.roc_auc,
            "pr_auc": self.pr_auc,
            "brier_score": self.brier_score,
            "high_confidence_phishing_precision": self.high_confidence_phishing_precision,
            "abstention_rate": self.abstention_rate,
            "phishing_abstention_rate": self.phishing_abstention_rate,
            "benign_abstention_rate": self.benign_abstention_rate,
            "confusion_matrix": self.confusion_matrix,
            "inference_duration_ms": (
                dict(self.inference_duration_ms)
                if self.inference_duration_ms is not None
                else None
            ),
        }


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    synthetic_only: bool
    release_eligible: bool
    release_eligibility_status: str
    release_eligibility_reason: str
    disclaimer: str
    groups: tuple[tuple[str, EvaluationMetrics], ...]

    def to_json(self) -> str:
        payload = {
            "synthetic_only": self.synthetic_only,
            "release_eligible": self.release_eligible,
            "release_eligibility_status": self.release_eligibility_status,
            "release_eligibility_reason": self.release_eligibility_reason,
            "disclaimer": self.disclaimer,
            "groups": {
                name: metrics.to_dict() for name, metrics in self.groups
            },
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    def to_markdown(self) -> str:
        lines = [
            "# ShieldDome Phase 2 Synthetic Baseline Evaluation",
            "",
            f"> {self.disclaimer}",
            "",
            "- Synthetic only: `true`",
            "- Release eligible: `false`",
            f"- Release eligibility status: `{self.release_eligibility_status}`",
            f"- Release eligibility reason: `{self.release_eligibility_reason}`",
            "",
            "## Metric definitions",
            "",
            "- Formal phishing recall: true phishing predicted confident-phishing / all true phishing.",
            "- Benign false-positive rate: true benign predicted confident-phishing / all true benign.",
            "- High-confidence phishing precision: true phishing predicted confident-phishing / all confident-phishing predictions.",
            "- Uncertain samples remain in the true-label denominators and are counted separately.",
            "- Confusion matrix rows: actual benign, actual phishing; columns: confident-benign, uncertain, confident-phishing.",
            "",
            "| Group | Status | Samples | Phishing | Benign | Conf. benign | Uncertain | Conf. phishing | Uncertain phishing | Uncertain benign | Formal recall | Benign FPR | HC phishing precision | F1 | ROC AUC | PR AUC | Brier | Abstention | Phishing abstention | Benign abstention |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]

        def display(value: float | None) -> str:
            return "not_evaluated" if value is None else f"{value:.6f}"

        for name, metrics in self.groups:
            lines.append(
                "| "
                + " | ".join(
                    (
                        name,
                        metrics.status,
                        str(metrics.sample_count),
                        str(metrics.total_phishing_count),
                        str(metrics.total_benign_count),
                        str(metrics.confident_benign_count),
                        str(metrics.uncertain_count),
                        str(metrics.confident_phishing_count),
                        str(metrics.uncertain_phishing_count),
                        str(metrics.uncertain_benign_count),
                        display(metrics.phishing_recall),
                        display(metrics.benign_false_positive_rate),
                        display(metrics.high_confidence_phishing_precision),
                        display(metrics.f1),
                        display(metrics.roc_auc),
                        display(metrics.pr_auc),
                        display(metrics.brier_score),
                        display(metrics.abstention_rate),
                        display(metrics.phishing_abstention_rate),
                        display(metrics.benign_abstention_rate),
                    )
                )
                + " |"
            )
        return "\n".join(lines) + "\n"


@dataclass(frozen=True, slots=True)
class BaselineModelMetadata:
    model_type: str
    feature_schema_version: str
    corpus_schema_version: str
    assembler_schema_version: str
    feature_names: tuple[str, ...]
    input_dimension: int
    random_seed: int
    max_iterations: int
    class_weight: str
    calibration: CalibrationSelection
    calibration_method: str
    calibration_fitted_split: DatasetSplit
    calibration_sample_count: int
    calibration_parameters: tuple[tuple[str, float], ...]
    validation_brier_before: float
    validation_brier_after: float
    thresholds: AbstentionThresholds
    validation_threshold_metrics: tuple[tuple[str, float], ...]
    onnx_opset: int
    onnx_sha256: str
    onnx_size_bytes: int
    training_dependency_versions: tuple[tuple[str, str], ...]
    synthetic_only: bool


@dataclass(frozen=True, slots=True)
class OnnxValidationResult:
    runtime_provider: str
    input_name: str
    input_dimension: int
    compared_sample_count: int
    metadata_validated: bool
    maximum_absolute_error: float
    tolerance: float
    consistent: bool


@dataclass(frozen=True, slots=True)
class BaselineExperimentResult:
    probability_model: "CalibratedProbabilityModel"
    metadata: BaselineModelMetadata
    evaluation_report: EvaluationReport
    onnx_validation: OnnxValidationResult
    onnx_model_path: Path
    json_report_path: Path
    markdown_report_path: Path
