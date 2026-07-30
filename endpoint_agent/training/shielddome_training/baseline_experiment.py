from dataclasses import asdict, dataclass
from datetime import timezone
import hashlib
from importlib.metadata import version
import json
import math
from pathlib import Path
import re
from time import perf_counter

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper
import onnxruntime as ort
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

from shielddome_endpoint.corpus import CORPUS_SCHEMA_VERSION, DatasetSplit
from shielddome_endpoint.domain import FEATURE_SCHEMA_VERSION, FeatureVector

from .contracts import (
    AbstentionThresholds,
    BaselineExperimentConfig,
    BaselineExperimentResult,
    BaselineModelMetadata,
    CalibrationSelection,
    EvaluationMetrics,
    EvaluationReport,
    OnnxValidationResult,
    TrainingDataset,
    TrainingLabel,
    TrainingSample,
)
from .feature_assembler import ASSEMBLER_SCHEMA_VERSION, FeatureAssembler


SYNTHETIC_DISCLAIMER = (
    "This report uses only synthetic Phase 2 smoke-test data. "
    "It is not a production model evaluation and is not release evidence."
)
_GROUP_FIELDS = (
    "duplicate_group",
    "near_duplicate_group",
    "template_group",
    "campaign_group",
)
_DEPENDENCIES = (
    "numpy",
    "scipy",
    "scikit-learn",
    "onnx",
    "onnxruntime",
    "skl2onnx",
    "joblib",
)
_SAFE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?:password|passwd|token|api[_-]?key|authorization)[:=]"
)


@dataclass(frozen=True, slots=True)
class CalibratedProbabilityModel:
    assembler: FeatureAssembler
    base_model: LogisticRegression
    calibration_method: str
    calibration_coefficient: float
    calibration_intercept: float

    def predict_uncalibrated_probabilities(
        self,
        vectors: tuple[FeatureVector, ...],
    ) -> tuple[float, ...]:
        matrix = self.assembler.transform_many(vectors)
        if not len(matrix):
            return ()
        probabilities = self.base_model.predict_proba(matrix)[:, 1]
        return tuple(float(value) for value in probabilities)

    def predict_probabilities(
        self,
        vectors: tuple[FeatureVector, ...],
    ) -> tuple[float, ...]:
        raw = np.asarray(
            self.predict_uncalibrated_probabilities(vectors),
            dtype=np.float64,
        )
        if not len(raw):
            return ()
        if self.calibration_method == "identity":
            return tuple(float(value) for value in raw)
        logits = self.calibration_coefficient * raw + self.calibration_intercept
        calibrated = 1.0 / (1.0 + np.exp(-np.clip(logits, -709.0, 709.0)))
        calibrated = np.clip(calibrated, 0.0, 1.0)
        return tuple(float(value) for value in calibrated)


def _validate_dataset(
    dataset: TrainingDataset,
    config: BaselineExperimentConfig,
) -> None:
    if not dataset.synthetic_only:
        raise ValueError("phase_two_requires_synthetic_dataset")
    if not dataset.samples:
        raise ValueError("empty_training_dataset")
    if config.random_seed < 0 or config.max_iterations <= 0:
        raise ValueError("invalid_experiment_config")
    if not 0.0 < config.onnx_probability_tolerance < 1.0:
        raise ValueError("invalid_experiment_config")
    if (
        not math.isfinite(config.calibration_improvement_tolerance)
        or config.calibration_improvement_tolerance < 0.0
    ):
        raise ValueError("invalid_experiment_config")
    if (
        config.minimum_release_evaluation_group_size is not None
        and config.minimum_release_evaluation_group_size <= 0
    ):
        raise ValueError("invalid_experiment_config")
    if config.onnx_opset < 15:
        raise ValueError("invalid_experiment_config")
    if config.time_test_cutoff is not None and (
        config.time_test_cutoff.tzinfo is None
        or config.time_test_cutoff.utcoffset() is None
    ):
        raise ValueError("invalid_experiment_config")

    item_splits: dict[str, set[DatasetSplit]] = {}
    group_splits: dict[tuple[str, str], set[DatasetSplit]] = {}
    for sample in dataset.samples:
        identifiers = (
                sample.item_id,
                sample.language_group,
                sample.source_group,
                sample.duplicate_group,
                sample.near_duplicate_group,
                sample.template_group,
                sample.campaign_group,
            )
        if not all(value.strip() for value in identifiers):
            raise ValueError("missing_training_metadata")
        if any(
            _SAFE_IDENTIFIER_PATTERN.fullmatch(value) is None
            or _SENSITIVE_ASSIGNMENT_PATTERN.search(value) is not None
            for value in identifiers
        ):
            raise ValueError("unsafe_training_metadata")
        if sample.ingested_at.tzinfo is None or sample.ingested_at.utcoffset() is None:
            raise ValueError("invalid_ingestion_time")
        item_splits.setdefault(sample.item_id, set()).add(sample.split)
        for field_name in _GROUP_FIELDS:
            group_splits.setdefault(
                (field_name, getattr(sample, field_name)), set()
            ).add(sample.split)
    if any(len(splits) != 1 for splits in item_splits.values()) or any(
        len(splits) != 1 for splits in group_splits.values()
    ):
        raise ValueError("group_split_leakage")

    if any(
        sample.feature_schema_version != FEATURE_SCHEMA_VERSION
        or sample.feature_vector.schema_version != FEATURE_SCHEMA_VERSION
        for sample in dataset.samples
    ):
        raise ValueError("feature_schema_mismatch")
    if any(
        sample.corpus_schema_version != CORPUS_SCHEMA_VERSION
        for sample in dataset.samples
    ):
        raise ValueError("corpus_schema_mismatch")

    split_labels: dict[DatasetSplit, list[TrainingLabel]] = {
        split: [] for split in DatasetSplit
    }
    for sample in dataset.samples:
        split_labels[sample.split].append(sample.label)
    for split, labels in split_labels.items():
        minimum = 2 if split is DatasetSplit.VALIDATION else 1
        if any(labels.count(label) < minimum for label in TrainingLabel):
            error = (
                "insufficient_validation_samples"
                if split is DatasetSplit.VALIDATION
                else f"insufficient_{split.value}_samples"
            )
            raise ValueError(error)


def _ordered_samples(
    dataset: TrainingDataset,
    split: DatasetSplit,
) -> tuple[TrainingSample, ...]:
    return tuple(
        sorted(
            (sample for sample in dataset.samples if sample.split is split),
            key=lambda sample: sample.item_id,
        )
    )


def _labels(samples: tuple[TrainingSample, ...]) -> np.ndarray:
    return np.asarray(
        [int(sample.label is TrainingLabel.PHISHING) for sample in samples],
        dtype=np.int64,
    )


def _select_thresholds(
    probabilities: tuple[float, ...],
    labels: np.ndarray,
) -> tuple[AbstentionThresholds, tuple[tuple[str, float], ...]]:
    candidates = sorted({0.0, 1.0, *probabilities})
    best: tuple | None = None
    best_values: tuple[float, float, int, int] | None = None
    for benign_threshold in candidates:
        for phishing_threshold in candidates:
            if benign_threshold >= phishing_threshold:
                continue
            states = tuple(
                0
                if value <= benign_threshold
                else 1 if value >= phishing_threshold else -1
                for value in probabilities
            )
            errors = sum(
                state != -1 and state != int(label)
                for state, label in zip(states, labels, strict=True)
            )
            classified = sum(state != -1 for state in states)
            score = (
                errors,
                -classified,
                phishing_threshold - benign_threshold,
                benign_threshold,
                phishing_threshold,
            )
            if best is None or score < best:
                best = score
                best_values = (
                    benign_threshold,
                    phishing_threshold,
                    errors,
                    classified,
                )
    if best_values is None:
        raise ValueError("threshold_selection_failed")
    benign_threshold, phishing_threshold, errors, classified = best_values
    thresholds = AbstentionThresholds(
        benign_threshold=float(benign_threshold),
        phishing_threshold=float(phishing_threshold),
        selection_objective=(
            "minimize_validation_high_confidence_errors_then_maximize_coverage"
        ),
        selection_split=DatasetSplit.VALIDATION,
    )
    sample_count = len(probabilities)
    metrics = (
        ("high_confidence_errors", float(errors)),
        ("classified_count", float(classified)),
        ("abstention_rate", float((sample_count - classified) / sample_count)),
    )
    return thresholds, metrics


def _evaluate_group(
    samples: tuple[TrainingSample, ...],
    probabilities: tuple[float, ...],
    durations: tuple[float, ...],
    thresholds: AbstentionThresholds,
    status: str,
) -> EvaluationMetrics:
    states = tuple(thresholds.classify(value) for value in probabilities)
    return EvaluationMetrics.from_predictions(
        labels=tuple(sample.label for sample in samples),
        probabilities=probabilities,
        states=states,
        inference_durations_ms=durations,
        status=status,
    )


def _evaluation_report(
    test_samples: tuple[TrainingSample, ...],
    model: CalibratedProbabilityModel,
    thresholds: AbstentionThresholds,
    config: BaselineExperimentConfig,
) -> EvaluationReport:
    probabilities: list[float] = []
    durations: list[float] = []
    for sample in test_samples:
        started = perf_counter()
        probability = model.predict_probabilities((sample.feature_vector,))[0]
        durations.append((perf_counter() - started) * 1000.0)
        probabilities.append(probability)

    indexed = tuple(zip(test_samples, probabilities, durations, strict=True))

    def evaluation_status(sample_count: int) -> str:
        if sample_count == 0:
            return "not_evaluated"
        minimum = config.minimum_release_evaluation_group_size
        if minimum is None:
            return "not_release_evaluable"
        if sample_count < minimum:
            return "insufficient_sample"
        return "evaluated"

    def group_metrics(predicate) -> EvaluationMetrics:
        selected = tuple(item for item in indexed if predicate(item[0]))
        return _evaluate_group(
            tuple(item[0] for item in selected),
            tuple(item[1] for item in selected),
            tuple(item[2] for item in selected),
            thresholds,
            evaluation_status(len(selected)),
        )

    groups: list[tuple[str, EvaluationMetrics]] = [
        ("overall", group_metrics(lambda sample: True))
    ]
    for language in ("zh", "en", "mixed"):
        groups.append(
            (
                f"language:{language}",
                group_metrics(lambda sample, value=language: sample.language_group == value),
            )
        )
    for source in sorted({sample.source_group for sample in test_samples}):
        groups.append(
            (
                f"source:{source}",
                group_metrics(lambda sample, value=source: sample.source_group == value),
            )
        )
    if config.time_test_cutoff is not None:
        cutoff = config.time_test_cutoff.astimezone(timezone.utc)
        groups.append(
            (
                "time:test",
                group_metrics(
                    lambda sample: sample.ingested_at.astimezone(timezone.utc) > cutoff
                ),
            )
        )
    return EvaluationReport(
        synthetic_only=True,
        release_eligible=False,
        release_eligibility_status="not_release_evaluable",
        release_eligibility_reason="synthetic_dataset_no_approved_corpus",
        disclaimer=SYNTHETIC_DISCLAIMER,
        groups=tuple(groups),
    )


def _export_calibrated_onnx(
    model: CalibratedProbabilityModel,
    assembler: FeatureAssembler,
    config: BaselineExperimentConfig,
    output_path: Path,
) -> onnx.ModelProto:
    converted = convert_sklearn(
        model.base_model,
        initial_types=[
            ("features", FloatTensorType([None, assembler.output_dimension]))
        ],
        options={id(model.base_model): {"zipmap": False}},
        target_opset=config.onnx_opset,
    )
    converted.graph.name = "shielddome_phase2_logistic_selected_calibration"
    probability_output = next(
        output.name
        for output in converted.graph.output
        if output.type.tensor_type.elem_type == TensorProto.FLOAT
    )
    del converted.graph.output[:]

    converted.graph.initializer.extend(
        (
            numpy_helper.from_array(np.asarray([1], dtype=np.int64), "phishing_index"),
            numpy_helper.from_array(np.asarray([1.0], dtype=np.float32), "one"),
        )
    )
    converted.graph.node.append(
        helper.make_node(
            "Gather",
            (probability_output, "phishing_index"),
            ("raw_phishing_probability",),
            axis=1,
            name="select_phishing_probability",
        )
    )
    if model.calibration_method == "sigmoid_on_validation_probability":
        converted.graph.initializer.extend(
            (
                numpy_helper.from_array(
                    np.asarray([model.calibration_coefficient], dtype=np.float32),
                    "calibration_coefficient",
                ),
                numpy_helper.from_array(
                    np.asarray([model.calibration_intercept], dtype=np.float32),
                    "calibration_intercept",
                ),
            )
        )
        converted.graph.node.extend(
            (
                helper.make_node(
                    "Mul",
                    ("raw_phishing_probability", "calibration_coefficient"),
                    ("scaled_probability",),
                    name="apply_calibration_scale",
                ),
                helper.make_node(
                    "Add",
                    ("scaled_probability", "calibration_intercept"),
                    ("calibration_logit",),
                    name="apply_calibration_intercept",
                ),
                helper.make_node(
                    "Sigmoid",
                    ("calibration_logit",),
                    ("selected_phishing_probability",),
                    name="calibrated_sigmoid",
                ),
            )
        )
    else:
        converted.graph.node.append(
            helper.make_node(
                "Identity",
                ("raw_phishing_probability",),
                ("selected_phishing_probability",),
                name="identity_calibration",
            )
        )
    converted.graph.node.extend(
        (
            helper.make_node(
                "Sub",
                ("one", "selected_phishing_probability"),
                ("selected_benign_probability",),
                name="derive_benign_probability",
            ),
            helper.make_node(
                "Concat",
                ("selected_benign_probability", "selected_phishing_probability"),
                ("selected_probabilities",),
                axis=1,
                name="combine_selected_probabilities",
            ),
        )
    )
    converted.graph.output.extend(
        (
            helper.make_tensor_value_info(
                "selected_probabilities",
                TensorProto.FLOAT,
                [None, 2],
            ),
        )
    )
    for key, value in (
        ("feature_schema_version", FEATURE_SCHEMA_VERSION),
        ("corpus_schema_version", CORPUS_SCHEMA_VERSION),
        ("assembler_schema_version", ASSEMBLER_SCHEMA_VERSION),
        ("input_dimension", str(assembler.output_dimension)),
        ("model_type", "logistic-regression-with-selected-calibration"),
        ("calibration_method", model.calibration_method),
        ("synthetic_only", "true"),
    ):
        property_value = converted.metadata_props.add()
        property_value.key = key
        property_value.value = value
    onnx.checker.check_model(converted, full_check=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(converted.SerializeToString(deterministic=True))
    return converted


def _validate_onnx(
    path: Path,
    model: CalibratedProbabilityModel,
    vectors: tuple[FeatureVector, ...],
    assembler: FeatureAssembler,
    expected_opset: int,
    tolerance: float,
) -> OnnxValidationResult:
    model_proto = onnx.load_model(path, load_external_data=False)
    metadata = {item.key: item.value for item in model_proto.metadata_props}
    expected_metadata = {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "corpus_schema_version": CORPUS_SCHEMA_VERSION,
        "assembler_schema_version": ASSEMBLER_SCHEMA_VERSION,
        "input_dimension": str(assembler.output_dimension),
        "model_type": "logistic-regression-with-selected-calibration",
        "calibration_method": model.calibration_method,
        "synthetic_only": "true",
    }
    opsets = {item.domain: item.version for item in model_proto.opset_import}
    if metadata != expected_metadata or opsets.get("") != expected_opset:
        raise ValueError("onnx_metadata_mismatch")
    session_options = ort.SessionOptions()
    session_options.intra_op_num_threads = 1
    session_options.inter_op_num_threads = 1
    session_options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    session = ort.InferenceSession(
        str(path),
        sess_options=session_options,
        providers=["CPUExecutionProvider"],
    )
    input_meta = session.get_inputs()[0]
    if input_meta.shape[-1] != assembler.output_dimension:
        raise ValueError("onnx_input_dimension_mismatch")
    matrix = assembler.transform_many(vectors)
    onnx_probabilities = session.run(
        ["selected_probabilities"],
        {input_meta.name: matrix},
    )[0][:, 1]
    python_probabilities = np.asarray(
        model.predict_probabilities(vectors), dtype=np.float64
    )
    maximum_error = float(
        np.max(np.abs(onnx_probabilities.astype(np.float64) - python_probabilities))
    )
    consistent = maximum_error <= tolerance
    if not consistent:
        raise ValueError("onnx_probability_mismatch")
    return OnnxValidationResult(
        runtime_provider=session.get_providers()[0],
        input_name=input_meta.name,
        input_dimension=assembler.output_dimension,
        compared_sample_count=len(vectors),
        metadata_validated=True,
        maximum_absolute_error=maximum_error,
        tolerance=tolerance,
        consistent=True,
    )


def _metadata_dict(metadata: BaselineModelMetadata) -> dict:
    payload = asdict(metadata)
    payload["thresholds"]["selection_objective"] = metadata.thresholds.selection_objective
    return payload


class BaselineExperiment:
    def run(
        self,
        dataset: TrainingDataset,
        config: BaselineExperimentConfig,
    ) -> BaselineExperimentResult:
        _validate_dataset(dataset, config)
        assembler = FeatureAssembler()
        train_samples = _ordered_samples(dataset, DatasetSplit.TRAIN)
        validation_samples = _ordered_samples(dataset, DatasetSplit.VALIDATION)
        test_samples = _ordered_samples(dataset, DatasetSplit.TEST)

        train_matrix = assembler.transform_many(
            tuple(sample.feature_vector for sample in train_samples)
        )
        train_labels = _labels(train_samples)
        base_model = LogisticRegression(
            class_weight="balanced",
            max_iter=config.max_iterations,
            random_state=config.random_seed,
            solver="liblinear",
        )
        base_model.fit(train_matrix, train_labels)

        validation_vectors = tuple(
            sample.feature_vector for sample in validation_samples
        )
        validation_matrix = assembler.transform_many(validation_vectors)
        validation_labels = _labels(validation_samples)
        raw_validation = base_model.predict_proba(validation_matrix)[:, 1]
        calibrator = LogisticRegression(
            class_weight="balanced",
            max_iter=config.max_iterations,
            random_state=config.random_seed,
            solver="lbfgs",
        )
        calibrator.fit(raw_validation.reshape(-1, 1), validation_labels)
        candidate_model = CalibratedProbabilityModel(
            assembler=assembler,
            base_model=base_model,
            calibration_method="sigmoid_on_validation_probability",
            calibration_coefficient=float(calibrator.coef_[0, 0]),
            calibration_intercept=float(calibrator.intercept_[0]),
        )
        candidate_validation = candidate_model.predict_probabilities(
            validation_vectors
        )
        brier_before = float(brier_score_loss(validation_labels, raw_validation))
        brier_candidate = float(
            brier_score_loss(validation_labels, candidate_validation)
        )
        if (
            brier_candidate + config.calibration_improvement_tolerance
            < brier_before
        ):
            selected_method = "sigmoid_on_validation_probability"
            selection_reason = "validation_brier_improved"
            selected_validation = candidate_validation
        else:
            selected_method = "identity"
            selection_reason = "validation_brier_not_improved"
            selected_validation = tuple(float(value) for value in raw_validation)
        probability_model = CalibratedProbabilityModel(
            assembler=assembler,
            base_model=base_model,
            calibration_method=selected_method,
            calibration_coefficient=candidate_model.calibration_coefficient,
            calibration_intercept=candidate_model.calibration_intercept,
        )
        calibration_selection = CalibrationSelection(
            candidate_method="sigmoid_on_validation_probability",
            selected_method=selected_method,
            selection_reason=selection_reason,
            improvement_tolerance=config.calibration_improvement_tolerance,
            brier_before=brier_before,
            brier_candidate=brier_candidate,
            brier_selected=(
                brier_candidate if selected_method != "identity" else brier_before
            ),
            fitted_split=DatasetSplit.VALIDATION,
            validation_sample_count=len(validation_samples),
            candidate_parameters=(
                ("coefficient", candidate_model.calibration_coefficient),
                ("intercept", candidate_model.calibration_intercept),
            ),
        )
        thresholds, threshold_metrics = _select_thresholds(
            selected_validation,
            validation_labels,
        )

        artifact_directory = Path(config.artifact_directory)
        artifact_directory.mkdir(parents=True, exist_ok=True)
        onnx_path = artifact_directory / "baseline_model.onnx"
        model_proto = _export_calibrated_onnx(
            probability_model,
            assembler,
            config,
            onnx_path,
        )
        if any(
            initializer.data_location == TensorProto.EXTERNAL
            or initializer.external_data
            for initializer in model_proto.graph.initializer
        ):
            raise ValueError("onnx_external_data_not_allowed")
        allowed_domains = {"", "ai.onnx.ml"}
        if any(node.domain not in allowed_domains for node in model_proto.graph.node):
            raise ValueError("onnx_custom_operator_not_allowed")

        validation_vectors_for_onnx = tuple(
            sample.feature_vector
            for sample in sorted(dataset.samples, key=lambda sample: sample.item_id)[:8]
        )
        onnx_validation = _validate_onnx(
            onnx_path,
            probability_model,
            validation_vectors_for_onnx,
            assembler,
            config.onnx_opset,
            config.onnx_probability_tolerance,
        )
        onnx_bytes = onnx_path.read_bytes()
        onnx_size = len(onnx_bytes)
        if onnx_size >= 2 * 1024 * 1024 * 1024:
            raise ValueError("onnx_model_size_limit_exceeded")

        report = _evaluation_report(
            test_samples,
            probability_model,
            thresholds,
            config,
        )
        metadata = BaselineModelMetadata(
            model_type="logistic-regression-with-selected-calibration",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            corpus_schema_version=CORPUS_SCHEMA_VERSION,
            assembler_schema_version=ASSEMBLER_SCHEMA_VERSION,
            feature_names=assembler.feature_names,
            input_dimension=assembler.output_dimension,
            random_seed=config.random_seed,
            max_iterations=config.max_iterations,
            class_weight="balanced",
            calibration=calibration_selection,
            calibration_method=selected_method,
            calibration_fitted_split=DatasetSplit.VALIDATION,
            calibration_sample_count=len(validation_samples),
            calibration_parameters=(
                ("coefficient", probability_model.calibration_coefficient),
                ("intercept", probability_model.calibration_intercept),
            ),
            validation_brier_before=brier_before,
            validation_brier_after=calibration_selection.brier_selected,
            thresholds=thresholds,
            validation_threshold_metrics=threshold_metrics,
            onnx_opset=config.onnx_opset,
            onnx_sha256=hashlib.sha256(onnx_bytes).hexdigest(),
            onnx_size_bytes=onnx_size,
            training_dependency_versions=tuple(
                (dependency, version(dependency)) for dependency in _DEPENDENCIES
            ),
            synthetic_only=True,
        )

        json_report_path = artifact_directory / "evaluation.json"
        markdown_report_path = artifact_directory / "evaluation.md"
        json_payload = {
            "evaluation": json.loads(report.to_json()),
            "model_metadata": _metadata_dict(metadata),
            "onnx_validation": asdict(onnx_validation),
        }
        json_report_path.write_text(
            json.dumps(json_payload, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        markdown_report_path.write_text(
            report.to_markdown()
            + "\n## Model Metadata\n\n"
            + f"- Model type: `{metadata.model_type}`\n"
            + f"- Feature schema: `{metadata.feature_schema_version}`\n"
            + f"- Corpus schema: `{metadata.corpus_schema_version}`\n"
            + f"- Input dimension: `{metadata.input_dimension}`\n"
            + f"- ONNX opset: `{metadata.onnx_opset}`\n"
            + f"- ONNX SHA-256: `{metadata.onnx_sha256}`\n"
            + f"- ONNX size: `{metadata.onnx_size_bytes}` bytes\n",
            encoding="utf-8",
        )
        with markdown_report_path.open("a", encoding="utf-8", newline="") as output:
            output.write(
                "\n## Calibration\n\n"
                f"- Candidate method: `{metadata.calibration.candidate_method}`\n"
                f"- Selected method: `{metadata.calibration.selected_method}`\n"
                f"- Selection reason: `{metadata.calibration.selection_reason}`\n"
                f"- Improvement tolerance: `{metadata.calibration.improvement_tolerance:.12g}`\n"
                f"- Fitted split: `{metadata.calibration.fitted_split.value}`\n"
                f"- Validation samples: `{metadata.calibration.validation_sample_count}`\n"
                f"- Validation Brier before: `{metadata.calibration.brier_before:.8f}`\n"
                f"- Validation Brier candidate: `{metadata.calibration.brier_candidate:.8f}`\n"
                f"- Validation Brier selected: `{metadata.calibration.brier_selected:.8f}`\n"
                f"- Benign threshold: `{metadata.thresholds.benign_threshold:.8f}`\n"
                f"- Phishing threshold: `{metadata.thresholds.phishing_threshold:.8f}`\n"
                f"- Selection objective: `{metadata.thresholds.selection_objective}`\n"
                "\n## ONNX Validation\n\n"
                f"- Runtime provider: `{onnx_validation.runtime_provider}`\n"
                f"- Compared samples: `{onnx_validation.compared_sample_count}`\n"
                f"- Maximum absolute error: `{onnx_validation.maximum_absolute_error:.10g}`\n"
                f"- Tolerance: `{onnx_validation.tolerance:.10g}`\n"
                f"- Consistent: `{str(onnx_validation.consistent).lower()}`\n"
            )

        return BaselineExperimentResult(
            probability_model=probability_model,
            metadata=metadata,
            evaluation_report=report,
            onnx_validation=onnx_validation,
            onnx_model_path=onnx_path,
            json_report_path=json_report_path,
            markdown_report_path=markdown_report_path,
        )
