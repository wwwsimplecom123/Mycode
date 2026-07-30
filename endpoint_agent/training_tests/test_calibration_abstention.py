from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest

import onnx


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))
sys.path.insert(0, str(ENDPOINT_ROOT / "training"))

from _fixtures import make_minimal_dataset
from shielddome_endpoint.corpus import DatasetSplit
from shielddome_training import BaselineExperiment, BaselineExperimentConfig
from shielddome_training import AbstentionThresholds, ConfidenceState
from shielddome_training import TrainingLabel


class CalibrationAndAbstentionTests(unittest.TestCase):
    def test_worse_validation_brier_selects_identity(self):
        dataset = make_minimal_dataset()
        validation_vectors = tuple(
            sample.feature_vector
            for sample in dataset.samples
            if sample.split is DatasetSplit.VALIDATION
        )

        with TemporaryDirectory() as temporary_directory:
            result = BaselineExperiment().run(
                dataset,
                BaselineExperimentConfig(Path(temporary_directory)),
            )

        selection = result.metadata.calibration
        self.assertEqual(selection.candidate_method, "sigmoid_on_validation_probability")
        self.assertEqual(selection.selected_method, "identity")
        self.assertEqual(selection.selection_reason, "validation_brier_not_improved")
        self.assertGreater(selection.brier_candidate, selection.brier_before)
        self.assertEqual(selection.brier_selected, selection.brier_before)
        self.assertEqual(
            result.probability_model.predict_probabilities(validation_vectors),
            result.probability_model.predict_uncalibrated_probabilities(
                validation_vectors
            ),
        )

    def test_better_validation_brier_selects_sigmoid(self):
        dataset = make_minimal_dataset()
        changed_samples = tuple(
            replace(
                sample,
                label=(
                    TrainingLabel.BENIGN
                    if sample.label is TrainingLabel.PHISHING
                    else TrainingLabel.PHISHING
                ),
            )
            if sample.split is DatasetSplit.VALIDATION
            else sample
            for sample in dataset.samples
        )

        with TemporaryDirectory() as temporary_directory:
            result = BaselineExperiment().run(
                replace(dataset, samples=changed_samples),
                BaselineExperimentConfig(Path(temporary_directory)),
            )

        selection = result.metadata.calibration
        self.assertEqual(
            selection.selected_method,
            "sigmoid_on_validation_probability",
        )
        self.assertEqual(selection.selection_reason, "validation_brier_improved")
        self.assertLess(selection.brier_candidate, selection.brier_before)
        self.assertEqual(selection.brier_selected, selection.brier_candidate)

    def test_improvement_tolerance_prevents_noise_level_calibration_switch(self):
        dataset = make_minimal_dataset()
        changed_dataset = replace(
            dataset,
            samples=tuple(
                replace(
                    sample,
                    label=(
                        TrainingLabel.BENIGN
                        if sample.label is TrainingLabel.PHISHING
                        else TrainingLabel.PHISHING
                    ),
                )
                if sample.split is DatasetSplit.VALIDATION
                else sample
                for sample in dataset.samples
            ),
        )

        with TemporaryDirectory() as temporary_directory:
            result = BaselineExperiment().run(
                changed_dataset,
                BaselineExperimentConfig(
                    Path(temporary_directory),
                    calibration_improvement_tolerance=1.0,
                ),
            )

        self.assertLess(
            result.metadata.calibration.brier_candidate,
            result.metadata.calibration.brier_before,
        )
        self.assertEqual(result.metadata.calibration.selected_method, "identity")
        self.assertEqual(
            result.metadata.calibration.selection_reason,
            "validation_brier_not_improved",
        )

    def test_identity_and_sigmoid_paths_are_onnx_runtime_consistent(self):
        identity_dataset = make_minimal_dataset()
        sigmoid_dataset = replace(
            identity_dataset,
            samples=tuple(
                replace(
                    sample,
                    label=(
                        TrainingLabel.BENIGN
                        if sample.label is TrainingLabel.PHISHING
                        else TrainingLabel.PHISHING
                    ),
                )
                if sample.split is DatasetSplit.VALIDATION
                else sample
                for sample in identity_dataset.samples
            ),
        )

        with TemporaryDirectory() as identity_directory, TemporaryDirectory() as sigmoid_directory:
            identity = BaselineExperiment().run(
                identity_dataset,
                BaselineExperimentConfig(Path(identity_directory)),
            )
            sigmoid = BaselineExperiment().run(
                sigmoid_dataset,
                BaselineExperimentConfig(Path(sigmoid_directory)),
            )
            identity_metadata = {
                item.key: item.value
                for item in onnx.load_model(identity.onnx_model_path).metadata_props
            }
            sigmoid_metadata = {
                item.key: item.value
                for item in onnx.load_model(sigmoid.onnx_model_path).metadata_props
            }

        self.assertEqual(identity.metadata.calibration.selected_method, "identity")
        self.assertEqual(
            sigmoid.metadata.calibration.selected_method,
            "sigmoid_on_validation_probability",
        )
        self.assertEqual(identity_metadata["calibration_method"], "identity")
        self.assertEqual(
            sigmoid_metadata["calibration_method"],
            "sigmoid_on_validation_probability",
        )
        self.assertTrue(identity.onnx_validation.consistent)
        self.assertTrue(sigmoid.onnx_validation.consistent)

    def test_calibration_metadata_records_validation_only_candidate_fit(self):
        dataset = make_minimal_dataset()
        validation_count = sum(
            sample.split is DatasetSplit.VALIDATION
            for sample in dataset.samples
        )

        with TemporaryDirectory() as temporary_directory:
            result = BaselineExperiment().run(
                dataset,
                BaselineExperimentConfig(
                    artifact_directory=Path(temporary_directory)
                ),
            )

        self.assertEqual(
            result.metadata.calibration.fitted_split,
            DatasetSplit.VALIDATION,
        )
        self.assertEqual(
            result.metadata.calibration.validation_sample_count,
            validation_count,
        )
        self.assertEqual(
            result.metadata.calibration.candidate_method,
            "sigmoid_on_validation_probability",
        )
        self.assertGreaterEqual(result.metadata.calibration.brier_before, 0.0)
        self.assertLessEqual(result.metadata.calibration.brier_before, 1.0)
        self.assertGreaterEqual(result.metadata.calibration.brier_candidate, 0.0)
        self.assertLessEqual(result.metadata.calibration.brier_candidate, 1.0)
        self.assertGreaterEqual(result.metadata.calibration.brier_selected, 0.0)
        self.assertLessEqual(result.metadata.calibration.brier_selected, 1.0)

    def test_abstention_thresholds_record_validation_selection_and_classify_boundaries(self):
        thresholds = AbstentionThresholds(
            benign_threshold=0.3,
            phishing_threshold=0.7,
            selection_objective="synthetic-objective",
            selection_split=DatasetSplit.VALIDATION,
        )

        self.assertEqual(thresholds.selection_split, DatasetSplit.VALIDATION)
        self.assertEqual(
            thresholds.classify(0.3),
            ConfidenceState.CONFIDENT_BENIGN,
        )
        self.assertEqual(thresholds.classify(0.5), ConfidenceState.UNCERTAIN)
        self.assertEqual(
            thresholds.classify(0.7),
            ConfidenceState.CONFIDENT_PHISHING,
        )
        with self.assertRaisesRegex(
            ValueError, "^invalid_abstention_thresholds$"
        ):
            AbstentionThresholds(
                benign_threshold=0.7,
                phishing_threshold=0.7,
                selection_objective="invalid",
                selection_split=DatasetSplit.VALIDATION,
            )

    def test_test_label_changes_do_not_change_model_calibration_or_thresholds(self):
        dataset = make_minimal_dataset()
        changed_samples = tuple(
            replace(
                sample,
                label=(
                    TrainingLabel.BENIGN
                    if sample.label is TrainingLabel.PHISHING
                    else TrainingLabel.PHISHING
                ),
            )
            if sample.split is DatasetSplit.TEST
            else sample
            for sample in dataset.samples
        )
        changed_dataset = replace(dataset, samples=changed_samples)
        probe_vectors = tuple(
            sample.feature_vector
            for sample in dataset.samples
            if sample.split is DatasetSplit.VALIDATION
        )

        with TemporaryDirectory() as first_directory, TemporaryDirectory() as second_directory:
            first = BaselineExperiment().run(
                dataset,
                BaselineExperimentConfig(Path(first_directory)),
            )
            changed = BaselineExperiment().run(
                changed_dataset,
                BaselineExperimentConfig(Path(second_directory)),
            )

        self.assertEqual(
            first.probability_model.predict_probabilities(probe_vectors),
            changed.probability_model.predict_probabilities(probe_vectors),
        )
        self.assertEqual(
            first.metadata.calibration,
            changed.metadata.calibration,
        )
        self.assertEqual(first.metadata.thresholds, changed.metadata.thresholds)
        self.assertEqual(first.metadata.onnx_sha256, changed.metadata.onnx_sha256)
        self.assertNotEqual(
            first.evaluation_report.to_json(),
            changed.evaluation_report.to_json(),
        )

    def test_insufficient_validation_samples_fail_without_using_test_data(self):
        dataset = make_minimal_dataset()
        removed_one_validation_phishing = False
        samples = []
        for sample in dataset.samples:
            if (
                sample.split is DatasetSplit.VALIDATION
                and sample.label is TrainingLabel.PHISHING
                and not removed_one_validation_phishing
            ):
                removed_one_validation_phishing = True
                continue
            samples.append(sample)
        samples = [
            sample
            for sample in samples
            if not (
                sample.split is DatasetSplit.VALIDATION
                and sample.label is TrainingLabel.PHISHING
                and sample.item_id.endswith(("-2", "-3"))
            )
        ]

        with TemporaryDirectory() as temporary_directory:
            with self.assertRaisesRegex(
                ValueError, "^insufficient_validation_samples$"
            ):
                BaselineExperiment().run(
                    replace(dataset, samples=tuple(samples)),
                    BaselineExperimentConfig(Path(temporary_directory)),
                )


if __name__ == "__main__":
    unittest.main()
