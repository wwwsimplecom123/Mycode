from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import socket
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))
sys.path.insert(0, str(ENDPOINT_ROOT / "training"))

from _fixtures import make_minimal_dataset
from shielddome_endpoint.corpus import DatasetSplit
from shielddome_training import BaselineExperiment, BaselineExperimentConfig


class TrainingBoundaryTests(unittest.TestCase):
    def test_rejects_group_crossing_dataset_splits_before_training(self):
        dataset = make_minimal_dataset()
        first = dataset.samples[0]
        test_index = next(
            index
            for index, sample in enumerate(dataset.samples)
            if sample.split is DatasetSplit.TEST
        )
        leaking_test = replace(
            dataset.samples[test_index],
            duplicate_group=first.duplicate_group,
        )
        samples = list(dataset.samples)
        samples[test_index] = leaking_test

        with TemporaryDirectory() as temporary_directory:
            config = BaselineExperimentConfig(
                artifact_directory=Path(temporary_directory)
            )
            with self.assertRaisesRegex(ValueError, "^group_split_leakage$"):
                BaselineExperiment().run(
                    replace(dataset, samples=tuple(samples)),
                    config,
                )

    def test_rejects_incompatible_feature_and_corpus_schema(self):
        dataset = make_minimal_dataset()
        incompatible = replace(
            dataset.samples[0],
            corpus_schema_version="future",
        )
        samples = (incompatible,) + dataset.samples[1:]

        with TemporaryDirectory() as temporary_directory:
            config = BaselineExperimentConfig(
                artifact_directory=Path(temporary_directory)
            )
            with self.assertRaisesRegex(ValueError, "^corpus_schema_mismatch$"):
                BaselineExperiment().run(
                    replace(dataset, samples=samples),
                    config,
                )

    def test_fixed_seed_training_probabilities_and_parameters_are_repeatable(self):
        dataset = make_minimal_dataset()
        test_vectors = tuple(
            sample.feature_vector
            for sample in dataset.samples
            if sample.split is DatasetSplit.TEST
        )

        with TemporaryDirectory() as first_directory, TemporaryDirectory() as second_directory:
            first = BaselineExperiment().run(
                dataset,
                BaselineExperimentConfig(
                    artifact_directory=Path(first_directory)
                ),
            )
            second = BaselineExperiment().run(
                dataset,
                BaselineExperimentConfig(
                    artifact_directory=Path(second_directory)
                ),
            )

        first_probabilities = first.probability_model.predict_probabilities(
            test_vectors
        )
        second_probabilities = second.probability_model.predict_probabilities(
            test_vectors
        )
        self.assertEqual(first_probabilities, second_probabilities)
        self.assertTrue(all(0.0 <= value <= 1.0 for value in first_probabilities))
        self.assertEqual(
            first.metadata.calibration,
            second.metadata.calibration,
        )
        self.assertEqual(first.metadata.thresholds, second.metadata.thresholds)
        self.assertEqual(first.metadata.random_seed, 20260730)
        self.assertEqual(first.metadata.class_weight, "balanced")

    def test_rejects_invalid_calibration_tolerance_and_release_sample_floor(self):
        dataset = make_minimal_dataset()
        invalid_options = (
            {"calibration_improvement_tolerance": -1.0},
            {"calibration_improvement_tolerance": float("nan")},
            {"minimum_release_evaluation_group_size": 0},
        )

        for options in invalid_options:
            with self.subTest(options=options), TemporaryDirectory() as temporary_directory:
                with self.assertRaisesRegex(
                    ValueError, "^invalid_experiment_config$"
                ):
                    BaselineExperiment().run(
                        dataset,
                        BaselineExperimentConfig(
                            Path(temporary_directory),
                            **options,
                        ),
                    )

    def test_complete_experiment_does_not_connect_or_listen_on_network_sockets(self):
        dataset = make_minimal_dataset()
        with TemporaryDirectory() as temporary_directory:
            config = BaselineExperimentConfig(Path(temporary_directory))
            with (
                patch.object(
                    socket.socket,
                    "connect",
                    side_effect=AssertionError("network_connect_forbidden"),
                ),
                patch.object(
                    socket.socket,
                    "connect_ex",
                    side_effect=AssertionError("network_connect_forbidden"),
                ),
                patch.object(
                    socket.socket,
                    "bind",
                    side_effect=AssertionError("network_listener_forbidden"),
                ),
                patch.object(
                    socket.socket,
                    "listen",
                    side_effect=AssertionError("network_listener_forbidden"),
                ),
            ):
                result = BaselineExperiment().run(dataset, config)

        self.assertTrue(result.onnx_validation.consistent)


if __name__ == "__main__":
    unittest.main()
