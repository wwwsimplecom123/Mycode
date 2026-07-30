from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))
sys.path.insert(0, str(ENDPOINT_ROOT / "training"))

from _fixtures import make_minimal_dataset
from shielddome_endpoint.corpus import DatasetSplit
from shielddome_training import (
    BaselineExperiment,
    BaselineExperimentConfig,
    ConfidenceState,
    EvaluationMetrics,
    TrainingLabel,
)


class EvaluationReportingTests(unittest.TestCase):
    def test_synthetic_report_is_not_release_evaluable_without_approved_corpus(self):
        with TemporaryDirectory() as temporary_directory:
            result = BaselineExperiment().run(
                make_minimal_dataset(),
                BaselineExperimentConfig(Path(temporary_directory)),
            )

        report = result.evaluation_report
        self.assertFalse(report.release_eligible)
        self.assertEqual(report.release_eligibility_status, "not_release_evaluable")
        self.assertEqual(
            report.release_eligibility_reason,
            "synthetic_dataset_no_approved_corpus",
        )
        self.assertTrue(
            all(
                metrics.status in {"not_release_evaluable", "not_evaluated"}
                for _, metrics in report.groups
            )
        )

    def test_explicit_release_sample_floor_marks_small_groups_insufficient(self):
        with TemporaryDirectory() as temporary_directory:
            result = BaselineExperiment().run(
                make_minimal_dataset(),
                BaselineExperimentConfig(
                    Path(temporary_directory),
                    minimum_release_evaluation_group_size=10,
                ),
            )

        overall = dict(result.evaluation_report.groups)["overall"]
        self.assertEqual(overall.status, "insufficient_sample")
        self.assertEqual(overall.sample_count, 8)
        self.assertIsNotNone(overall.phishing_recall)
        self.assertFalse(result.evaluation_report.release_eligible)

    def test_formal_metrics_keep_uncertain_samples_in_label_denominators(self):
        metrics = EvaluationMetrics.from_predictions(
            labels=(
                TrainingLabel.PHISHING,
                TrainingLabel.PHISHING,
                TrainingLabel.BENIGN,
                TrainingLabel.BENIGN,
            ),
            probabilities=(0.5, 0.2, 0.5, 0.8),
            states=(
                ConfidenceState.UNCERTAIN,
                ConfidenceState.CONFIDENT_BENIGN,
                ConfidenceState.UNCERTAIN,
                ConfidenceState.CONFIDENT_PHISHING,
            ),
            inference_durations_ms=(1.0, 1.0, 1.0, 1.0),
            status="not_release_evaluable",
        )

        self.assertEqual(metrics.total_phishing_count, 2)
        self.assertEqual(metrics.total_benign_count, 2)
        self.assertEqual(metrics.uncertain_phishing_count, 1)
        self.assertEqual(metrics.uncertain_benign_count, 1)
        self.assertEqual(metrics.phishing_recall, 0.0)
        self.assertEqual(metrics.benign_false_positive_rate, 0.5)
        self.assertEqual(metrics.high_confidence_phishing_precision, 0.0)
        self.assertEqual(
            metrics.confusion_matrix,
            ((0, 1, 1), (1, 1, 0)),
        )

    def test_all_uncertain_phishing_has_zero_recall_and_full_phishing_abstention(self):
        metrics = EvaluationMetrics.from_predictions(
            labels=(TrainingLabel.PHISHING, TrainingLabel.PHISHING),
            probabilities=(0.4, 0.6),
            states=(ConfidenceState.UNCERTAIN, ConfidenceState.UNCERTAIN),
            inference_durations_ms=(1.0, 2.0),
            status="not_release_evaluable",
        )

        self.assertEqual(metrics.phishing_recall, 0.0)
        self.assertEqual(metrics.phishing_abstention_rate, 1.0)
        self.assertEqual(metrics.uncertain_phishing_count, 2)
        self.assertEqual(metrics.confusion_matrix, ((0, 0, 0), (0, 2, 0)))

    def test_high_confidence_precision_only_uses_confident_phishing(self):
        metrics = EvaluationMetrics.from_predictions(
            labels=(
                TrainingLabel.PHISHING,
                TrainingLabel.BENIGN,
                TrainingLabel.PHISHING,
            ),
            probabilities=(0.9, 0.8, 0.5),
            states=(
                ConfidenceState.CONFIDENT_PHISHING,
                ConfidenceState.CONFIDENT_PHISHING,
                ConfidenceState.UNCERTAIN,
            ),
            inference_durations_ms=(1.0, 1.0, 1.0),
            status="not_release_evaluable",
        )

        self.assertEqual(metrics.high_confidence_phishing_precision, 0.5)
        self.assertEqual(metrics.phishing_recall, 0.5)
        self.assertEqual(metrics.benign_false_positive_rate, 1.0)
        self.assertEqual(
            metrics.sample_count,
            metrics.total_phishing_count + metrics.total_benign_count,
        )
        self.assertEqual(
            metrics.uncertain_count,
            metrics.uncertain_phishing_count + metrics.uncertain_benign_count,
        )

    def test_rejects_private_or_network_metadata_before_report_generation(self):
        dataset = make_minimal_dataset()
        test_index = next(
            index
            for index, sample in enumerate(dataset.samples)
            if sample.split is DatasetSplit.TEST
        )
        samples = list(dataset.samples)
        samples[test_index] = replace(
            samples[test_index],
            source_group="C:\\Users\\Fictional\\private-corpus",
        )

        with TemporaryDirectory() as temporary_directory:
            with self.assertRaisesRegex(
                ValueError, "^unsafe_training_metadata$"
            ):
                BaselineExperiment().run(
                    replace(dataset, samples=tuple(samples)),
                    BaselineExperimentConfig(Path(temporary_directory)),
                )

    def test_reports_required_test_groups_metrics_and_synthetic_disclaimer(self):
        dataset = make_minimal_dataset()
        with TemporaryDirectory() as temporary_directory:
            result = BaselineExperiment().run(
                dataset,
                BaselineExperimentConfig(
                    Path(temporary_directory),
                    time_test_cutoff=datetime(
                        2026, 7, 20, tzinfo=timezone.utc
                    ),
                ),
            )
            json_text = result.json_report_path.read_text(encoding="utf-8")
            markdown_text = result.markdown_report_path.read_text(encoding="utf-8")

        groups = dict(result.evaluation_report.groups)
        expected_groups = {
            "overall",
            "language:zh",
            "language:en",
            "language:mixed",
            "source:browser",
            "source:eml",
            "source:public-source",
            "source:synthetic",
            "time:test",
        }
        self.assertTrue(expected_groups.issubset(groups))
        overall = groups["overall"]
        self.assertEqual(overall.status, "not_release_evaluable")
        self.assertEqual(overall.sample_count, 8)
        for group_name, metrics in groups.items():
            if metrics.status == "not_evaluated":
                continue
            with self.subTest(group=group_name):
                self.assertEqual(
                    metrics.sample_count,
                    metrics.total_phishing_count + metrics.total_benign_count,
                )
                self.assertEqual(
                    metrics.uncertain_count,
                    metrics.uncertain_phishing_count
                    + metrics.uncertain_benign_count,
                )
                self.assertEqual(
                    metrics.sample_count,
                    sum(sum(row) for row in metrics.confusion_matrix or ()),
                )
                if metrics.total_phishing_count:
                    self.assertEqual(
                        metrics.phishing_recall,
                        (metrics.confusion_matrix or ((0, 0, 0), (0, 0, 0)))[1][2]
                        / metrics.total_phishing_count,
                    )
                if metrics.total_benign_count:
                    self.assertEqual(
                        metrics.benign_false_positive_rate,
                        (metrics.confusion_matrix or ((0, 0, 0), (0, 0, 0)))[0][2]
                        / metrics.total_benign_count,
                    )
        self.assertGreaterEqual(overall.abstention_rate or 0.0, 0.0)
        self.assertIsNotNone(overall.confusion_matrix)
        self.assertIsNotNone(overall.inference_duration_ms)
        self.assertFalse(result.evaluation_report.release_eligible)
        self.assertTrue(result.evaluation_report.synthetic_only)
        payload = json.loads(json_text)
        self.assertFalse(payload["evaluation"]["release_eligible"])
        self.assertEqual(
            payload["evaluation"]["release_eligibility_status"],
            "not_release_evaluable",
        )
        self.assertIn("model_metadata", payload)
        self.assertIn("onnx_validation", payload)
        self.assertIn("synthetic", markdown_text.casefold())
        self.assertIn("Formal phishing recall", markdown_text)
        self.assertIn(
            "confident-benign, uncertain, confident-phishing",
            markdown_text,
        )
        self.assertIn("## Calibration", markdown_text)
        self.assertIn("Candidate method", markdown_text)
        self.assertIn("Selected method", markdown_text)
        self.assertIn("Validation Brier candidate", markdown_text)
        self.assertIn("Validation Brier selected", markdown_text)
        self.assertIn("## ONNX Validation", markdown_text)

    def test_empty_language_and_time_groups_are_not_evaluated(self):
        dataset = make_minimal_dataset()
        samples = tuple(
            sample
            for sample in dataset.samples
            if not (
                sample.split is DatasetSplit.TEST
                and sample.language_group == "mixed"
            )
        )
        with TemporaryDirectory() as temporary_directory:
            result = BaselineExperiment().run(
                replace(dataset, samples=samples),
                BaselineExperimentConfig(
                    Path(temporary_directory),
                    time_test_cutoff=datetime(
                        2026, 7, 30, tzinfo=timezone.utc
                    ),
                ),
            )

        groups = dict(result.evaluation_report.groups)
        mixed = groups["language:mixed"]
        time_test = groups["time:test"]
        self.assertEqual(mixed.status, "not_evaluated")
        self.assertEqual(mixed.sample_count, 0)
        self.assertIsNone(mixed.roc_auc)
        self.assertIsNone(mixed.confusion_matrix)
        self.assertEqual(time_test.status, "not_evaluated")
        self.assertIsNone(time_test.abstention_rate)

    def test_artifacts_do_not_contain_mail_text_credentials_urls_or_private_paths(self):
        dataset = make_minimal_dataset()
        forbidden_values = (
            "Synthetic private mail body",
            "password=fictional-secret",
            "token=fictional-token",
            "https://portal.example.test/login?token=fictional",
            "C:\\Users\\Fictional\\private-mail.eml",
        )
        with TemporaryDirectory() as temporary_directory:
            result = BaselineExperiment().run(
                dataset,
                BaselineExperimentConfig(Path(temporary_directory)),
            )
            artifact_content = b"\n".join(
                path.read_bytes()
                for path in (
                    result.json_report_path,
                    result.markdown_report_path,
                    result.onnx_model_path,
                )
            )

        for forbidden_value in forbidden_values:
            self.assertNotIn(forbidden_value.encode("utf-8"), artifact_content)


if __name__ == "__main__":
    unittest.main()
