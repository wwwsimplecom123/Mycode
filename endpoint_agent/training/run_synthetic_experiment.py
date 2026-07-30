import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_training import BaselineExperiment, BaselineExperimentConfig
from shielddome_training.synthetic import build_synthetic_dataset


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the offline Phase 2 synthetic baseline experiment."
    )
    parser.add_argument(
        "--artifact-directory",
        type=Path,
        default=ENDPOINT_ROOT / "training" / "artifacts" / "synthetic",
    )
    arguments = parser.parse_args()
    dataset = build_synthetic_dataset()
    result = BaselineExperiment().run(
        dataset,
        BaselineExperimentConfig(
            artifact_directory=arguments.artifact_directory,
            time_test_cutoff=datetime(2026, 7, 20, tzinfo=timezone.utc),
        ),
    )
    summary = {
        "synthetic_only": True,
        "release_eligible": False,
        "sample_count": len(dataset.samples),
        "model_type": result.metadata.model_type,
        "calibration_candidate_method": (
            result.metadata.calibration.candidate_method
        ),
        "calibration_selected_method": (
            result.metadata.calibration.selected_method
        ),
        "calibration_selection_reason": (
            result.metadata.calibration.selection_reason
        ),
        "validation_brier_before": result.metadata.calibration.brier_before,
        "validation_brier_candidate": (
            result.metadata.calibration.brier_candidate
        ),
        "validation_brier_selected": (
            result.metadata.calibration.brier_selected
        ),
        "release_eligibility_status": (
            result.evaluation_report.release_eligibility_status
        ),
        "release_eligibility_reason": (
            result.evaluation_report.release_eligibility_reason
        ),
        "onnx_sha256": result.metadata.onnx_sha256,
        "onnx_size_bytes": result.metadata.onnx_size_bytes,
        "onnx_maximum_absolute_error": (
            result.onnx_validation.maximum_absolute_error
        ),
        "onnx_tolerance": result.onnx_validation.tolerance,
        "onnx_consistent": result.onnx_validation.consistent,
        "json_report": str(result.json_report_path),
        "markdown_report": str(result.markdown_report_path),
        "disclaimer": result.evaluation_report.disclaimer,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
