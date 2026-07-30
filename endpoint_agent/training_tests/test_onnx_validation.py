import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest

import onnx
from onnx import TensorProto


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))
sys.path.insert(0, str(ENDPOINT_ROOT / "training"))

from _fixtures import make_minimal_dataset
from shielddome_training import BaselineExperiment, BaselineExperimentConfig


class OnnxValidationTests(unittest.TestCase):
    def test_onnx_is_self_describing_standard_bounded_and_runtime_consistent(self):
        dataset = make_minimal_dataset()
        with TemporaryDirectory() as temporary_directory:
            result = BaselineExperiment().run(
                dataset,
                BaselineExperimentConfig(Path(temporary_directory)),
            )
            model_bytes = result.onnx_model_path.read_bytes()
            model = onnx.load_model(
                result.onnx_model_path,
                load_external_data=False,
            )

        onnx.checker.check_model(model, full_check=True)
        metadata = {item.key: item.value for item in model.metadata_props}
        self.assertEqual(metadata["feature_schema_version"], "2.0")
        self.assertEqual(metadata["corpus_schema_version"], "2.0")
        self.assertEqual(metadata["assembler_schema_version"], "1.0")
        self.assertEqual(metadata["input_dimension"], "140")
        self.assertEqual(
            metadata["model_type"],
            "logistic-regression-with-selected-calibration",
        )
        self.assertEqual(
            metadata["calibration_method"],
            result.metadata.calibration.selected_method,
        )
        self.assertTrue(
            all(node.domain in {"", "ai.onnx.ml"} for node in model.graph.node)
        )
        self.assertFalse(
            any(
                initializer.data_location == TensorProto.EXTERNAL
                or initializer.external_data
                for initializer in model.graph.initializer
            )
        )
        self.assertLess(len(model_bytes), 2 * 1024 * 1024 * 1024)
        self.assertEqual(result.metadata.onnx_size_bytes, len(model_bytes))
        self.assertEqual(
            result.metadata.onnx_sha256,
            hashlib.sha256(model_bytes).hexdigest(),
        )
        self.assertEqual(result.metadata.onnx_opset, 17)
        self.assertEqual(result.onnx_validation.runtime_provider, "CPUExecutionProvider")
        self.assertEqual(result.onnx_validation.input_dimension, 140)
        self.assertTrue(result.onnx_validation.metadata_validated)
        self.assertTrue(result.onnx_validation.consistent)
        self.assertLessEqual(
            result.onnx_validation.maximum_absolute_error,
            result.onnx_validation.tolerance,
        )
        opsets = {item.domain: item.version for item in model.opset_import}
        self.assertEqual(opsets[""], 17)


if __name__ == "__main__":
    unittest.main()
