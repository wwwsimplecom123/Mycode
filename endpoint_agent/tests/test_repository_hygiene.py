from pathlib import Path
import subprocess
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class RepositoryHygieneTests(unittest.TestCase):
    def assert_endpoint_path_is_ignored(self, relative_path: str):
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", "--", relative_path],
            cwd=REPOSITORY_ROOT,
            check=False,
        )
        self.assertEqual(result.returncode, 0, relative_path)

    def test_model_files_and_model_packages_are_ignored(self):
        for relative_path in (
            "endpoint_agent/models/unified.onnx",
            "endpoint_agent/model_packages/release.zip",
        ):
            with self.subTest(path=relative_path):
                self.assert_endpoint_path_is_ignored(relative_path)

    def test_training_data_and_outputs_are_ignored(self):
        for relative_path in (
            "endpoint_agent/training/data/corpus.jsonl",
            "endpoint_agent/training/artifacts/training-run.bin",
            "endpoint_agent/training/snapshots/corpus-v1.json",
            "endpoint_agent/training_data/corpus.jsonl",
            "endpoint_agent/corpus_snapshots/corpus-v1.json",
            "endpoint_agent/datasets/snapshot.jsonl",
        ):
            with self.subTest(path=relative_path):
                self.assert_endpoint_path_is_ignored(relative_path)

    def test_training_environment_and_phase_two_artifacts_are_ignored(self):
        for relative_path in (
            "endpoint_agent/.venv-training/Scripts/python.exe",
            "endpoint_agent/training/artifacts/acceptance/baseline.onnx",
            "endpoint_agent/training/artifacts/acceptance/evaluation.json",
        ):
            with self.subTest(path=relative_path):
                self.assert_endpoint_path_is_ignored(relative_path)

    def test_local_keys_are_ignored(self):
        self.assert_endpoint_path_is_ignored(
            "endpoint_agent/local/keys/evidence.key"
        )

    def test_logs_are_ignored(self):
        self.assert_endpoint_path_is_ignored(
            "endpoint_agent/local/logs/agent.log"
        )

    def test_sqlite_databases_and_temporary_files_are_ignored(self):
        for relative_path in (
            "endpoint_agent/local/data/evidence.sqlite3",
            "endpoint_agent/local/data/evidence.sqlite3-wal",
            "endpoint_agent/local/data/evidence.sqlite3-shm",
            "endpoint_agent/local/data/evidence.db-journal",
        ):
            with self.subTest(path=relative_path):
                self.assert_endpoint_path_is_ignored(relative_path)

    def test_diagnostic_packages_are_ignored(self):
        self.assert_endpoint_path_is_ignored(
            "endpoint_agent/diagnostics/support-bundle.zip"
        )

    def test_local_caches_and_build_outputs_are_ignored(self):
        for relative_path in (
            "endpoint_agent/.cache/features.bin",
            "endpoint_agent/src/shielddome_endpoint/__pycache__/domain.cpython-312.pyc",
            "endpoint_agent/build/temp.win-amd64/agent.obj",
            "endpoint_agent/dist/shielddome_endpoint.whl",
            "endpoint_agent/dist/native-host/ShieldDomeEndpointHost.exe",
            "endpoint_agent/dist/native-host/build-metadata.json",
            "endpoint_agent/dist/native-host/manifests/Chrome/cn.shielddome.endpoint_agent.json",
            "endpoint_agent/build/native-host/ShieldDomeEndpointHost.spec",
            "endpoint_agent/src/shielddome_endpoint.egg-info/PKG-INFO",
        ):
            with self.subTest(path=relative_path):
                self.assert_endpoint_path_is_ignored(relative_path)
