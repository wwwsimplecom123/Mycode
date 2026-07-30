from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]


class OfflineConstraintTests(unittest.TestCase):
    def test_guard_rejects_forbidden_network_import(self):
        from _offline_guard import scan_offline_violations

        temporary_path = None
        with TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            source_root = temporary_path / "src"
            source_root.mkdir()
            (source_root / "networked.py").write_text(
                "import socket\n",
                encoding="utf-8",
            )
            pyproject_path = temporary_path / "pyproject.toml"
            pyproject_path.write_text(
                '[project]\nname = "guard-fixture"\nversion = "0"\ndependencies = []\n',
                encoding="utf-8",
            )

            violations = scan_offline_violations(source_root, pyproject_path)

            self.assertTrue(any("socket" in violation for violation in violations))

        self.assertFalse(temporary_path.exists())

    def test_guard_rejects_forbidden_runtime_dependency(self):
        from _offline_guard import scan_offline_violations

        with TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            source_root = temporary_path / "src"
            source_root.mkdir()
            pyproject_path = temporary_path / "pyproject.toml"
            pyproject_path.write_text(
                '[project]\nname = "guard-fixture"\nversion = "0"\n'
                'dependencies = ["FastAPI>=1"]\n',
                encoding="utf-8",
            )

            violations = scan_offline_violations(source_root, pyproject_path)

            self.assertTrue(any("fastapi" in violation for violation in violations))

    def test_guard_rejects_network_endpoint_literal(self):
        from _offline_guard import scan_offline_violations

        with TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            source_root = temporary_path / "src"
            source_root.mkdir()
            (source_root / "endpoint.py").write_text(
                'REMOTE_ENDPOINT = "https://telemetry.example.test/events"\n',
                encoding="utf-8",
            )
            pyproject_path = temporary_path / "pyproject.toml"
            pyproject_path.write_text(
                '[project]\nname = "guard-fixture"\nversion = "0"\ndependencies = []\n',
                encoding="utf-8",
            )

            violations = scan_offline_violations(source_root, pyproject_path)

            self.assertTrue(any("network URL" in violation for violation in violations))

    def test_production_source_and_dependencies_are_offline(self):
        from _offline_guard import scan_offline_violations

        violations = scan_offline_violations(
            ENDPOINT_ROOT / "src" / "shielddome_endpoint",
            ENDPOINT_ROOT / "pyproject.toml",
        )

        self.assertEqual(violations, ())

    def test_phase_two_training_source_contains_no_network_capability(self):
        from _offline_guard import scan_offline_violations

        violations = scan_offline_violations(
            ENDPOINT_ROOT / "training",
            ENDPOINT_ROOT / "pyproject.toml",
        )

        self.assertEqual(violations, ())
