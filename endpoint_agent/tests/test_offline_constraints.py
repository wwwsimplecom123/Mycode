from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]


class OfflineConstraintTests(unittest.TestCase):
    def test_guard_rejects_model_runtime_import_and_listener_calls(self):
        from _offline_guard import scan_offline_violations

        with TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            source_root = temporary_path / "src"
            source_root.mkdir()
            (source_root / "forbidden.py").write_text(
                "import onnxruntime\nlistener.bind(('127.0.0.1', 1))\nlistener.listen()\n",
                encoding="utf-8",
            )
            pyproject_path = temporary_path / "pyproject.toml"
            pyproject_path.write_text(
                '[project]\nname = "guard-fixture"\nversion = "0"\ndependencies = []\n',
                encoding="utf-8",
            )

            violations = scan_offline_violations(
                source_root,
                pyproject_path,
                additional_forbidden_import_roots=("onnxruntime",),
            )

            self.assertTrue(any("onnxruntime" in item for item in violations))
            self.assertTrue(any("listener call bind" in item for item in violations))
            self.assertTrue(any("listener call listen" in item for item in violations))

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
            additional_forbidden_import_roots=("onnxruntime",),
        )

        self.assertEqual(violations, ())

    def test_phase_two_training_source_contains_no_network_capability(self):
        from _offline_guard import scan_offline_violations

        violations = scan_offline_violations(
            ENDPOINT_ROOT / "training",
            ENDPOINT_ROOT / "pyproject.toml",
        )

        self.assertEqual(violations, ())

    def test_phase_five_b_packaging_and_registration_assets_are_offline(self):
        packaging_sources = [ENDPOINT_ROOT / "packaging" / "native_host_entry.py"]
        packaging_sources.extend((ENDPOINT_ROOT / "native_host").glob("*.ps1"))
        packaging_sources.extend((ENDPOINT_ROOT / "native_host").glob("*.psm1"))
        sources = "\n".join(path.read_text(encoding="utf-8") for path in packaging_sources)

        forbidden = (
            r"\bInvoke-WebRequest\b",
            r"\bInvoke-RestMethod\b",
            r"\bStart-BitsTransfer\b",
            r"\b(?:curl|wget)\.exe\b",
            r"\b(?:socket|requests|urllib3|httpx|aiohttp)\b",
            r"\.(?:bind|listen|connect)\s*\(",
            r"\b(?:http|https|ws|wss)://",
            r"\bserver[_-]?address\b",
            r"\bapi[_-]?key\b",
            r"\btoken\b",
        )
        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, sources, re.IGNORECASE))
        self.assertIn("--no-index", sources)
        self.assertNotIn("print(", (ENDPOINT_ROOT / "packaging" / "native_host_entry.py").read_text(encoding="utf-8"))

    def test_phase_six_b_has_no_network_listener_upload_or_model_training_code(self):
        sources = "\n".join(
            (ENDPOINT_ROOT / "src" / "shielddome_endpoint" / filename).read_text(
                encoding="utf-8"
            )
            for filename in (
                "confirmed_examples.py",
                "example_store.py",
                "example_calibration.py",
            )
        ).casefold()

        for forbidden in (
            "import socket",
            ".bind(",
            ".listen(",
            "requests.",
            "urllib.",
            "http://",
            "https://",
            ".partial_fit(",
            ".fit(",
            ".train(",
            "upload",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sources)

    def test_phase_six_c_has_no_network_listener_upload_or_background_code(self):
        source_root = ENDPOINT_ROOT / "src" / "shielddome_endpoint"
        sources = "\n".join(
            (source_root / filename).read_text(encoding="utf-8").casefold()
            for filename in ("diagnostics.py", "diagnostic_export.py")
        )

        for forbidden in (
            "import socket",
            ".connect(",
            ".bind(",
            ".listen(",
            "requests.",
            "urllib.",
            "http://",
            "https://",
            "upload",
            "threading",
            "sched",
            "subprocess",
            "traceback",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sources)

    def test_phase_six_c_is_not_exposed_to_native_messaging_or_extension(self):
        sources = "\n".join(
            path.read_text(encoding="utf-8").casefold()
            for path in (
                ENDPOINT_ROOT / "src" / "shielddome_endpoint" / "native_host.py",
                ENDPOINT_ROOT / "src" / "shielddome_endpoint" / "native_payload.py",
                ENDPOINT_ROOT / "extension" / "background.js",
                ENDPOINT_ROOT / "extension" / "content.js",
            )
        )

        for forbidden in (
            "diagnosticexporter",
            "diagnostics.json",
            "manifest.json",
            ".diag.zip",
            "diagnostic_output_path",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sources)
