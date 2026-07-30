from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]


class WheelBuildTests(unittest.TestCase):
    def test_wheel_builds_offline_without_external_build_dependencies(self):
        with TemporaryDirectory() as temporary_directory:
            wheel_directory = Path(temporary_directory)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-index",
                    "--no-deps",
                    str(ENDPOINT_ROOT),
                    "--wheel-dir",
                    str(wheel_directory),
                ],
                cwd=ENDPOINT_ROOT.parent,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            self.assertEqual(
                result.returncode,
                0,
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            wheels = list(wheel_directory.glob("*.whl"))
            self.assertEqual(
                [wheel.name for wheel in wheels],
                ["shielddome_endpoint-0.1.0-py3-none-any.whl"],
            )

            with ZipFile(wheels[0]) as wheel_archive:
                archive_names = set(wheel_archive.namelist())
                expected_names = {
                    "shielddome_endpoint/__init__.py",
                    "shielddome_endpoint/domain.py",
                    "shielddome_endpoint-0.1.0.dist-info/METADATA",
                    "shielddome_endpoint-0.1.0.dist-info/WHEEL",
                    "shielddome_endpoint-0.1.0.dist-info/RECORD",
                }
                self.assertTrue(expected_names.issubset(archive_names))
                metadata = wheel_archive.read(
                    "shielddome_endpoint-0.1.0.dist-info/METADATA"
                ).decode("utf-8")

            self.assertIn("Name: shielddome-endpoint", metadata)
            self.assertIn("Version: 0.1.0", metadata)
            self.assertIn("Requires-Python: >=3.12", metadata)
