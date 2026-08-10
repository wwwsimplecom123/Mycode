import ast
from pathlib import Path
import os
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ENDPOINT_ROOT / "src" / "shielddome_endpoint"
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))
sys.path.insert(0, str(ENDPOINT_ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

DESKTOP_SOURCES = (
    "desktop_presenter.py",
    "desktop_lifecycle.py",
    "desktop_qt.py",
    "desktop_app.py",
)


class DesktopPrivacyTests(unittest.TestCase):
    def test_ui_does_not_import_storage_crypto_or_mutation_implementations(self):
        forbidden_modules = {
            "confirmed_examples",
            "diagnostic_export",
            "diagnostics",
            "evidence_crypto",
            "evidence_store",
            "example_store",
            "key_protection",
            "local_data_commands",
            "sqlite3",
            "cryptography",
        }
        forbidden_mutations = {
            "confirm_benign",
            "confirm_phishing",
        }

        for filename in DESKTOP_SOURCES:
            source = (SOURCE_ROOT / filename).read_text(encoding="utf-8")
            tree = ast.parse(source, filename=filename)
            imports = set()
            attributes = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".", 1)[0])
                elif isinstance(node, ast.Attribute):
                    attributes.add(node.attr)
            with self.subTest(filename=filename):
                self.assertTrue(imports.isdisjoint(forbidden_modules), imports)
                self.assertTrue(attributes.isdisjoint(forbidden_mutations), attributes)

    def test_desktop_production_sources_have_no_network_or_eml_capability(self):
        sources = "\n".join(
            (SOURCE_ROOT / filename).read_text(encoding="utf-8").casefold()
            for filename in DESKTOP_SOURCES
        )
        for forbidden in (
            "import socket",
            "requests.",
            "urllib.",
            "http://",
            "https://",
            "websocket",
            ".bind(",
            ".listen(",
            "fastapi",
            "flask",
            "uvicorn",
            "import email",
            "mailparser",
            ".eml",
            "telemetry",
            "upload",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sources)

    def test_core_package_import_succeeds_when_pyside_is_blocked(self):
        source_root = ENDPOINT_ROOT / "src"
        code = """
import importlib.abc
import sys
class BlockPySide(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'PySide6' or fullname.startswith('PySide6.'):
            raise ImportError('blocked for optional import test')
        return None
sys.meta_path.insert(0, BlockPySide())
import shielddome_endpoint
assert 'PySide6' not in sys.modules
print(shielddome_endpoint.__version__)
"""
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(source_root)
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ENDPOINT_ROOT.parent,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertEqual(result.stdout.strip(), "0.1.0")

    def test_desktop_entrypoint_fails_cleanly_without_pyside(self):
        code = """
import importlib.abc
class BlockPySide(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'PySide6' or fullname.startswith('PySide6.'):
            raise ImportError('blocked for entrypoint test')
        return None
import sys
sys.meta_path.insert(0, BlockPySide())
from shielddome_endpoint.desktop_app import main
raise SystemExit(main())
"""
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ENDPOINT_ROOT / "src")
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ENDPOINT_ROOT.parent,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "ShieldDome desktop UI requires the approved offline "
            "PySide6-Essentials==6.8.3 runtime.\n",
        )
        self.assertNotIn("Traceback", result.stderr)


try:
    from PySide6.QtWidgets import QApplication
except ImportError:
    QApplication = None


@unittest.skipUnless(QApplication is not None, "PySide6 unavailable in core test environment")
class DesktopRuntimePrivacyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_real_qt_application_creates_no_network_socket(self):
        from test_desktop_presenter import (
            PagingConsoleService,
            make_dashboard,
        )
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )
        from shielddome_endpoint.desktop_qt import create_desktop_application

        service = PagingConsoleService(
            ConsoleOperationResult(
                ConsoleStatusCode.SUCCESS,
                make_dashboard(today_count=0),
            ),
            (),
        )
        with patch.object(
            socket,
            "socket",
            side_effect=AssertionError("desktop UI attempted network access"),
        ) as socket_constructor:
            bundle = create_desktop_application(
                service=service,
                show=False,
                enable_tray=False,
            )
            QApplication.processEvents()

        socket_constructor.assert_not_called()
        bundle.lifecycle.quit_application()


if __name__ == "__main__":
    unittest.main()
