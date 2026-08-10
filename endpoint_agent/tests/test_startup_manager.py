from pathlib import Path
import sys
import tempfile
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))


class FakeRegistry:
    def __init__(self, value=None):
        self.value = value
        self.events = []

    def read_current_user_value(self, name):
        self.events.append(("read", name))
        return self.value

    def write_current_user_value(self, name, value):
        self.events.append(("write", name, value))
        self.value = value

    def delete_current_user_value(self, name):
        self.events.append(("delete", name))
        self.value = None


class StartupManagerTests(unittest.TestCase):
    def test_rejects_development_relative_python_and_nonpackaged_entries(self):
        from shielddome_endpoint.startup_manager import WindowsStartupManager

        for path, frozen in (
            ("ShieldDomeEndpoint.exe", True),
            (Path(sys.executable), True),
            (Path(sys.executable), False),
        ):
            registry = FakeRegistry()
            manager = WindowsStartupManager(
                executable_path=path,
                frozen=frozen,
                registry=registry,
            )
            with self.subTest(path=str(path), frozen=frozen):
                self.assertEqual(manager.status().code.value, "unavailable")
                self.assertEqual(manager.install().code.value, "unavailable")
                self.assertFalse(any(event[0] == "write" for event in registry.events))

    def test_install_query_and_owned_uninstall_are_idempotent(self):
        from shielddome_endpoint.startup_manager import WindowsStartupManager

        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "ShieldDomeEndpoint.exe"
            executable.touch()
            registry = FakeRegistry()
            manager = WindowsStartupManager(
                executable_path=executable,
                frozen=True,
                registry=registry,
            )
            self.assertEqual(manager.status().code.value, "disabled")
            self.assertEqual(manager.install().code.value, "enabled")
            self.assertEqual(manager.install().code.value, "enabled")
            self.assertEqual(
                len([event for event in registry.events if event[0] == "write"]), 1
            )
            self.assertEqual(manager.uninstall().code.value, "disabled")
            self.assertEqual(manager.uninstall().code.value, "disabled")
            self.assertEqual(
                len([event for event in registry.events if event[0] == "delete"]), 1
            )

    def test_foreign_same_name_value_is_never_overwritten_or_deleted(self):
        from shielddome_endpoint.startup_manager import WindowsStartupManager

        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "ShieldDomeEndpoint.exe"
            executable.touch()
            registry = FakeRegistry('"C:\\Other\\NotShieldDome.exe"')
            manager = WindowsStartupManager(
                executable_path=executable,
                frozen=True,
                registry=registry,
            )
            self.assertEqual(manager.status().code.value, "foreign_entry")
            self.assertEqual(manager.install().code.value, "foreign_entry")
            self.assertEqual(manager.uninstall().code.value, "foreign_entry")
            self.assertEqual(registry.value, '"C:\\Other\\NotShieldDome.exe"')
            self.assertFalse(any(event[0] in {"write", "delete"} for event in registry.events))


if __name__ == "__main__":
    unittest.main()
