from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))


class RecordingDesktopAdapter:
    def __init__(self):
        self.events = []

    def show_window(self):
        self.events.append("show")

    def hide_window(self):
        self.events.append("hide")

    def hide_tray(self):
        self.events.append("hide_tray")

    def quit_event_loop(self):
        self.events.append("quit")


class DesktopLifecycleTests(unittest.TestCase):
    def test_tray_open_hide_and_explicit_quit_use_one_lifecycle_seam(self):
        from shielddome_endpoint.desktop_lifecycle import DesktopLifecycle

        adapter = RecordingDesktopAdapter()
        lifecycle = DesktopLifecycle(adapter)

        lifecycle.show_console()
        lifecycle.hide_console()
        lifecycle.quit_application()

        self.assertEqual(
            adapter.events,
            ["show", "hide", "hide_tray", "quit"],
        )
        self.assertTrue(lifecycle.is_quitting)

    def test_window_close_hides_to_tray_and_quit_is_idempotent(self):
        from shielddome_endpoint.desktop_lifecycle import (
            CloseDisposition,
            DesktopLifecycle,
        )

        adapter = RecordingDesktopAdapter()
        lifecycle = DesktopLifecycle(adapter)

        disposition = lifecycle.handle_window_close()
        lifecycle.show_console()
        lifecycle.quit_application()
        lifecycle.quit_application()
        after_quit = lifecycle.handle_window_close()

        self.assertIs(disposition, CloseDisposition.HIDE_TO_TRAY)
        self.assertIs(after_quit, CloseDisposition.EXIT)
        self.assertEqual(
            adapter.events,
            ["hide", "show", "hide_tray", "quit"],
        )


if __name__ == "__main__":
    unittest.main()
