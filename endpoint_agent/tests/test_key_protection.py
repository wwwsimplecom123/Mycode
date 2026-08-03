from pathlib import Path
import os
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))


class RecordingDpapiBackend:
    def __init__(self):
        self.protect_flags = []
        self.unprotect_flags = []

    def protect(self, plaintext, *, flags):
        self.protect_flags.append(flags)
        return b"dpapi:" + plaintext

    def unprotect(self, protected, *, flags):
        self.unprotect_flags.append(flags)
        return protected.removeprefix(b"dpapi:")


class CurrentUserKeyProtectorTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_real_dpapi_round_trip_uses_current_user_scope(self):
        from shielddome_endpoint.key_protection import CurrentUserKeyProtector

        plaintext = b"k" * 32
        protector = CurrentUserKeyProtector()

        protected = protector.protect(plaintext)

        self.assertNotEqual(protected, plaintext)
        self.assertEqual(protector.unprotect(protected), plaintext)

    def test_different_user_scope_is_rejected_and_local_machine_flag_is_never_used(self):
        from shielddome_endpoint.key_protection import (
            CRYPTPROTECT_LOCAL_MACHINE,
            CurrentUserKeyProtector,
            KeyProtectionError,
        )

        backend = RecordingDpapiBackend()
        user_a = CurrentUserKeyProtector(
            backend=backend,
            scope_identity_provider=lambda: "S-1-5-21-user-a",
        )
        user_b = CurrentUserKeyProtector(
            backend=backend,
            scope_identity_provider=lambda: "S-1-5-21-user-b",
        )

        protected = user_a.protect(b"k" * 32)

        self.assertEqual(backend.protect_flags[0] & CRYPTPROTECT_LOCAL_MACHINE, 0)
        with self.assertRaisesRegex(KeyProtectionError, "^user_scope_mismatch$"):
            user_b.unprotect(protected)
        self.assertEqual(backend.unprotect_flags, [])


class UserDataKeyManagerTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_creates_random_protected_keys_in_independent_user_data_roots(self):
        from shielddome_endpoint.key_protection import (
            UserDataKeyManager,
            default_user_data_directory,
        )

        with TemporaryDirectory() as first_root, TemporaryDirectory() as second_root:
            with patch.dict(os.environ, {"LOCALAPPDATA": first_root}):
                default_path = default_user_data_directory()
            first = UserDataKeyManager(default_path)
            second = UserDataKeyManager(Path(second_root) / "ShieldDome" / "EndpointAgent")

            first_key = first.load_or_create()
            second_key = second.load_or_create()

            self.assertEqual(len(first_key), 32)
            self.assertEqual(len(second_key), 32)
            self.assertNotEqual(first_key, second_key)
            self.assertEqual(first.load_or_create(), first_key)
            self.assertEqual(
                default_path,
                Path(first_root) / "ShieldDome" / "EndpointAgent",
            )
            self.assertNotIn(first_key, first.key_path.read_bytes())

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_corrupt_or_missing_protected_key_is_never_silently_replaced(self):
        from shielddome_endpoint.key_protection import (
            KeyProtectionError,
            UserDataKeyManager,
        )

        with TemporaryDirectory() as temporary_directory:
            manager = UserDataKeyManager(Path(temporary_directory))
            manager.load_or_create()
            manager.key_path.write_bytes(b"damaged-protected-key")

            with self.assertRaises(KeyProtectionError):
                manager.load_or_create()
            self.assertEqual(manager.key_path.read_bytes(), b"damaged-protected-key")

        with TemporaryDirectory() as temporary_directory:
            manager = UserDataKeyManager(Path(temporary_directory))
            manager.database_path.parent.mkdir(parents=True)
            manager.database_path.write_bytes(b"existing-database")

            with self.assertRaisesRegex(
                KeyProtectionError,
                "^protected_key_missing$",
            ):
                manager.load_or_create()
            self.assertFalse(manager.key_path.exists())

    def test_default_data_directory_rejects_a_system_shared_root(self):
        from shielddome_endpoint.key_protection import (
            KeyProtectionError,
            default_user_data_directory,
        )

        with patch.dict(
            os.environ,
            {
                "LOCALAPPDATA": "C:\\ProgramData\\ShieldDomeShared",
                "PROGRAMDATA": "C:\\ProgramData",
            },
        ):
            with self.assertRaisesRegex(
                KeyProtectionError,
                "^shared_data_directory_forbidden$",
            ):
                default_user_data_directory()

    def test_explicit_data_directory_must_remain_under_local_app_data(self):
        from shielddome_endpoint.key_protection import (
            KeyProtectionError,
            UserDataKeyManager,
        )

        with patch.dict(
            os.environ,
            {"LOCALAPPDATA": "C:\\Users\\TestUser\\AppData\\Local"},
        ):
            with self.assertRaisesRegex(
                KeyProtectionError,
                "^data_directory_outside_local_app_data$",
            ):
                UserDataKeyManager(Path("C:\\ProgramData\\ShieldDome"))


if __name__ == "__main__":
    unittest.main()
