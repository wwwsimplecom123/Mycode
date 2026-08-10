import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
import uuid


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
IDENTITY = json.loads(
    (ENDPOINT_ROOT / "native_host" / "identity.json").read_text(encoding="utf-8")
)


def run_powershell(script_name, *arguments):
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ENDPOINT_ROOT / "native_host" / script_name),
            *map(str, arguments),
        ],
        cwd=ENDPOINT_ROOT.parent,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )


def write_fake_build(root):
    host_path = root / "程序 目录" / "ShieldDomeEndpointHost.exe"
    host_path.parent.mkdir(parents=True)
    host_path.write_bytes(b"MZ\x00ShieldDome packaging test")
    metadata_path = root / "构建 元数据.json"
    metadata_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "host_name": IDENTITY["host_name"],
                "extension_id": IDENTITY["extension_id"],
                "extension_origin": IDENTITY["extension_origin"],
                "executable_path": str(host_path.resolve()),
                "executable_sha256": hashlib.sha256(host_path.read_bytes()).hexdigest(),
                "build_tool": "PyInstaller",
                "build_tool_version": "6.15.0-test-fixture",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return host_path, metadata_path


class NativePackagingTests(unittest.TestCase):
    def test_host_build_is_reproducible_and_development_only(self):
        requirements = (ENDPOINT_ROOT / "requirements-packaging.txt").read_text(
            encoding="utf-8"
        ).splitlines()
        entry_source = (ENDPOINT_ROOT / "packaging" / "native_host_entry.py").read_text(
            encoding="utf-8"
        )
        build_source = (ENDPOINT_ROOT / "native_host" / "build-host.ps1").read_text(
            encoding="utf-8"
        )
        pyproject = (ENDPOINT_ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertEqual(requirements, ["pyinstaller==6.15.0"])
        self.assertIn("from shielddome_endpoint.native_host import main", entry_source)
        for option in (
            "--noconfirm",
            "--clean",
            "--onefile",
            "--console",
            "--noupx",
            "ShieldDomeEndpointHost",
            "dist\\native-host",
            "build\\native-host",
        ):
            with self.subTest(option=option):
                self.assertIn(option, build_source)
        self.assertIn("python -m PyInstaller", build_source)
        self.assertNotIn("pyinstaller", pyproject.lower())

    def test_public_identity_document_has_only_non_secret_fields(self):
        identity = json.loads(
            (ENDPOINT_ROOT / "native_host" / "identity.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(identity),
            {"identity_kind", "host_name", "extension_id", "extension_origin"},
        )

    def test_registration_wrappers_default_only_to_current_user_browser_keys(self):
        install = (ENDPOINT_ROOT / "native_host" / "install-host.ps1").read_text(
            encoding="utf-8"
        )
        check = (ENDPOINT_ROOT / "native_host" / "check-host.ps1").read_text(
            encoding="utf-8"
        )
        uninstall = (ENDPOINT_ROOT / "native_host" / "uninstall-host.ps1").read_text(
            encoding="utf-8"
        )
        combined = "\n".join((install, check, uninstall))
        for source in (install, check, uninstall):
            self.assertNotIn("@PSBoundParameters", source)
        for registry_path in (
            "HKCU:\\Software\\Google\\Chrome\\NativeMessagingHosts\\cn.shielddome.endpoint_agent",
            "HKCU:\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\cn.shielddome.endpoint_agent",
        ):
            self.assertEqual(combined.count(registry_path), 3)
        self.assertNotIn("HKLM:", combined)
        self.assertNotIn("RunAs", combined)
        self.assertNotIn("-Verb RunAs", combined)

    @unittest.skipUnless(sys.platform == "win32", "Windows default CLI paths")
    def test_default_install_resolves_repository_host_path_before_validation(self):
        result = run_powershell("install-host.ps1")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Native Host executable does not exist", result.stderr)
        self.assertNotIn("PSScriptRoot", result.stderr)

    @unittest.skipUnless(sys.platform == "win32", "Windows registry lifecycle")
    def test_install_status_and_uninstall_are_idempotent_with_unicode_paths(self):
        registry_root = (
            "HKCU:\\Software\\ShieldDome\\EndpointAgentTests\\"
            + uuid.uuid4().hex
        )
        chrome_registry = registry_root + "\\Chrome"
        edge_registry = registry_root + "\\Edge"
        try:
            with TemporaryDirectory(prefix="ShieldDome Phase5B ") as temporary_directory:
                root = Path(temporary_directory) / "含 空格"
                root.mkdir()
                host_path, metadata_path = write_fake_build(root)
                manifest_root = root / "清单 目录"
                common = (
                    "-HostPath",
                    host_path,
                    "-BuildMetadataPath",
                    metadata_path,
                    "-ManifestRoot",
                    manifest_root,
                    "-ChromeRegistryPath",
                    chrome_registry,
                    "-EdgeRegistryPath",
                    edge_registry,
                )

                for _ in range(2):
                    result = run_powershell("install-host.ps1", *common)
                    self.assertEqual(
                        result.returncode,
                        0,
                        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
                    )

                status = run_powershell("check-host.ps1", *common)
                self.assertEqual(
                    status.returncode,
                    0,
                    f"stdout:\n{status.stdout}\nstderr:\n{status.stderr}",
                )
                status_data = json.loads(status.stdout)
                self.assertTrue(status_data["ready"])
                self.assertEqual(set(status_data["browsers"]), {"Chrome", "Edge"})

                for browser in ("Chrome", "Edge"):
                    manifest_path = (
                        manifest_root
                        / browser
                        / f'{IDENTITY["host_name"]}.json'
                    )
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
                    self.assertEqual(manifest["name"], IDENTITY["host_name"])
                    self.assertEqual(manifest["type"], "stdio")
                    self.assertEqual(manifest["path"], str(host_path.resolve()))
                    self.assertEqual(
                        manifest["allowed_origins"], [IDENTITY["extension_origin"]]
                    )

                uninstall_arguments = (
                    "-ManifestRoot",
                    manifest_root,
                    "-ChromeRegistryPath",
                    chrome_registry,
                    "-EdgeRegistryPath",
                    edge_registry,
                )
                for uninstall_index in range(2):
                    uninstall = run_powershell("uninstall-host.ps1", *uninstall_arguments)
                    self.assertEqual(
                        uninstall.returncode,
                        0,
                        f"stdout:\n{uninstall.stdout}\nstderr:\n{uninstall.stderr}",
                    )
                    uninstall_data = json.loads(uninstall.stdout)
                    expected_removed = {"Chrome", "Edge"} if uninstall_index == 0 else set()
                    self.assertEqual(set(uninstall_data["removed"]), expected_removed)
                self.assertFalse((manifest_root / "Chrome").exists())
                self.assertFalse((manifest_root / "Edge").exists())
        finally:
            cleanup = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"if (Test-Path -LiteralPath '{registry_root}') {{ Remove-Item -LiteralPath '{registry_root}' -Recurse -Force }}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(cleanup.returncode, 0, cleanup.stderr)

    @unittest.skipUnless(sys.platform == "win32", "Windows registry ownership")
    def test_install_refuses_to_overwrite_unowned_registry_value(self):
        registry_root = (
            "HKCU:\\Software\\ShieldDome\\EndpointAgentTests\\"
            + uuid.uuid4().hex
        )
        chrome_registry = registry_root + "\\Chrome"
        edge_registry = registry_root + "\\Edge"
        try:
            with TemporaryDirectory(prefix="ShieldDome Phase5B ") as temporary_directory:
                root = Path(temporary_directory)
                host_path, metadata_path = write_fake_build(root)
                manifest_root = root / "manifests"
                unrelated = root / "unrelated.json"
                unrelated.write_text("{}", encoding="utf-8")
                seed = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        (
                            f"New-Item -Path '{chrome_registry}' -Force | Out-Null; "
                            f"Set-Item -LiteralPath '{chrome_registry}' -Value '{unrelated}'"
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(seed.returncode, 0, seed.stderr)

                install = run_powershell(
                    "install-host.ps1",
                    "-HostPath", host_path,
                    "-BuildMetadataPath", metadata_path,
                    "-ManifestRoot", manifest_root,
                    "-ChromeRegistryPath", chrome_registry,
                    "-EdgeRegistryPath", edge_registry,
                )

                self.assertNotEqual(install.returncode, 0)
                registered = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        f"[string](Get-Item -LiteralPath '{chrome_registry}').GetValue('')",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(registered.returncode, 0, registered.stderr)
                self.assertEqual(registered.stdout.strip(), str(unrelated))
                self.assertFalse(manifest_root.exists())
        finally:
            cleanup = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"if (Test-Path -LiteralPath '{registry_root}') {{ Remove-Item -LiteralPath '{registry_root}' -Recurse -Force }}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(cleanup.returncode, 0, cleanup.stderr)

    @unittest.skipUnless(sys.platform == "win32", "Windows registry ownership")
    def test_uninstall_refuses_unowned_registry_value(self):
        registry_root = (
            "HKCU:\\Software\\ShieldDome\\EndpointAgentTests\\"
            + uuid.uuid4().hex
        )
        chrome_registry = registry_root + "\\Chrome"
        edge_registry = registry_root + "\\Edge"
        try:
            with TemporaryDirectory(prefix="ShieldDome Phase5B ") as temporary_directory:
                root = Path(temporary_directory)
                host_path, metadata_path = write_fake_build(root)
                manifest_root = root / "manifests"
                common = (
                    "-HostPath", host_path,
                    "-BuildMetadataPath", metadata_path,
                    "-ManifestRoot", manifest_root,
                    "-ChromeRegistryPath", chrome_registry,
                    "-EdgeRegistryPath", edge_registry,
                )
                install = run_powershell("install-host.ps1", *common)
                self.assertEqual(install.returncode, 0, install.stderr)
                unrelated = root / "unrelated.json"
                unrelated.write_text("{}", encoding="utf-8")
                mutate = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        f"Set-Item -LiteralPath '{chrome_registry}' -Value '{unrelated}'",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(mutate.returncode, 0, mutate.stderr)

                uninstall = run_powershell(
                    "uninstall-host.ps1",
                    "-ManifestRoot", manifest_root,
                    "-ChromeRegistryPath", chrome_registry,
                    "-EdgeRegistryPath", edge_registry,
                )
                self.assertNotEqual(uninstall.returncode, 0)
                remains = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        f"[bool](Test-Path -LiteralPath '{chrome_registry}')",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(remains.stdout.strip(), "True")
        finally:
            cleanup = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"if (Test-Path -LiteralPath '{registry_root}') {{ Remove-Item -LiteralPath '{registry_root}' -Recurse -Force }}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(cleanup.returncode, 0, cleanup.stderr)


if __name__ == "__main__":
    unittest.main()
