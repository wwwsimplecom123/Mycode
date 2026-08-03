import base64
import csv
import hashlib
from io import StringIO
from pathlib import Path
import re
import tomllib
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PROJECT_ROOT / "src"
PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _project_metadata() -> tuple[str, str, str, tuple[str, ...]]:
    configuration = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    project = configuration["project"]
    return (
        str(project["name"]),
        str(project["version"]),
        str(project["requires-python"]),
        tuple(str(item) for item in project.get("dependencies", ())),
    )


def _distribution_name(project_name: str) -> str:
    return re.sub(r"[-_.]+", "_", project_name)


def _metadata_files() -> tuple[str, dict[str, bytes]]:
    project_name, version, requires_python, dependencies = _project_metadata()
    distribution_name = _distribution_name(project_name)
    dist_info = f"{distribution_name}-{version}.dist-info"
    dependency_metadata = "".join(
        f"Requires-Dist: {dependency}\n" for dependency in dependencies
    )
    metadata = (
        "Metadata-Version: 2.1\n"
        f"Name: {project_name}\n"
        f"Version: {version}\n"
        f"Requires-Python: {requires_python}\n"
        f"{dependency_metadata}"
        "\n"
    ).encode("utf-8")
    wheel = (
        "Wheel-Version: 1.0\n"
        "Generator: shielddome-endpoint-phase0\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
        "\n"
    ).encode("utf-8")
    return (
        dist_info,
        {
            f"{dist_info}/METADATA": metadata,
            f"{dist_info}/WHEEL": wheel,
        },
    )


def _record_digest(content: bytes) -> str:
    digest = hashlib.sha256(content).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={encoded}"


def _record_content(files: dict[str, bytes], record_path: str) -> bytes:
    output = StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for archive_path, content in sorted(files.items()):
        writer.writerow((archive_path, _record_digest(content), len(content)))
    writer.writerow((record_path, "", ""))
    return output.getvalue().encode("utf-8")


def _write_archive_file(
    archive: ZipFile,
    archive_path: str,
    content: bytes,
) -> None:
    information = ZipInfo(archive_path, ZIP_TIMESTAMP)
    information.compress_type = ZIP_DEFLATED
    information.external_attr = 0o644 << 16
    archive.writestr(information, content)


def get_requires_for_build_wheel(config_settings=None) -> list[str]:
    return []


def prepare_metadata_for_build_wheel(
    metadata_directory,
    config_settings=None,
) -> str:
    dist_info, metadata_files = _metadata_files()
    dist_info_directory = Path(metadata_directory) / dist_info
    dist_info_directory.mkdir(parents=True, exist_ok=True)
    for archive_path, content in metadata_files.items():
        filename = archive_path.rsplit("/", 1)[1]
        (dist_info_directory / filename).write_bytes(content)
    return dist_info


def build_wheel(
    wheel_directory,
    config_settings=None,
    metadata_directory=None,
) -> str:
    project_name, version, _, _ = _project_metadata()
    distribution_name = _distribution_name(project_name)
    wheel_filename = f"{distribution_name}-{version}-py3-none-any.whl"
    wheel_path = Path(wheel_directory) / wheel_filename
    wheel_path.parent.mkdir(parents=True, exist_ok=True)

    files: dict[str, bytes] = {}
    package_root = SOURCE_ROOT / "shielddome_endpoint"
    for source_path in sorted(package_root.rglob("*.py")):
        archive_path = source_path.relative_to(SOURCE_ROOT).as_posix()
        files[archive_path] = source_path.read_bytes()

    dist_info, metadata_files = _metadata_files()
    files.update(metadata_files)
    record_path = f"{dist_info}/RECORD"
    files[record_path] = _record_content(files, record_path)

    with ZipFile(wheel_path, "w") as archive:
        for archive_path, content in sorted(files.items()):
            _write_archive_file(archive, archive_path, content)

    return wheel_filename
