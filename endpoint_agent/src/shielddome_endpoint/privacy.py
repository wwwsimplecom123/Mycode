from dataclasses import dataclass, fields, is_dataclass
from enum import StrEnum
import re

from .corpus import CorpusManifest
from .domain import FeatureVector


@dataclass(frozen=True, slots=True)
class PrivacyScanResult:
    safe: bool
    violations: tuple[str, ...]


def _string_values(value) -> tuple[str, ...]:
    if isinstance(value, StrEnum):
        return (str(value),)
    if isinstance(value, str):
        return (value,)
    if is_dataclass(value):
        strings: list[str] = []
        for field in fields(value):
            strings.extend(_string_values(getattr(value, field.name)))
        return tuple(strings)
    if isinstance(value, (tuple, list)):
        strings = []
        for item in value:
            strings.extend(_string_values(item))
        return tuple(strings)
    return ()


def _scan_strings(
    strings: tuple[str, ...],
    forbidden_values: tuple[str, ...],
) -> tuple[str, ...]:
    violations: set[str] = set()
    for value in strings:
        for forbidden in forbidden_values:
            if forbidden and forbidden in value:
                violations.add("forbidden_value")
        if re.search(
            r"(?i)\b(?:password|passwd|token|api[_-]?key|authorization)\s*[:=]\s*\S+",
            value,
        ) or re.search(r"(?i)\bbearer\s+\S+", value):
            violations.add("credential_assignment")
        if re.search(r"\b[a-z][a-z0-9+.-]*://[^\s?]+\?[^\s]+", value):
            violations.add("url_query")
        if re.search(r"(?i)(?:[a-z]:\\users\\|/home/|/users/)", value):
            violations.add("private_path")
    return tuple(sorted(violations))


class PrivacyScanner:
    def scan_feature_vector(
        self,
        vector: FeatureVector,
        forbidden_values: tuple[str, ...] = (),
    ) -> PrivacyScanResult:
        violations = list(_scan_strings(_string_values(vector), forbidden_values))
        if vector.text_input is not None:
            violations.append("raw_text_field")
        unique_violations = tuple(sorted(set(violations)))
        return PrivacyScanResult(
            safe=not unique_violations,
            violations=unique_violations,
        )

    def scan_manifest(
        self,
        manifest: CorpusManifest,
        forbidden_values: tuple[str, ...] = (),
    ) -> PrivacyScanResult:
        violations = _scan_strings(_string_values(manifest), forbidden_values)
        return PrivacyScanResult(
            safe=not violations,
            violations=violations,
        )
