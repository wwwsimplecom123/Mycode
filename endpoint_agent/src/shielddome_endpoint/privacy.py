from dataclasses import dataclass, fields, is_dataclass
from enum import StrEnum
import re

from .corpus import CorpusCandidate, CorpusManifest
from .domain import DetectionOutcome, FeatureVector, RuleAssessment


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
        if re.search(
            r"(?i)(?:[a-z]:\\|/home/|/users/|/private/|/var/lib/)",
            value,
        ):
            violations.add("private_path")
        if re.search(
            r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}\b",
            value,
        ):
            violations.add("email_address")
        if "\n" in value or "\r" in value:
            violations.add("line_break")
    return tuple(sorted(violations))


class PrivacyScanner:
    def scan_rule_assessments(
        self,
        assessments: tuple[RuleAssessment, ...],
        forbidden_values: tuple[str, ...] = (),
    ) -> PrivacyScanResult:
        violations = _scan_strings(_string_values(assessments), forbidden_values)
        return PrivacyScanResult(
            safe=not violations,
            violations=violations,
        )

    def scan_candidate(
        self,
        candidate: CorpusCandidate,
        forbidden_values: tuple[str, ...] = (),
    ) -> PrivacyScanResult:
        violations = _scan_strings(_string_values(candidate), forbidden_values)
        return PrivacyScanResult(
            safe=not violations,
            violations=violations,
        )

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

    def scan_detection_outcome(
        self,
        outcome: DetectionOutcome,
        forbidden_values: tuple[str, ...] = (),
    ) -> PrivacyScanResult:
        violations = _scan_strings(_string_values(outcome), forbidden_values)
        return PrivacyScanResult(
            safe=not violations,
            violations=violations,
        )
