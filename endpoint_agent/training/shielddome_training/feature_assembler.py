import math

import numpy as np

from shielddome_endpoint.domain import FEATURE_SCHEMA_VERSION, FeatureVector
from shielddome_endpoint.feature_pipeline import (
    CATEGORICAL_FEATURE_NAMES,
    NUMERIC_FEATURE_NAMES,
    TEXT_HASH_DIMENSION,
)


ASSEMBLER_SCHEMA_VERSION = "1.0"

_CATEGORICAL_VALUES = {
    "sender_domain_state": ("missing", "present", "unknown"),
    "reply_to_domain_state": ("missing", "present", "unknown"),
    "auth_spf_value": (
        "missing",
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "temperror",
        "permerror",
        "other",
        "unknown",
    ),
    "auth_dkim_value": (
        "missing",
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "temperror",
        "permerror",
        "other",
        "unknown",
    ),
    "auth_dmarc_value": (
        "missing",
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "temperror",
        "permerror",
        "other",
        "unknown",
    ),
    "language": ("zh", "en", "mixed", "other", "unknown"),
}
_MISSING_VALUE_NAMES = (
    "subject",
    "body",
    "sender",
    "reply_to",
    "auth_spf",
    "auth_dkim",
    "auth_dmarc",
    "language_hint",
    "unknown",
)


def _feature_names() -> tuple[str, ...]:
    numeric = tuple(f"numeric:{name}" for name in NUMERIC_FEATURE_NAMES)
    categorical = tuple(
        f"categorical:{name}={value}"
        for name in CATEGORICAL_FEATURE_NAMES
        for value in _CATEGORICAL_VALUES[name]
    )
    text = tuple(f"text_hash:{index:02d}" for index in range(TEXT_HASH_DIMENSION))
    missing = tuple(f"missing:{name}" for name in _MISSING_VALUE_NAMES)
    return numeric + categorical + text + missing


FEATURE_NAMES = _feature_names()


class FeatureAssembler:
    @property
    def feature_names(self) -> tuple[str, ...]:
        return FEATURE_NAMES

    @property
    def output_dimension(self) -> int:
        return len(FEATURE_NAMES)

    def transform(self, vector: FeatureVector) -> np.ndarray:
        if vector.schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError("feature_schema_mismatch")
        if vector.text_input is not None:
            raise ValueError("raw_text_not_allowed")
        if tuple(name for name, _ in vector.numeric_features) != NUMERIC_FEATURE_NAMES:
            raise ValueError("numeric_feature_layout_mismatch")
        if tuple(name for name, _ in vector.categorical_features) != CATEGORICAL_FEATURE_NAMES:
            raise ValueError("categorical_feature_layout_mismatch")
        if vector.text_vector is None or len(vector.text_vector) != TEXT_HASH_DIMENSION:
            raise ValueError("text_feature_layout_mismatch")

        numeric_values = tuple(float(value) for _, value in vector.numeric_features)
        if not all(math.isfinite(value) for value in numeric_values):
            raise ValueError("non_finite_feature")
        text_values = tuple(float(value) for value in vector.text_vector)
        if not all(math.isfinite(value) for value in text_values):
            raise ValueError("non_finite_feature")

        categorical_values: list[float] = []
        for name, value in vector.categorical_features:
            allowed = _CATEGORICAL_VALUES[name]
            selected = value if value in allowed[:-1] else "unknown"
            categorical_values.extend(float(candidate == selected) for candidate in allowed)

        missing = frozenset(vector.missing_value_mask)
        known_missing = frozenset(_MISSING_VALUE_NAMES[:-1])
        missing_values = tuple(float(name in missing) for name in _MISSING_VALUE_NAMES[:-1])
        missing_values += (float(bool(missing - known_missing)),)

        assembled = numeric_values + tuple(categorical_values) + text_values + missing_values
        return np.asarray(assembled, dtype=np.float32)

    def transform_many(self, vectors: tuple[FeatureVector, ...]) -> np.ndarray:
        if not vectors:
            return np.empty((0, self.output_dimension), dtype=np.float32)
        return np.stack(tuple(self.transform(vector) for vector in vectors))
