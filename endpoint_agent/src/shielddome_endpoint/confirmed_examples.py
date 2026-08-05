from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib
import hmac
import json
import math
import re

from .domain import FEATURE_SCHEMA_VERSION, FeatureVector
from .feature_pipeline import (
    CATEGORICAL_FEATURE_NAMES,
    KNOWN_AUTH_VALUES,
    NUMERIC_FEATURE_NAMES,
    TEXT_HASH_DIMENSION,
)


CONFIRMED_EXAMPLE_SCHEMA_VERSION = "1.0"
EXAMPLE_FINGERPRINT_VERSION = "hmac-sha256-v1"
_LOWER_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SERIALIZED_BYTES = 65_536
_SERIALIZED_FIELDS = frozenset(
    {
        "confirmed_at",
        "feature_schema_version",
        "feature_vector",
        "fingerprint_version",
        "keyed_fingerprint",
        "label",
        "schema_version",
        "source",
    }
)
_FEATURE_VECTOR_FIELDS = frozenset(
    {
        "categorical_features",
        "missing_value_mask",
        "numeric_features",
        "schema_version",
        "text_input",
        "text_vector",
    }
)
_MISSING_VALUE_NAMES = (
    "subject",
    "body",
    "sender",
    "reply_to",
    "auth_spf",
    "auth_dkim",
    "auth_dmarc",
    "language_hint",
)
_CATEGORICAL_VALUES = {
    "sender_domain_state": frozenset({"missing", "present"}),
    "reply_to_domain_state": frozenset({"missing", "present"}),
    "auth_spf_value": KNOWN_AUTH_VALUES | frozenset({"missing", "other"}),
    "auth_dkim_value": KNOWN_AUTH_VALUES | frozenset({"missing", "other"}),
    "auth_dmarc_value": KNOWN_AUTH_VALUES | frozenset({"missing", "other"}),
    "language": frozenset({"zh", "en", "mixed", "other"}),
}


class ExampleLabel(StrEnum):
    BENIGN = "benign"
    PHISHING = "phishing"


class ExampleSource(StrEnum):
    BROWSER_NATIVE = "browser_native"


class UserConfirmationAction(StrEnum):
    CONFIRM_BENIGN = "confirm_benign"
    CONFIRM_PHISHING = "confirm_phishing"


class ConfirmedExampleValidationError(ValueError):
    pass


def validate_example_feature_vector(feature_vector: FeatureVector) -> None:
    try:
        numeric_names = tuple(name for name, _ in feature_vector.numeric_features)
        numeric_values = tuple(value for _, value in feature_vector.numeric_features)
        categorical_names = tuple(
            name for name, _ in feature_vector.categorical_features
        )
        categorical_values = tuple(
            value for _, value in feature_vector.categorical_features
        )
        text_vector = feature_vector.text_vector
        missing_mask = feature_vector.missing_value_mask
        missing_positions = tuple(
            _MISSING_VALUE_NAMES.index(name) for name in missing_mask
        )
        norm = math.sqrt(sum(value * value for value in text_vector))
    except (AttributeError, TypeError, ValueError):
        raise ConfirmedExampleValidationError("invalid_confirmed_example") from None
    if (
        not isinstance(feature_vector, FeatureVector)
        or feature_vector.schema_version != FEATURE_SCHEMA_VERSION
        or not isinstance(feature_vector.numeric_features, tuple)
        or numeric_names != NUMERIC_FEATURE_NAMES
        or any(
            not isinstance(value, float)
            or not math.isfinite(value)
            or not 0.0 <= value <= 1_000_000.0
            for value in numeric_values
        )
        or not isinstance(feature_vector.categorical_features, tuple)
        or categorical_names != CATEGORICAL_FEATURE_NAMES
        or any(
            not isinstance(value, str)
            or value not in _CATEGORICAL_VALUES[name]
            for name, value in feature_vector.categorical_features
        )
        or feature_vector.text_input is not None
        or not isinstance(text_vector, tuple)
        or len(text_vector) != TEXT_HASH_DIMENSION
        or any(
            not isinstance(value, float)
            or not math.isfinite(value)
            or not -1.0 <= value <= 1.0
            for value in text_vector
        )
        or not (math.isclose(norm, 0.0, abs_tol=1e-12) or math.isclose(norm, 1.0, rel_tol=1e-9, abs_tol=1e-9))
        or not isinstance(missing_mask, tuple)
        or len(set(missing_mask)) != len(missing_mask)
        or missing_positions != tuple(sorted(missing_positions))
    ):
        raise ConfirmedExampleValidationError("invalid_confirmed_example")


def canonical_feature_vector_bytes(feature_vector: FeatureVector) -> bytes:
    validate_example_feature_vector(feature_vector)
    return json.dumps(
        {
            "categorical_features": [
                list(item) for item in feature_vector.categorical_features
            ],
            "missing_value_mask": list(feature_vector.missing_value_mask),
            "numeric_features": [
                list(item) for item in feature_vector.numeric_features
            ],
            "schema_version": feature_vector.schema_version,
            "text_input": None,
            "text_vector": list(feature_vector.text_vector or ()),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def keyed_feature_fingerprint(feature_vector: FeatureVector, key: bytes) -> str:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ConfirmedExampleValidationError("invalid_fingerprint_key")
    message = (
        b"ShieldDome Confirmed Example Fingerprint v1\0"
        + canonical_feature_vector_bytes(feature_vector)
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def label_for_confirmation_action(
    action: UserConfirmationAction,
) -> ExampleLabel:
    if action is UserConfirmationAction.CONFIRM_BENIGN:
        return ExampleLabel.BENIGN
    if action is UserConfirmationAction.CONFIRM_PHISHING:
        return ExampleLabel.PHISHING
    raise ConfirmedExampleValidationError("invalid_confirmation")


@dataclass(frozen=True, slots=True)
class ConfirmedExample:
    feature_vector: FeatureVector
    label: ExampleLabel
    source: ExampleSource
    confirmed_at: datetime
    keyed_fingerprint: str
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    fingerprint_version: str = EXAMPLE_FINGERPRINT_VERSION
    schema_version: str = CONFIRMED_EXAMPLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_example_feature_vector(self.feature_vector)
        if (
            not isinstance(self.label, ExampleLabel)
            or not isinstance(self.source, ExampleSource)
            or not isinstance(self.confirmed_at, datetime)
            or self.confirmed_at.tzinfo is None
            or self.confirmed_at.utcoffset() is None
            or not isinstance(self.keyed_fingerprint, str)
            or _LOWER_HEX_256.fullmatch(self.keyed_fingerprint) is None
            or self.feature_schema_version != FEATURE_SCHEMA_VERSION
            or self.feature_vector.schema_version != self.feature_schema_version
            or self.fingerprint_version != EXAMPLE_FINGERPRINT_VERSION
            or self.schema_version != CONFIRMED_EXAMPLE_SCHEMA_VERSION
        ):
            raise ConfirmedExampleValidationError("invalid_confirmed_example")

    @classmethod
    def create(
        cls,
        feature_vector: FeatureVector,
        *,
        label: ExampleLabel,
        source: ExampleSource,
        confirmed_at: datetime,
        keyed_fingerprint: str,
    ) -> "ConfirmedExample":
        return cls(
            feature_vector=feature_vector,
            label=label,
            source=source,
            confirmed_at=confirmed_at,
            keyed_fingerprint=keyed_fingerprint,
        )

    def to_json_bytes(self) -> bytes:
        payload = {
            "confirmed_at": self.confirmed_at.isoformat(),
            "feature_schema_version": self.feature_schema_version,
            "feature_vector": {
                "categorical_features": [list(item) for item in self.feature_vector.categorical_features],
                "missing_value_mask": list(self.feature_vector.missing_value_mask),
                "numeric_features": [list(item) for item in self.feature_vector.numeric_features],
                "schema_version": self.feature_vector.schema_version,
                "text_input": self.feature_vector.text_input,
                "text_vector": list(self.feature_vector.text_vector or ()),
            },
            "fingerprint_version": self.fingerprint_version,
            "keyed_fingerprint": self.keyed_fingerprint,
            "label": self.label.value,
            "schema_version": self.schema_version,
            "source": self.source.value,
        }
        return json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> "ConfirmedExample":
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ConfirmedExampleValidationError(
                        "invalid_confirmed_example"
                    )
                result[key] = value
            return result

        def reject_constant(_value):
            raise ConfirmedExampleValidationError("invalid_confirmed_example")

        try:
            if (
                not isinstance(payload, bytes)
                or not payload
                or len(payload) > _MAX_SERIALIZED_BYTES
            ):
                raise ValueError
            values = json.loads(
                payload.decode("utf-8", errors="strict"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
            if not isinstance(values, dict) or set(values) != _SERIALIZED_FIELDS:
                raise ValueError
            vector_values = values["feature_vector"]
            if (
                not isinstance(vector_values, dict)
                or set(vector_values) != _FEATURE_VECTOR_FIELDS
                or not isinstance(vector_values["numeric_features"], list)
                or not isinstance(vector_values["categorical_features"], list)
                or not isinstance(vector_values["text_vector"], list)
                or not isinstance(vector_values["missing_value_mask"], list)
            ):
                raise ValueError
            vector = FeatureVector(
                numeric_features=tuple(
                    (item[0], item[1])
                    for item in vector_values["numeric_features"]
                ),
                categorical_features=tuple(
                    (item[0], item[1])
                    for item in vector_values["categorical_features"]
                ),
                text_input=vector_values["text_input"],
                text_vector=tuple(vector_values["text_vector"]),
                missing_value_mask=tuple(vector_values["missing_value_mask"]),
                schema_version=vector_values["schema_version"],
            )
            return cls(
                feature_vector=vector,
                label=ExampleLabel(values["label"]),
                source=ExampleSource(values["source"]),
                confirmed_at=datetime.fromisoformat(values["confirmed_at"]),
                keyed_fingerprint=values["keyed_fingerprint"],
                feature_schema_version=values["feature_schema_version"],
                fingerprint_version=values["fingerprint_version"],
                schema_version=values["schema_version"],
            )
        except ConfirmedExampleValidationError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            raise ConfirmedExampleValidationError("invalid_confirmed_example") from None


__all__ = [
    "CONFIRMED_EXAMPLE_SCHEMA_VERSION",
    "EXAMPLE_FINGERPRINT_VERSION",
    "ConfirmedExample",
    "ConfirmedExampleValidationError",
    "ExampleLabel",
    "ExampleSource",
    "UserConfirmationAction",
    "canonical_feature_vector_bytes",
    "keyed_feature_fingerprint",
    "label_for_confirmation_action",
    "validate_example_feature_vector",
]
