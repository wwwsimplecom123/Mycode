from dataclasses import dataclass
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .evidence_record import EndpointEvidenceRecord, EvidenceRecordValidationError


AES_256_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
EVIDENCE_CIPHERTEXT_MAX_BYTES = 65_536
EVIDENCE_ASSOCIATED_DATA_MAX_BYTES = 4_096


class EvidenceCryptoError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class EncryptedEvidence:
    nonce: bytes
    ciphertext: bytes
    authentication_tag: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.nonce, bytes)
            or len(self.nonce) != AES_GCM_NONCE_BYTES
            or not isinstance(self.ciphertext, bytes)
            or not self.ciphertext
            or len(self.ciphertext) > EVIDENCE_CIPHERTEXT_MAX_BYTES
            or not isinstance(self.authentication_tag, bytes)
            or len(self.authentication_tag) != AES_GCM_TAG_BYTES
        ):
            raise EvidenceCryptoError("invalid_encrypted_evidence")


def _validate_associated_data(value: bytes) -> None:
    if (
        not isinstance(value, bytes)
        or not value
        or len(value) > EVIDENCE_ASSOCIATED_DATA_MAX_BYTES
    ):
        raise EvidenceCryptoError("invalid_associated_data")


class EvidenceCipher:
    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != AES_256_KEY_BYTES:
            raise EvidenceCryptoError("invalid_data_key")
        self._cipher = AESGCM(key)

    def encrypt(
        self,
        record: EndpointEvidenceRecord,
        *,
        associated_data: bytes,
    ) -> EncryptedEvidence:
        if not isinstance(record, EndpointEvidenceRecord):
            raise EvidenceCryptoError("invalid_evidence_record")
        _validate_associated_data(associated_data)
        nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
        combined = self._cipher.encrypt(
            nonce,
            record.to_json_bytes(),
            associated_data,
        )
        return EncryptedEvidence(
            nonce=nonce,
            ciphertext=combined[:-AES_GCM_TAG_BYTES],
            authentication_tag=combined[-AES_GCM_TAG_BYTES:],
        )

    def decrypt(
        self,
        encrypted: EncryptedEvidence,
        *,
        associated_data: bytes,
    ) -> EndpointEvidenceRecord:
        if not isinstance(encrypted, EncryptedEvidence):
            raise EvidenceCryptoError("invalid_encrypted_evidence")
        _validate_associated_data(associated_data)
        try:
            plaintext = self._cipher.decrypt(
                encrypted.nonce,
                encrypted.ciphertext + encrypted.authentication_tag,
                associated_data,
            )
            return EndpointEvidenceRecord.from_json_bytes(plaintext)
        except (InvalidTag, EvidenceRecordValidationError, ValueError):
            raise EvidenceCryptoError("evidence_decryption_failed") from None


__all__ = [
    "AES_256_KEY_BYTES",
    "AES_GCM_NONCE_BYTES",
    "AES_GCM_TAG_BYTES",
    "EncryptedEvidence",
    "EvidenceCipher",
    "EvidenceCryptoError",
]
