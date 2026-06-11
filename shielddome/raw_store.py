"""Encrypted raw EML storage.

Production must configure SHIELDDOME_DATA_ENCRYPTION_KEY as a URL-safe base64
encoded 32-byte AES key. Development without a key writes permission-restricted
plaintext and reports that state to the caller.
"""

from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path


class RawStore:
    def __init__(self, directory: Path, encryption_key: str = ""):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.encryption_key = encryption_key.strip()

    @property
    def encrypted(self) -> bool:
        return bool(self.encryption_key)

    def put(self, digest: str, raw: bytes) -> Path:
        if self.encryption_key:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            except ImportError as exc:
                raise RuntimeError("Encrypted raw storage requires cryptography") from exc
            key = base64.urlsafe_b64decode(self.encryption_key)
            if len(key) != 32:
                raise ValueError("SHIELDDOME_DATA_ENCRYPTION_KEY must decode to exactly 32 bytes")
            nonce = secrets.token_bytes(12)
            payload = b"SD01" + nonce + AESGCM(key).encrypt(nonce, raw, digest.encode("ascii"))
            path = self.directory / f"{digest}.eml.enc"
        else:
            payload = raw
            path = self.directory / f"{digest}.eml"
        path.write_bytes(payload)
        os.chmod(path, 0o600)
        return path
