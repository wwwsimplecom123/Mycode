"""AES-GCM encryption for secrets configured through the admin console."""

from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path


class EncryptedSecretStore:
    AAD = b"shielddome-provider-secret-v1"

    def __init__(self, directory: Path, master_key: str = ""):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.key_file = self.directory / "provider-secrets.key"
        self.key, self.key_source = self._load_key(master_key.strip())

    def encrypt(self, value: str) -> str:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except (ImportError, OSError) as exc:
            raise RuntimeError("密钥加密组件无法加载，请重新安装依赖或修复 .deps 目录权限") from exc

        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(self.key).encrypt(nonce, value.encode("utf-8"), self.AAD)
        return "SDSEC1:" + base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")

    def decrypt(self, value: str) -> str:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except (ImportError, OSError) as exc:
            raise RuntimeError("密钥加密组件无法加载，请重新安装依赖或修复 .deps 目录权限") from exc

        if not value.startswith("SDSEC1:"):
            raise ValueError("不支持的密钥密文格式")
        payload = base64.urlsafe_b64decode(value.split(":", 1)[1])
        return AESGCM(self.key).decrypt(payload[:12], payload[12:], self.AAD).decode("utf-8")

    def _load_key(self, configured: str) -> tuple[bytes, str]:
        if configured:
            key = base64.urlsafe_b64decode(configured)
            if len(key) != 32:
                raise ValueError("SHIELDDOME_DATA_ENCRYPTION_KEY must decode to exactly 32 bytes")
            return key, "environment"
        if self.key_file.exists():
            key = base64.urlsafe_b64decode(self.key_file.read_text(encoding="ascii").strip())
            if len(key) != 32:
                raise ValueError("provider-secrets.key is invalid")
            return key, "local_key_file"
        key = secrets.token_bytes(32)
        self.key_file.write_text(base64.urlsafe_b64encode(key).decode("ascii"), encoding="ascii")
        os.chmod(self.key_file, 0o600)
        return key, "local_key_file"
