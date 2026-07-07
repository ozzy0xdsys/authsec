from __future__ import annotations

import base64
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ENCRYPTED_PREFIX = "aesgcm:v1:"


def password_sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def validate_password_length(password: str) -> None:
    length = len(password)
    if length < 4 or length > 30:
        raise ValueError("Password must be 4-30 characters long.")


def encrypt_text(value: str | None, password: str) -> str | None:
    if value is None:
        return None
    if is_encrypted_text(value):
        return value

    nonce = os.urandom(12)
    ciphertext = AESGCM(_key_from_password(password)).encrypt(
        nonce,
        value.encode("utf-8"),
        None,
    )
    return ENCRYPTED_PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_text(value: str | None, password: str) -> str | None:
    if value is None:
        return None
    if not is_encrypted_text(value):
        return value

    raw_value = value[len(ENCRYPTED_PREFIX) :]
    try:
        raw = base64.urlsafe_b64decode(raw_value.encode("ascii"))
        nonce = raw[:12]
        ciphertext = raw[12:]
        plaintext = AESGCM(_key_from_password(password)).decrypt(
            nonce,
            ciphertext,
            None,
        )
    except (ValueError, InvalidTag) as exc:
        raise ValueError("Could not decrypt stored account data.") from exc

    return plaintext.decode("utf-8")


def is_encrypted_text(value: str | None) -> bool:
    return bool(value and value.startswith(ENCRYPTED_PREFIX))


def _key_from_password(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()
