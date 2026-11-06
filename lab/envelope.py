"""Real local envelope encryption; the in-memory keyring is not Azure Key Vault."""

from dataclasses import dataclass, replace
import base64
import json
import os
import re
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_ID = "https://example.vault.azure.net/keys/record-wrapping-key"


def context(record, field):
    if not all(
        isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value)
        for value in [record, field]
    ):
        raise ValueError("Use bounded record/field identifiers")
    return json.dumps(
        ["public-envelope:v1", record.lower(), field.lower()], separators=(",", ":")
    ).encode()


def oaep():
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    )


class LocalKeyring:
    def __init__(self):
        self.keys = {}
        self.current = None
        self.next_version = 1
        self.rotate()

    def rotate(self):
        version = "v" + str(self.next_version)
        if version in self.keys:
            raise ValueError("Version already exists")
        self.keys[version] = rsa.generate_private_key(
            public_exponent=65537, key_size=3072
        )
        self.next_version += 1
        self.current = version
        return version

    def wrap(self, key):
        if self.current not in self.keys:
            raise ValueError("Current wrapping key is unavailable")
        return (
            self.keys[self.current].public_key().encrypt(key, oaep()),
            KEY_ID,
            self.current,
        )

    def unwrap(self, wrapped, key_id, version):
        if key_id != KEY_ID or version not in self.keys:
            raise ValueError("Expected historical key/version is unavailable")
        return self.keys[version].decrypt(wrapped, oaep())


@dataclass(frozen=True)
class Envelope:
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    wrapped_key: bytes
    key_id: str
    key_version: str

    def public_fields(self):
        return {
            **{
                name: base64.b64encode(getattr(self, name)).decode()
                for name in ["ciphertext", "nonce", "tag", "wrapped_key"]
            },
            "key_id": self.key_id,
            "key_version": self.key_version,
        }


def validate(envelope):
    if not isinstance(envelope, Envelope):
        raise ValueError("Invalid envelope type")
    if not all(
        isinstance(getattr(envelope, name), bytes)
        for name in ["ciphertext", "nonce", "tag", "wrapped_key"]
    ):
        raise ValueError("Invalid binary envelope fields")
    if (
        not 0 < len(envelope.ciphertext) <= 65536
        or len(envelope.nonce) != 12
        or len(envelope.tag) != 16
        or not 1 <= len(envelope.wrapped_key) <= 512
    ):
        raise ValueError("Invalid envelope dimensions")
    if not isinstance(envelope.key_id, str) or not isinstance(
        envelope.key_version, str
    ):
        raise ValueError("Missing versioned key identity")


def encrypt(plaintext, record, field, keyring):
    if not isinstance(plaintext, bytes) or not 0 < len(plaintext) <= 65536:
        raise ValueError("Use bounded byte plaintext")
    aad = context(record, field)
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    encrypted = AESGCM(dek).encrypt(nonce, plaintext, aad)
    wrapped, key_id, version = keyring.wrap(dek)
    return Envelope(encrypted[:-16], nonce, encrypted[-16:], wrapped, key_id, version)


def decrypt(envelope, record, field, keyring):
    validate(envelope)
    key = keyring.unwrap(envelope.wrapped_key, envelope.key_id, envelope.key_version)
    if len(key) != 32:
        raise ValueError("Unwrapped data key has invalid length")
    try:
        return AESGCM(key).decrypt(
            envelope.nonce, envelope.ciphertext + envelope.tag, context(record, field)
        )
    except InvalidTag:
        raise ValueError("Ciphertext or record context failed authentication") from None


def rewrap(envelope, record, field, keyring):
    """Local reference only, not a production data/key migration command."""
    validate(envelope)
    key = keyring.unwrap(envelope.wrapped_key, envelope.key_id, envelope.key_version)
    try:
        AESGCM(key).decrypt(
            envelope.nonce, envelope.ciphertext + envelope.tag, context(record, field)
        )
    except InvalidTag:
        raise ValueError("Do not rewrap an unauthenticated envelope") from None
    wrapped, key_id, version = keyring.wrap(key)
    return replace(envelope, wrapped_key=wrapped, key_id=key_id, key_version=version)
