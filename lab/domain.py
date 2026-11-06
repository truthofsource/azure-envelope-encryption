from dataclasses import replace
import hashlib
from .envelope import LocalKeyring, encrypt, decrypt, rewrap


def demo():
    ring = LocalKeyring()
    plain = b"FICTIONAL RECORD VALUE - NOT PERSONAL DATA"
    first = encrypt(plain, "record-001", "field-001", ring)
    second = encrypt(plain, "record-001", "field-001", ring)
    checks = [
        {
            "name": "Authorized context round trip succeeds",
            "passed": decrypt(first, "record-001", "field-001", ring) == plain,
            "detail": "AES-256-GCM data key wrapped with real local RSA-OAEP-256",
        },
        {
            "name": "Repeated plaintext receives fresh key/nonce material",
            "passed": first.nonce != second.nonce
            and first.wrapped_key != second.wrapped_key
            and first.ciphertext != second.ciphertext,
            "detail": "No deterministic ciphertext or reused envelope",
        },
    ]
    for name, value, record in [
        (
            "Changed ciphertext is rejected",
            replace(
                first,
                ciphertext=bytes([first.ciphertext[0] ^ 1]) + first.ciphertext[1:],
            ),
            "record-001",
        ),
        ("Another record cannot reuse this ciphertext", first, "record-002"),
    ]:
        try:
            decrypt(value, record, "field-001", ring)
            passed = False
        except ValueError:
            passed = True
        checks.append(
            {
                "name": name,
                "passed": passed,
                "detail": "Authenticated decryption fails without releasing a value",
            }
        )
    ring.rotate()
    new = encrypt(plain, "record-001", "field-001", ring)
    checks.append(
        {
            "name": "New writes use v2 while retained v1 remains readable",
            "passed": new.key_version == "v2"
            and first.key_version == "v1"
            and decrypt(first, "record-001", "field-001", ring) == plain,
            "detail": "Each envelope selects its stored key version",
        }
    )
    updated = rewrap(first, "record-001", "field-001", ring)
    checks.append(
        {
            "name": "Local rewrap preserves ciphertext",
            "passed": updated.ciphertext == first.ciphertext
            and updated.key_version == "v2"
            and decrypt(updated, "record-001", "field-001", ring) == plain,
            "detail": "A reference recovery exercise, not a live migration",
        }
    )
    del ring.keys["v1"]
    try:
        decrypt(first, "record-001", "field-001", ring)
        missing = False
    except ValueError:
        missing = True
    checks.append(
        {
            "name": "Missing historical key fails without fallback",
            "passed": missing,
            "detail": "The current key cannot replace an unavailable historical version",
        }
    )
    fingerprint = hashlib.sha256(first.ciphertext).hexdigest()[:20]
    return {
        "checks": checks,
        "metrics": [
            {
                "label": "Data encryption",
                "value": "AES-256-GCM",
                "detail": "32-byte data key; 12-byte nonce",
            },
            {
                "label": "Key wrapping",
                "value": "RSA-OAEP-256",
                "detail": "3072-bit local wrapping key",
            },
            {
                "label": "Version exercise",
                "value": "v1 to v2",
                "detail": "Historical reads and local rewrap",
            },
            {
                "label": "Cloud requests",
                "value": "0",
                "detail": "In-memory keys; no Key Vault calls",
            },
        ],
        "records": [
            [
                "record-001 / field-001",
                "Encrypted",
                "Ciphertext SHA-256 " + fingerprint,
            ],
            [
                "Stored envelope",
                "Metadata",
                "Nonce, tag, wrapped key, key ID and version",
            ],
            ["v1 after rotation", "Readable", "Requires retained matching key version"],
            ["wrong record / changed bytes", "Rejected", "No plaintext released"],
            ["missing v1 key", "Rejected", "No current-version fallback"],
        ],
        "example_envelope": first.public_fields(),
    }
