from dataclasses import replace
import unittest
from lab.envelope import LocalKeyring, encrypt, decrypt, rewrap, context


class EnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ring = LocalKeyring()
        cls.ring.rotate()

    def value(self):
        return encrypt(b"000123456", "record-001", "field-001", self.ring)

    def test_round_trip_and_leading_zeroes(self):
        self.assertEqual(
            decrypt(self.value(), "record-001", "field-001", self.ring), b"000123456"
        )

    def test_fresh_material(self):
        first = self.value()
        second = self.value()
        self.assertNotEqual(first.nonce, second.nonce)
        self.assertNotEqual(first.wrapped_key, second.wrapped_key)

    def test_wrong_record(self):
        with self.assertRaises(ValueError):
            decrypt(self.value(), "record-002", "field-001", self.ring)

    def test_wrong_field(self):
        with self.assertRaises(ValueError):
            decrypt(self.value(), "record-001", "field-002", self.ring)

    def test_ciphertext_tamper(self):
        value = self.value()
        changed = replace(
            value, ciphertext=bytes([value.ciphertext[0] ^ 1]) + value.ciphertext[1:]
        )
        with self.assertRaises(ValueError):
            decrypt(changed, "record-001", "field-001", self.ring)

    def test_tag_tamper(self):
        with self.assertRaises(ValueError):
            decrypt(
                replace(self.value(), tag=b"0" * 16),
                "record-001",
                "field-001",
                self.ring,
            )

    def test_malformed_nonce(self):
        with self.assertRaises(ValueError):
            decrypt(
                replace(self.value(), nonce=b"short"),
                "record-001",
                "field-001",
                self.ring,
            )

    def test_wrapped_key_tamper(self):
        with self.assertRaises(ValueError):
            decrypt(
                replace(self.value(), wrapped_key=b"0" * 384),
                "record-001",
                "field-001",
                self.ring,
            )

    def test_foreign_key_id(self):
        with self.assertRaises(ValueError):
            decrypt(
                replace(self.value(), key_id="https://other.example.invalid/key"),
                "record-001",
                "field-001",
                self.ring,
            )

    def test_rotation_and_local_rewrap(self):
        ring = LocalKeyring()
        value = encrypt(b"fictional", "r1", "f1", ring)
        ring.rotate()
        self.assertEqual(decrypt(value, "r1", "f1", ring), b"fictional")
        updated = rewrap(value, "r1", "f1", ring)
        self.assertEqual(updated.ciphertext, value.ciphertext)
        self.assertEqual(updated.key_version, "v2")

    def test_missing_version_does_not_use_latest(self):
        with self.assertRaises(ValueError):
            decrypt(
                replace(self.value(), key_version="missing"),
                "record-001",
                "field-001",
                self.ring,
            )

    def test_context_identifiers_are_unambiguous(self):
        with self.assertRaises(ValueError):
            context("record:injected", "field")
