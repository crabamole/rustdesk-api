"""Tests for the example admission webhook receiver (an example, not a supported product).
Run: python3 -m unittest test_receiver.py"""
import base64
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import receiver

KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
KEYS = receiver.load_keys(base64.b64encode(PUB).decode())


def header(body: bytes, t: int, key=KEY) -> str:
    return f"t={t},ed25519=" + base64.b64encode(key.sign(f"{t}.".encode() + body)).decode()


RULES = {
    "rules": [
        {"decision": "admit", "match": {"hostnames": ["CORP-WS-*"], "subnets": ["10.20.0.0/16"], "owner_groups": ["IT"]}},
        {"decision": "reject", "match": {"hostnames": ["*-guest"]}},
    ],
    "default": "pending",
}


class VerifyTest(unittest.TestCase):
    def test_valid_signature(self):
        now = int(time.time())
        self.assertIsNone(receiver.verify(header(b"{}", now), b"{}", KEYS, now, 300))

    def test_rejects_bad_signature_changed_body_old_and_missing(self):
        now = int(time.time())
        other = Ed25519PrivateKey.generate()
        self.assertIsNotNone(receiver.verify(header(b"{}", now, other), b"{}", KEYS, now, 300))
        self.assertIsNotNone(receiver.verify(header(b"{}", now), b'{"x":1}', KEYS, now, 300))
        self.assertIsNotNone(receiver.verify(header(b"{}", now - 301), b"{}", KEYS, now, 300))
        self.assertIsNotNone(receiver.verify("", b"{}", KEYS, now, 300))
        self.assertIsNotNone(receiver.verify("t=abc,ed25519=zz", b"{}", KEYS, now, 300))

    def test_any_of_several_keys(self):
        now = int(time.time())
        old = Ed25519PrivateKey.generate()
        old_pub = old.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        keys = receiver.load_keys(",".join(base64.b64encode(k).decode() for k in (old_pub, PUB)))
        self.assertIsNone(receiver.verify(header(b"{}", now, old), b"{}", keys, now, 300))
        self.assertIsNone(receiver.verify(header(b"{}", now), b"{}", keys, now, 300))


class DecideTest(unittest.TestCase):
    def dev(self, **kw):
        d = {"id": "1", "hostname": "", "os": "", "username": "", "ip": "", "owner": None, "first_seen": ""}
        d.update(kw)
        return d

    def test_first_match_wins_and_any_condition(self):
        self.assertEqual(receiver.decide(self.dev(hostname="corp-ws-7"), RULES), ("admit", "rule 1: admit"))
        self.assertEqual(receiver.decide(self.dev(ip="10.20.3.4"), RULES), ("admit", "rule 1: admit"))
        self.assertEqual(receiver.decide(self.dev(owner={"name": "a", "email": "", "group": "IT"}), RULES), ("admit", "rule 1: admit"))
        self.assertEqual(receiver.decide(self.dev(hostname="LAB-GUEST"), RULES), ("reject", "rule 2: reject"))

    def test_default_and_empty_fields(self):
        self.assertEqual(receiver.decide(self.dev(hostname="other", ip="", owner=None), RULES), ("pending", "default"))
        self.assertEqual(receiver.decide(self.dev(ip="not-an-ip"), RULES), ("pending", "default"))
        self.assertEqual(receiver.decide(self.dev(), {"rules": []}), ("pending", "default"))


if __name__ == "__main__":
    unittest.main()
