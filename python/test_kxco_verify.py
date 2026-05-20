"""Vector-driven tests for kxco_verify. Loads the shared vectors.json and
asserts that this Python implementation produces identical outputs to the
JavaScript, Go, and Rust implementations.

Run:  python -m pytest test_kxco_verify.py -v
Or:   python test_kxco_verify.py
"""
from __future__ import annotations

import json
import os
import sys

import kxco_verify as kx

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.path.join(HERE, "..", "vectors", "vectors.json")


def load_vectors():
    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_envelope():
    v = load_vectors()
    for vec in v["webhook_envelope"]:
        got = kx.envelope(vec["timestamp"], vec["body_utf8"].encode("utf-8")).hex()
        assert got == vec["expect_envelope_hex"], f"[envelope:{vec['name']}]"


def test_hmac():
    v = load_vectors()
    for vec in v["webhook_hmac"]:
        got = kx.hmac_hex(
            vec["secret_utf8"].encode("utf-8"),
            vec["timestamp"],
            vec["body_utf8"].encode("utf-8"),
        )
        assert got == vec["expect_hmac_hex"], f"[hmac:{vec['name']}]"
        assert kx.verify_hmac(
            vec["secret_utf8"].encode("utf-8"),
            vec["timestamp"],
            vec["body_utf8"].encode("utf-8"),
            "sha256=" + got,
        )


def test_fingerprint_hex_input():
    v = load_vectors()
    for vec in v["fingerprint"]:
        if "input_hex" not in vec:
            continue
        raw = bytes.fromhex(vec["input_hex"])
        got = kx.fingerprint(raw)
        assert got == vec["expect_kid"], f"[fingerprint:{vec['name']}]"


def test_fingerprint_utf8_input():
    v = load_vectors()
    for vec in v["fingerprint"]:
        if "input_utf8" not in vec:
            continue
        got = kx.fingerprint(vec["input_utf8"].encode("utf-8"))
        assert got == vec["expect_kid"], f"[fingerprint:{vec['name']}]"


def test_kid_equals():
    assert kx.kid_equals("4a7c9e2f1b3d5680", "4a7c9e2f1b3d5680")
    assert not kx.kid_equals("4a7c9e2f1b3d5680", "0000000000000000")
    assert not kx.kid_equals("short", "longer")


def test_verify_hmac_accepts_prefixed_and_bare():
    v = load_vectors()
    vec = v["webhook_hmac"][0]
    secret = vec["secret_utf8"].encode("utf-8")
    body = vec["body_utf8"].encode("utf-8")
    bare = vec["expect_hmac_hex"]
    assert kx.verify_hmac(secret, vec["timestamp"], body, bare)
    assert kx.verify_hmac(secret, vec["timestamp"], body, "sha256=" + bare)
    tampered = "0" + bare[1:]
    assert not kx.verify_hmac(secret, vec["timestamp"], body, tampered)


if __name__ == "__main__":
    # Plain runner — no pytest required
    tests = [
        ("envelope", test_envelope),
        ("hmac", test_hmac),
        ("fingerprint_hex_input", test_fingerprint_hex_input),
        ("fingerprint_utf8_input", test_fingerprint_utf8_input),
        ("kid_equals", test_kid_equals),
        ("verify_hmac_prefixes", test_verify_hmac_accepts_prefixed_and_bare),
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
    if failed:
        sys.exit(1)
    print(f"\nAll {len(tests)} vector tests passed.")
