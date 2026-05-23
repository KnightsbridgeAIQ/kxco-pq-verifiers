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


def test_verify_delivery_pinned_kids_rejects_mixed_with_singular():
    """v1.1.0 — pinned_kids is mutually exclusive with pinned_kid/pq_public_key."""
    raised = False
    try:
        kx.verify_delivery(
            headers={}, raw_body=b"",
            pq_public_key=b"\x00" * 1952, pinned_kid="abcdef0123456789",
            pinned_kids={"abcdef0123456789": b"\x00" * 1952},
        )
    except ValueError as e:
        raised = "mutually exclusive" in str(e)
    assert raised


def test_verify_delivery_pinned_kids_kid_mismatch_sets_kid_not_ok():
    """v1.1.0 — incoming kid absent from pinned_kids set => kid_ok=False, resolved_kid=None."""
    kids = {
        "aaaaaaaaaaaaaaaa": b"\x00" * 1952,
        "bbbbbbbbbbbbbbbb": b"\x00" * 1952,
    }
    now = 1_000_000_000
    headers = {
        "x-kxco-timestamp": str(now),
        "x-kxco-pq-kid": "cccccccccccccccc",
        "x-kxco-pq-signature": "ml-dsa-65=" + "00" * 3309,
    }
    r = kx.verify_delivery(headers=headers, raw_body=b"{}", pinned_kids=kids, now_unix=now)
    assert r.kid_ok is False
    assert r.resolved_kid is None
    assert r.pq_ok is False
    assert r.ok is False


def test_verify_delivery_pinned_kids_kid_match_resolves_kid():
    """v1.1.0 — incoming kid in pinned_kids set => resolved_kid populated, kid_ok=True.

    No pq-signature header is sent — we're testing kid RESOLUTION, not the
    PQ math itself. (PQ math is exercised by the existing oqs/pqcrypto-backed
    integration tests in CI.)
    """
    pubkey = b"\x00" * 1952
    kids = {"aaaaaaaaaaaaaaaa": pubkey, "bbbbbbbbbbbbbbbb": pubkey}
    now = 1_000_000_000
    headers = {
        "x-kxco-timestamp": str(now),
        "x-kxco-pq-kid":    "aaaaaaaaaaaaaaaa",
        # deliberately no x-kxco-pq-signature: pq_ok stays False, kid resolution still works
    }
    r = kx.verify_delivery(headers=headers, raw_body=b"{}", pinned_kids=kids, now_unix=now)
    assert r.kid_ok is True, f"expected kid_ok=True, got {r.kid_ok}"
    assert r.resolved_kid == "aaaaaaaaaaaaaaaa", f"expected resolved_kid='aaa…', got {r.resolved_kid!r}"
    assert r.pq_ok is False  # no sig sent => no pq verify
    assert r.timestamp_ok is True


if __name__ == "__main__":
    # Plain runner — no pytest required
    tests = [
        ("envelope", test_envelope),
        ("hmac", test_hmac),
        ("fingerprint_hex_input", test_fingerprint_hex_input),
        ("fingerprint_utf8_input", test_fingerprint_utf8_input),
        ("kid_equals", test_kid_equals),
        ("verify_hmac_prefixes", test_verify_hmac_accepts_prefixed_and_bare),
        ("pinned_kids_mutual_exclusion",   test_verify_delivery_pinned_kids_rejects_mixed_with_singular),
        ("pinned_kids_kid_mismatch",       test_verify_delivery_pinned_kids_kid_mismatch_sets_kid_not_ok),
        ("pinned_kids_kid_match_resolves", test_verify_delivery_pinned_kids_kid_match_resolves_kid),
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
