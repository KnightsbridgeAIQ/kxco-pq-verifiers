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
import warnings

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


# ── ML-DSA-65 and ML-DSA-87 verification vectors ─────────────────────────────
#
# Structural refusals (key size, declared algorithm, signature size) need no
# backend. The cryptographic cases need oqs or pqcrypto; without one they are
# skipped with a warning, unless KXCO_REQUIRE_PQ_BACKEND=1, which CI sets so a
# missing backend fails instead of passing quietly.

REQUIRE_PQ_BACKEND = os.environ.get("KXCO_REQUIRE_PQ_BACKEND") == "1"
SKIPPED_NO_BACKEND = []


def _ml_dsa_case_inputs(v, case):
    """Resolve a case's key and header, checking the declared byte counts."""
    k = v["public_keys"][case["public_key"]]
    s = v["signatures"][case["signature"]]
    pk = bytes.fromhex(k["hex"])
    sig = bytes.fromhex(s["hex"])
    assert len(pk) == k["bytes"], f"public key {case['public_key']}: {len(pk)} bytes, want {k['bytes']}"
    assert len(sig) == s["bytes"], f"signature {case['signature']}: {len(sig)} bytes, want {s['bytes']}"
    return pk, case["header_prefix"] + s["hex"]


def _skip_no_backend(label):
    if REQUIRE_PQ_BACKEND:
        raise AssertionError(f"[{label}] no ML-DSA backend installed and KXCO_REQUIRE_PQ_BACKEND=1")
    SKIPPED_NO_BACKEND.append(label)
    warnings.warn(f"[{label}] skipped: no ML-DSA backend installed")


def test_ml_dsa_verify_vectors():
    v = load_vectors()["ml_dsa_verify"]
    assert v["cases"], "no ml_dsa_verify cases in vectors.json"
    failures = []
    for case in v["cases"]:
        pk, header = _ml_dsa_case_inputs(v, case)
        try:
            got = kx.verify_pq(pk, case["timestamp"], case["body_utf8"].encode("utf-8"), header)
        except RuntimeError:
            _skip_no_backend(f"ml_dsa_verify:{case['name']}")
            continue
        if got is not case["expect_valid"]:
            failures.append(f"[ml_dsa_verify:{case['name']}] expected {case['expect_valid']}, got {got!r}")
    assert not failures, f"{len(failures)} case(s) failed: " + "; ".join(failures)


def test_verify_delivery_pinned_kids_mixed_parameter_sets():
    """A rotation set may hold an ML-DSA-65 and an ML-DSA-87 key side by side;
    each delivery is verified under the set of the key its kid resolves to."""
    v = load_vectors()["ml_dsa_verify"]
    cases = {c["name"]: c for c in v["cases"]}
    c87 = cases["ML-DSA-87 valid, ml-dsa-87= prefix"]
    c65 = cases["ML-DSA-65 valid, ml-dsa-65= prefix (unchanged behaviour)"]
    pk87, h87 = _ml_dsa_case_inputs(v, c87)
    pk65, h65 = _ml_dsa_case_inputs(v, c65)
    kid87, kid65 = kx.fingerprint(pk87), kx.fingerprint(pk65)
    kids = {kid87: pk87, kid65: pk65}

    def deliver(kid, header, case):
        return kx.verify_delivery(
            headers={
                "x-kxco-timestamp": case["timestamp"],
                "x-kxco-pq-kid": kid,
                "x-kxco-pq-signature": header,
            },
            raw_body=case["body_utf8"].encode("utf-8"),
            pinned_kids=kids,
            now_unix=int(case["timestamp"]),
        )

    # An ML-DSA-87 signature under the ML-DSA-65 key's kid is refused before
    # any backend is needed.
    r = deliver(kid65, h87, c87)
    assert r.pq_ok is False and r.ok is False, f"ML-DSA-87 header under ML-DSA-65 kid: expected refusal, got {r}"

    for name, kid, header, case in (("ML-DSA-87", kid87, h87, c87), ("ML-DSA-65", kid65, h65, c65)):
        try:
            r = deliver(kid, header, case)
        except RuntimeError:
            _skip_no_backend(f"pinned_kids {name}")
            continue
        assert r.pq_ok is True and r.ok is True, f"{name}: expected pq_ok, got {r}"
        assert r.resolved_kid == kid, f"{name}: expected resolved_kid={kid}, got {r.resolved_kid!r}"


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
        ("ml_dsa_verify_vectors",          test_ml_dsa_verify_vectors),
        ("pinned_kids_mixed_ml_dsa_sets",  test_verify_delivery_pinned_kids_mixed_parameter_sets),
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
    if SKIPPED_NO_BACKEND:
        print(f"  SKIP  {len(SKIPPED_NO_BACKEND)} ML-DSA checks need a backend "
              f"(pip install pqcrypto or liboqs-python): {', '.join(SKIPPED_NO_BACKEND)}")
    if failed:
        sys.exit(1)
    print(f"\nAll {len(tests)} vector tests passed.")
