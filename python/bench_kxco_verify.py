"""Micro-benchmark: how many KXCO webhook deliveries can this machine
sign + verify per second?

Run:   python bench_kxco_verify.py
       BENCH_N=10000 python bench_kxco_verify.py

Reports: ops/sec for envelope, HMAC sign, HMAC verify, full verify_delivery
round-trip (HMAC-only path; PQ verify requires liboqs/pqcrypto installed).
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sys
import time

import kxco_verify as kx


def measure(label: str, n: int, fn) -> None:
    # warm-up
    for _ in range(min(50, n)):
        fn()
    start = time.perf_counter_ns()
    for _ in range(n):
        fn()
    elapsed_ns = time.perf_counter_ns() - start
    elapsed_ms = elapsed_ns / 1e6
    ops = n / (elapsed_ms / 1000)
    per = elapsed_ms / n
    print(f"  {label:<38}  {int(ops):>10,} ops/s   {per:>8.3f} ms/op")


def main() -> int:
    n = int(os.environ.get("BENCH_N", "1000"))
    body = b'{"event":"payment.settled","amount":1000,"ref":"INV-2026-001"}'
    secret = secrets.token_bytes(32)
    ts = "1748000000"

    print(f"kxco-verify (python) bench — N={n}")
    print(f"Python {sys.version.split()[0]} on {sys.platform}")
    print()

    measure("envelope construction",       n * 100, lambda: kx.envelope(ts, body))
    measure("HMAC-SHA-256 sign",           n * 10,  lambda: kx.hmac_hex(secret, ts, body))

    sig = "sha256=" + kx.hmac_hex(secret, ts, body)
    measure("HMAC-SHA-256 verify",         n * 10,  lambda: kx.verify_hmac(secret, ts, body, sig))

    pubkey = hashlib.sha256(b"demo").digest() * 61  # 1952 bytes; never decoded by HMAC-only path
    pubkey = pubkey[:1952]
    headers = {
        "x-kxco-timestamp":   str(int(time.time())),
        "x-kxco-signature":   "sha256=" + kx.hmac_hex(secret, str(int(time.time())), body),
        "x-kxco-pq-kid":      kx.fingerprint(pubkey),
    }
    measure("verify_delivery (HMAC-only)", n * 10,
            lambda: kx.verify_delivery(
                headers=headers, raw_body=body, hmac_secret=secret,
                pinned_kid=headers["x-kxco-pq-kid"],
            ))

    print()
    print("PQ verify rates depend on the installed ML-DSA backend (liboqs or pqcrypto).")
    print("Expect ~200-400 verify ops/sec/core on commodity x86-64 hardware.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
