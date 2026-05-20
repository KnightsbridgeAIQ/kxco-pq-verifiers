"""kxco_verify — receiver-side verifier for the KXCO hybrid HMAC + ML-DSA-65
webhook signature scheme.

Wire-format compatible with @kxco/post-quantum (npm), the Go verifier, and the
Rust verifier.

The HMAC, envelope, fingerprint, and timestamp paths depend only on the Python
standard library.

ML-DSA-65 verification requires one of:
    - `oqs`        (Open Quantum Safe Python bindings; pip install oqs)
    - `pqcrypto`   (pip install pqcrypto, with ML-DSA backend)
The verifier auto-detects the available backend at import time.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Mapping, Optional

DEFAULT_REPLAY_WINDOW = 300  # seconds

# ── ML-DSA backend detection ────────────────────────────────────────────────
#
# Backend selection is LAZY: probing happens only on the first verify_pq call.
# This keeps the HMAC and envelope paths fully functional even if no PQC
# library is installed locally (the receiver may only verify HMAC and treat PQ
# as defence-in-depth that they'll wire up later).

_ml_dsa_backend: Optional[str] = None
_pqcrypto_ml_dsa = None
_backend_probed = False


def _probe_ml_dsa_backend() -> None:
    """Lazy backend probe. Called from verify_pq only."""
    global _ml_dsa_backend, _pqcrypto_ml_dsa, _backend_probed
    if _backend_probed:
        return
    _backend_probed = True

    try:
        import oqs  # type: ignore
        probe = oqs.Signature("ML-DSA-65")  # raises if liboqs shared lib missing
        del probe
        _ml_dsa_backend = "oqs"
        return
    except Exception:
        pass

    try:
        from pqcrypto.sign import ml_dsa_65 as _ml_dsa_mod  # type: ignore
        _pqcrypto_ml_dsa = _ml_dsa_mod
        _ml_dsa_backend = "pqcrypto"
    except Exception:
        _pqcrypto_ml_dsa = None


# ── Envelope + HMAC primitives (pure stdlib) ─────────────────────────────────

def envelope(timestamp: str, raw_body: bytes) -> bytes:
    """Canonical signed envelope: timestamp + "." + raw_body bytes."""
    if isinstance(raw_body, str):
        raw_body = raw_body.encode("utf-8")
    return timestamp.encode("utf-8") + b"." + raw_body


def hmac_hex(secret: bytes, timestamp: str, raw_body: bytes) -> str:
    """HMAC-SHA-256 of the envelope, hex-encoded. No `sha256=` prefix."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    mac = hmac.new(secret, envelope(timestamp, raw_body), hashlib.sha256)
    return mac.hexdigest()


def verify_hmac(secret: bytes, timestamp: str, raw_body: bytes, sig_header: str) -> bool:
    """Constant-time verify of the X-KXCO-Signature header.
    Accepts the value with or without the `sha256=` prefix.
    """
    expected = "sha256=" + hmac_hex(secret, timestamp, raw_body)
    given = sig_header if sig_header.startswith("sha256=") else "sha256=" + sig_header
    return hmac.compare_digest(expected, given)


# ── ML-DSA-65 verify ─────────────────────────────────────────────────────────

def verify_pq(public_key: bytes, timestamp: str, raw_body: bytes, sig_header: str) -> bool:
    """Verify the X-KXCO-PQ-Signature ML-DSA-65 signature.

    Accepts header value with or without the `ml-dsa-65=` prefix.
    Returns False on any error (invalid hex, invalid key, signature mismatch).
    """
    hex_sig = sig_header[len("ml-dsa-65="):] if sig_header.startswith("ml-dsa-65=") else sig_header
    try:
        sig_bytes = bytes.fromhex(hex_sig)
    except ValueError:
        return False

    env = envelope(timestamp, raw_body)
    _probe_ml_dsa_backend()

    if _ml_dsa_backend == "oqs":
        try:
            import oqs  # type: ignore
            verifier = oqs.Signature("ML-DSA-65")
            return verifier.verify(env, sig_bytes, public_key)
        except Exception:
            return False

    if _ml_dsa_backend == "pqcrypto":
        try:
            _pqcrypto_ml_dsa.verify(public_key, sig_bytes + env)
            return True
        except Exception:
            return False

    raise RuntimeError(
        "No ML-DSA-65 backend available. Install one of:\n"
        "  pip install liboqs-python    # Open Quantum Safe (with liboqs built locally)\n"
        "  pip install pqcrypto         # pqcrypto with ML-DSA backend"
    )


# ── Kid / fingerprint ────────────────────────────────────────────────────────

def fingerprint(public_key: bytes) -> str:
    """16-hex kid: first 8 bytes of SHA-256(public_key)."""
    if isinstance(public_key, str):
        public_key = bytes.fromhex(public_key)
    return hashlib.sha256(public_key).hexdigest()[:16]


def kid_equals(a: str, b: str) -> bool:
    """Constant-time string compare for kids."""
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


# ── Full delivery verifier ───────────────────────────────────────────────────

@dataclass
class VerifyResult:
    hmac_ok: bool
    pq_ok: bool
    timestamp_ok: bool
    kid_ok: bool

    @property
    def ok(self) -> bool:
        return (self.hmac_ok or self.pq_ok) and self.timestamp_ok and self.kid_ok


def verify_delivery(
    *,
    headers: Mapping[str, str],
    raw_body: bytes,
    hmac_secret: Optional[bytes] = None,
    pq_public_key: Optional[bytes] = None,
    pinned_kid: Optional[str] = None,
    window_seconds: int = DEFAULT_REPLAY_WINDOW,
    now_unix: Optional[int] = None,
) -> VerifyResult:
    """Verify a KXCO webhook delivery.

    `headers` should have lowercase keys. `raw_body` must be the exact bytes
    received over the wire (do not re-stringify a parsed JSON object).

    Either signature alone is sufficient; verifying both is defence-in-depth.
    """
    timestamp = headers.get("x-kxco-timestamp", "")
    sig_hmac = headers.get("x-kxco-signature", "")
    sig_pq = headers.get("x-kxco-pq-signature", "")
    kid = headers.get("x-kxco-pq-kid", "")

    try:
        ts = int(timestamp)
    except ValueError:
        return VerifyResult(False, False, False, False)

    now = now_unix if now_unix is not None else int(time.time())
    timestamp_ok = abs(now - ts) <= window_seconds
    kid_ok = (pinned_kid is None) or kid_equals(kid, pinned_kid)

    hmac_ok = False
    if hmac_secret is not None and sig_hmac and timestamp_ok:
        hmac_ok = verify_hmac(hmac_secret, timestamp, raw_body, sig_hmac)

    pq_ok = False
    if pq_public_key is not None and sig_pq and timestamp_ok and kid_ok:
        pq_ok = verify_pq(pq_public_key, timestamp, raw_body, sig_pq)

    return VerifyResult(hmac_ok=hmac_ok, pq_ok=pq_ok, timestamp_ok=timestamp_ok, kid_ok=kid_ok)


__all__ = [
    "envelope",
    "hmac_hex",
    "verify_hmac",
    "verify_pq",
    "fingerprint",
    "kid_equals",
    "verify_delivery",
    "VerifyResult",
    "DEFAULT_REPLAY_WINDOW",
]
