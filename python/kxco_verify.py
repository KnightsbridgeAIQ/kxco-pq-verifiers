"""kxco_verify is a receiver-side verifier for the KXCO hybrid HMAC and ML-DSA
webhook signature scheme, ML-DSA-87 and ML-DSA-65 (FIPS 204). The receiver's
pinned public key decides which parameter set a signature is verified under.

Wire-format compatible with kxco-post-quantum (npm), the Go verifier, and the
Rust verifier.

The HMAC, envelope, fingerprint, and timestamp paths depend only on the Python
standard library.

ML-DSA verification requires one of:
    - `oqs`        (Open Quantum Safe Python bindings; pip install oqs)
    - `pqcrypto`   (pip install pqcrypto, with ML-DSA backend)
The verifier auto-detects the available backend at import time.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib
import time
from dataclasses import dataclass
from typing import Mapping, Optional

DEFAULT_REPLAY_WINDOW = 300  # seconds

# ML-DSA parameter sets, keyed by public-key size. The key decides the set:
# public-key bytes -> (algorithm name, header prefix, signature bytes,
# pqcrypto module name).
_ML_DSA_SETS = {
    1952: ("ML-DSA-65", "ml-dsa-65=", 3309, "ml_dsa_65"),
    2592: ("ML-DSA-87", "ml-dsa-87=", 4627, "ml_dsa_87"),
}
_ML_DSA_PREFIXES = ("ml-dsa-65=", "ml-dsa-87=")

# ── ML-DSA backend detection ────────────────────────────────────────────────
#
# Backend selection is LAZY: probing happens only on the first verify_pq call.
# This keeps the HMAC and envelope paths fully functional even if no PQC
# library is installed locally (the receiver may only verify HMAC and treat PQ
# as defence-in-depth that they'll wire up later).

_ml_dsa_backend: Optional[str] = None
_backend_probed = False


def _probe_ml_dsa_backend() -> None:
    """Lazy backend probe. Called from verify_pq only."""
    global _ml_dsa_backend, _backend_probed
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
        from pqcrypto.sign import ml_dsa_65, ml_dsa_87  # type: ignore  # noqa: F401
        _ml_dsa_backend = "pqcrypto"
    except Exception:
        pass


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


# ── ML-DSA verify (ML-DSA-65 or ML-DSA-87, chosen by the key) ───────────────

def verify_pq(public_key: bytes, timestamp: str, raw_body: bytes, sig_header: str) -> bool:
    """Verify the X-KXCO-PQ-Signature ML-DSA signature.

    The public key decides the parameter set: 1952 bytes is ML-DSA-65 and 2592
    bytes is ML-DSA-87; any other size returns False. The header value carries
    an `ml-dsa-87=` or `ml-dsa-65=` prefix naming the key's set; a prefix naming
    the other set from the key's returns False. An ML-DSA-65 key also takes the
    bare hex, as it always has; an ML-DSA-87 key takes only `ml-dsa-87=`, and
    bare hex under it returns False, as in kxco-post-quantum 1.8.0 and later.
    A signature that is not the size of the key's set (3309 or 4627 bytes)
    returns False.

    Returns False on any error (invalid hex, invalid key, signature mismatch).
    Raises RuntimeError only when no ML-DSA backend is installed.
    """
    ml_set = _ML_DSA_SETS.get(len(public_key))
    if ml_set is None:
        return False
    algorithm, prefix, sig_size, pqcrypto_module = ml_set

    hex_sig, prefixed = sig_header, False
    for declared in _ML_DSA_PREFIXES:
        if sig_header.startswith(declared):
            if declared != prefix:
                return False
            hex_sig, prefixed = sig_header[len(declared):], True
            break
    if not prefixed and algorithm == "ML-DSA-87":
        return False
    try:
        sig_bytes = bytes.fromhex(hex_sig)
    except ValueError:
        return False
    if len(sig_bytes) != sig_size:
        return False

    env = envelope(timestamp, raw_body)
    _probe_ml_dsa_backend()

    if _ml_dsa_backend == "oqs":
        try:
            import oqs  # type: ignore
            verifier = oqs.Signature(algorithm)
            return verifier.verify(env, sig_bytes, public_key)
        except Exception:
            return False

    if _ml_dsa_backend == "pqcrypto":
        try:
            module = importlib.import_module("pqcrypto.sign." + pqcrypto_module)
            # pqcrypto 0.3.x returns True/False; 1.x returns None and raises on
            # failure. Anything else is treated as a failure.
            result = module.verify(public_key, env, sig_bytes)
            return result is None or result is True
        except Exception:
            return False

    raise RuntimeError(
        "No ML-DSA backend available. Install one of:\n"
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
    # Populated when `pinned_kids` is used and the incoming kid matched one
    # of the pinned entries. None when single-kid mode is used.
    resolved_kid: Optional[str] = None

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
    pinned_kids: Optional[Mapping[str, bytes]] = None,
    window_seconds: int = DEFAULT_REPLAY_WINDOW,
    now_unix: Optional[int] = None,
) -> VerifyResult:
    """Verify a KXCO webhook delivery.

    `headers` should have lowercase keys. `raw_body` must be the exact bytes
    received over the wire (do not re-stringify a parsed JSON object).

    Either signature alone is sufficient; verifying both is defence-in-depth.

    Multi-kid rotation (v1.1.0): pass `pinned_kids` as ``{kid_hex: pubkey_bytes}``
    to accept any kid in the set. Mutually exclusive with ``pinned_kid`` +
    ``pq_public_key``. See the rotation playbook at
    https://github.com/JackKXCO/kxco-post-quantum-webhook/blob/main/docs/key-rotation-playbook.md
    """
    if pinned_kids is not None and (pinned_kid is not None or pq_public_key is not None):
        raise ValueError(
            "verify_delivery: pinned_kids is mutually exclusive with pinned_kid/pq_public_key — pick one shape"
        )

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

    # Resolve which pubkey (if any) to verify against this delivery.
    effective_pubkey: Optional[bytes] = pq_public_key
    effective_pinned_kid: Optional[str] = pinned_kid
    resolved_kid: Optional[str] = None

    if pinned_kids is not None:
        # Multi-kid mode — look up the pubkey by the header's kid.
        match = pinned_kids.get(kid)
        if match is not None:
            effective_pubkey = match
            effective_pinned_kid = kid  # by definition matches
            resolved_kid = kid
        else:
            # No match — kid_ok will be False; pq won't be attempted.
            effective_pubkey = None
            effective_pinned_kid = None

    if pinned_kids is not None:
        kid_ok = resolved_kid is not None
    else:
        kid_ok = (effective_pinned_kid is None) or kid_equals(kid, effective_pinned_kid)

    hmac_ok = False
    if hmac_secret is not None and sig_hmac and timestamp_ok:
        hmac_ok = verify_hmac(hmac_secret, timestamp, raw_body, sig_hmac)

    pq_ok = False
    if effective_pubkey is not None and sig_pq and timestamp_ok and kid_ok:
        pq_ok = verify_pq(effective_pubkey, timestamp, raw_body, sig_pq)

    return VerifyResult(
        hmac_ok=hmac_ok, pq_ok=pq_ok, timestamp_ok=timestamp_ok,
        kid_ok=kid_ok, resolved_kid=resolved_kid,
    )


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
