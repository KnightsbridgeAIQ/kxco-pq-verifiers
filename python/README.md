# kxco-verify (Python)

Receiver-side verifier for the KXCO hybrid HMAC + ML-DSA-65 webhook signature scheme. Wire-format compatible with `@kxco/post-quantum` (npm), the Go verifier, and the Rust verifier.

## Install

```bash
pip install kxco-verify           # core (HMAC, envelope, fingerprint)
pip install kxco-verify[oqs]      # adds liboqs-python for ML-DSA
pip install kxco-verify[pqcrypto] # adds pqcrypto for ML-DSA
```

The HMAC, envelope, fingerprint, and timestamp paths use only the Python standard library. ML-DSA-65 verification is lazy-loaded: it only requires a PQC backend when `verify_pq` is actually called.

## Quick start (FastAPI)

```python
from fastapi import FastAPI, Request, HTTPException
import os
import kxco_verify as kx

PINNED_KID    = "4a7c9e2f1b3d5680"
PINNED_PUBKEY = bytes.fromhex("...3904 hex chars...")
HMAC_SECRET   = os.environ["KXCO_WEBHOOK_SECRET"].encode()

app = FastAPI()

@app.post("/webhooks/kxco")
async def webhook(request: Request):
    raw_body = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}

    result = kx.verify_delivery(
        headers=headers,
        raw_body=raw_body,
        hmac_secret=HMAC_SECRET,
        pq_public_key=PINNED_PUBKEY,
        pinned_kid=PINNED_KID,
    )
    if not result.ok:
        raise HTTPException(401, "invalid signature")

    return {"ok": True}
```

## Running tests

```bash
cd python
python test_kxco_verify.py
```

Expected: `All 6 vector tests passed.`

This verifies that the Python implementation produces identical outputs to `vectors.json` — the same file used by the JavaScript, Go, and Rust verifiers.

## License

MIT.
