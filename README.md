# kxco-pq-verifiers

**Four languages. One wire format. Signatures interchange.**

Receiver-side verifier implementations of the KXCO hybrid HMAC + ML-DSA-65 webhook signature scheme. Every implementation verifies the same `vectors/vectors.json` against the same envelope format. Banks live in Go and Java. Fintech ops live in Python. Systems integrators live in Rust. A JavaScript-only verifier locks out the institutional buyer. This repo closes that gap.

[![cross-language CI](https://github.com/KnightsbridgeAIQ/kxco-pq-verifiers/actions/workflows/cross-lang.yml/badge.svg)](https://github.com/KnightsbridgeAIQ/kxco-pq-verifiers/actions/workflows/cross-lang.yml)
[![npm](https://img.shields.io/npm/v/kxco-post-quantum?label=npm)](https://www.npmjs.com/package/kxco-post-quantum)
[![PyPI](https://img.shields.io/pypi/v/kxco-verify?label=pypi)](https://pypi.org/project/kxco-verify/)
[![crates.io](https://img.shields.io/crates/v/kxco-verify?label=crates.io)](https://crates.io/crates/kxco-verify)
[![Go module](https://img.shields.io/badge/go.mod-v1.0.0-007d9c?logo=go)](https://pkg.go.dev/go.kxco.ai/verifiers)
[![live](https://img.shields.io/website?url=https%3A%2F%2Fchain.kxco.ai%2Fwallet%2Fverify&up_message=live&up_color=brightgreen&down_message=down&down_color=red&label=production)](https://chain.kxco.ai/wallet/verify)

## Install in your language

```bash
# JavaScript / TypeScript
npm install kxco-post-quantum

# Python
pip install kxco-verify

# Rust
cargo add kxco-verify

# Go
go get go.kxco.ai/verifiers@latest
```

## Verify a real KXCO production webhook

The KXCO platform publishes its ML-DSA-65 identity key at https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey. Pin the `kid` and `publicKey`, then verify any inbound delivery offline in the language of your choice.

The current production kid is **`aa29f37ab7f4b2cf`**. Fetch the matching `publicKey` from the well-known endpoint on first integration.

### JavaScript

```js
import { webhook } from 'kxco-post-quantum'

const PINNED_KID    = 'aa29f37ab7f4b2cf'
const PINNED_PUBKEY = Buffer.from(process.env.KXCO_PUBLIC_KEY_HEX, 'hex')

const r = webhook.verifyDelivery({
  headers,
  rawBody:     req.rawBody,
  pqPublicKey: PINNED_PUBKEY,
  pinnedKid:   PINNED_KID,
})
if (!r.pqOk || !r.timestampOk || !r.kidOk) return res.status(401).end()
```

### Python

```python
import kxco_verify as kx
import os

PINNED_KID    = "aa29f37ab7f4b2cf"
PINNED_PUBKEY = bytes.fromhex(os.environ["KXCO_PUBLIC_KEY_HEX"])

r = kx.verify_delivery(
    headers=lower_case_headers,
    raw_body=raw_body,
    pq_public_key=PINNED_PUBKEY,
    pinned_kid=PINNED_KID,
)
if not r.ok:
    return 401
```

### Rust

```rust
use kxco_verify::{verify_delivery, VerifyDeliveryArgs};

let result = verify_delivery(VerifyDeliveryArgs {
    headers:        &headers_map,
    raw_body:       &body,
    pq_public_key:  Some(&pinned_pubkey),
    pinned_kid:     Some("aa29f37ab7f4b2cf"),
    window_seconds: 0,
    now_unix:       chrono::Utc::now().timestamp(),
    ..Default::default()
});
if !result.ok() {
    return StatusCode::UNAUTHORIZED;
}
```

### Go

```go
import kxcoverify "go.kxco.ai/verifiers"

var PinnedKid = "aa29f37ab7f4b2cf"

result, err := kxcoverify.VerifyDelivery(kxcoverify.VerifyDeliveryArgs{
    Headers:     headers,
    RawBody:     body,
    PQPublicKey: pinnedPubkey,
    PinnedKid:   PinnedKid,
})
if err != nil || !result.Ok() {
    return http.StatusUnauthorized
}
```

## Wire format

All four implementations agree on a single envelope:

```
Envelope:               timestamp + "." + raw_body
X-KXCO-Signature:       sha256=<HMAC-SHA-256 hex>
X-KXCO-PQ-Signature:    ml-dsa-65=<ML-DSA-65 hex, 6618 chars>
X-KXCO-PQ-Kid:          16-hex SHA-256 prefix of the platform public key
X-KXCO-Timestamp:       Unix seconds
```

Either signature alone is sufficient; verifying both is defence-in-depth. The HMAC layer covers ecosystem compatibility; the ML-DSA layer covers non-repudiation and post-quantum forgery resistance.

Default replay window: 5 minutes. Configurable.

## Shared test vectors

[`vectors/vectors.json`](./vectors/vectors.json) — 29 deterministic checks across:

- `deriveSeed` (HKDF-SHA-512)
- `mlDsa.keypairFromMaster` (FIPS 204)
- `mlDsa.sign` round-trip
- `mlKem.keypairFromMaster` (FIPS 203)
- `mlKem.encapsulate` round-trip
- `fingerprint` (16-hex kid)
- `webhook.envelope` / `webhook.hmacHex` / hybrid round-trip

Every language's test suite asserts identical bytes against this file. Cross-language compatibility is enforced by CI on every push.

## Why each underlying library

| Language    | PQC library | Why |
|-------------|-------------|-----|
| JavaScript  | `@noble/post-quantum` | Audited by Cure53 (2024). Pure JS, no native deps. |
| Python      | `liboqs-python` or `pqcrypto` | Open Quantum Safe / NIST round-finalist implementation, lazy backend detection. |
| Rust        | `fips204` | Pure-Rust FIPS 204 implementation. No CGo or liboqs build step. |
| Go          | `cloudflare/circl/sign/mldsa/mldsa65` | Cloudflare's audited cryptography toolkit. Pure Go. |

## License

MIT. See individual language directories for any additional notices required by their dependencies.

## See also

- Main library: [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) on npm
- Live verifier demo: https://chain.kxco.ai/wallet/verify
- Live platform public key: https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey
- Security architecture: https://chain.kxco.ai/wallet/security
- Post-quantum overview: https://chain.kxco.ai/wallet/post-quantum
- Quantum Index (industry benchmark): https://chain.kxco.ai/wallet/quantum-index
