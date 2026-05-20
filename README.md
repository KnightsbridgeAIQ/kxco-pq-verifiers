# kxco-post-quantum-verifiers

**Four languages. One wire format. Signatures interchange.**

This repository contains receiver-side verifier implementations of the KXCO hybrid HMAC + ML-DSA-65 webhook signature scheme in four languages:

| Language | Path | Status | ML-DSA dependency |
|---|---|---|---|
| **JavaScript / TypeScript** | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | v1.0.1 live on npm | `@noble/post-quantum` |
| **Go** | [`go/`](./go) | reference impl | `github.com/cloudflare/circl/sign/dilithium/mode3` |
| **Python** | [`python/`](./python) | reference impl | `oqs` (Open Quantum Safe) or `pqcrypto-mldsa-65` |
| **Rust** | [`rust/`](./rust) | reference impl | `fips204` crate |

Every implementation verifies the **same `vectors.json`** at the repo root. The wire format is identical across languages:

```
Envelope:    timestamp + "." + raw_body
HMAC header: X-KXCO-Signature: sha256=<HMAC-SHA-256-hex>
PQ header:   X-KXCO-PQ-Signature: ml-dsa-65=<ML-DSA-65-hex>
Kid header:  X-KXCO-PQ-Kid: <16-hex SHA-256 prefix of public key>
TS header:   X-KXCO-Timestamp: <Unix seconds>
```

## Why this exists

Banks live in Go and Java. Fintech ops live in Python. Systems-level integrators live in Rust. A JavaScript-only verifier locks out 80% of the institutional buyers KXCO targets. This repo proves the wire format is language-agnostic and the test vectors prove every implementation produces the same outputs.

## Quick start — verify a KXCO production webhook in your language

The KXCO platform's live ML-DSA-65 public key is at:

```
https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey
```

Pin the `kid` and the `publicKey` (3904 hex chars). Then use the verifier in your language to verify any inbound webhook from the KXCO production fleet offline.

## Cross-language compatibility CI

A GitHub Actions workflow (in `.github/workflows/cross-lang.yml`) runs each language's verifier against the shared vectors on every push. The matrix asserts: **the same bytes verify in all four languages.**

## Test vectors

[`vectors/vectors.json`](./vectors/vectors.json) — 29 deterministic checks across `deriveSeed`, `mlDsa.keypairFromMaster`, `mlDsa.sign` round-trip, `mlKem.keypairFromMaster`, `mlKem.encapsulate` round-trip, `fingerprint`, `webhook.envelope`, `webhook.hmacHex`, and full hybrid round-trip.

The HMAC and envelope checks are pure language-stdlib and always run. The ML-DSA and ML-KEM checks require the language-specific PQC dependency (documented per-language).

## License

MIT. See individual language directories for any additional notices required by their dependencies.

## See also

- Main library: [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) on npm
- Security architecture: https://chain.kxco.ai/wallet/security
- Live platform key: https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey
- Audit posture: in each language directory's `AUDIT.md`
