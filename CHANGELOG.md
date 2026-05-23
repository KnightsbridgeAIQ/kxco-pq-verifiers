# Changelog

All notable changes to the multi-language verifiers are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
each language uses its own SemVer line.

## [Unreleased]

## [Go 1.1.0] — 2026-05-23

### Added
- **`VerifyDeliveryArgs.PinnedKids map[string][]byte`** — accept a map of `{kid_hex: pubkey_bytes}` instead of a single `PinnedKid` + `PQPublicKey`. The verifier looks up the matching pubkey by the incoming `X-KXCO-PQ-Kid` header. Closes Go's gap behind the Phase 5 `pinnedKids[]` spec extension in `kxco-post-quantum-webhook` ≥ 0.3.0.
- **`Result.ResolvedKid`** — populated with the matched kid string when `PinnedKids` is used and matched; empty for single-kid mode.
- Mutual-exclusion check: passing both `PinnedKids` and `PinnedKid`/`PQPublicKey` returns an error.
- Tests: 3 new cases covering mutex enforcement, kid-mismatch handling, kid-match resolution.

### Compatibility
- Singular `PinnedKid` + `PQPublicKey` form continues to work unchanged. Zero behaviour change for v1.0.0 callers.
- Wire format identical to `kxco-post-quantum-webhook` ≥ 0.3.0 and to the spec in [`docs/webhook-contract.md`](https://github.com/JackKXCO/kxco-post-quantum-webhook/blob/main/docs/webhook-contract.md#key-rotation-and-history).
- Install: `go get github.com/JackKXCO/kxco-post-quantum-verifiers/go@v1.1.0`

## [Python 1.1.0] — 2026-05-23

### Added
- **`verify_delivery(..., pinned_kids=...)`** — accept a `Mapping[str, bytes]` of `{kid: pubkey}` instead of a single `pinned_kid` + `pq_public_key`. The verifier looks up the matching pubkey by the incoming `X-KXCO-PQ-Kid` header. Closes Python's gap behind the Phase 5 `pinnedKids[]` spec extension in `kxco-post-quantum-webhook` ≥ 0.3.0.
- **`VerifyResult.resolved_kid`** — populated with the matched kid string when `pinned_kids` is used and matched; `None` for single-kid mode. Useful for logging / metrics during rotation.
- Mutual-exclusion check: passing both `pinned_kids` and `pinned_kid`/`pq_public_key` raises `ValueError`.
- Tests: 3 new cases covering mutex enforcement, kid-mismatch handling, kid-match resolution.

### Compatibility
- Singular `pinned_kid` + `pq_public_key` form continues to work unchanged. Zero behaviour change for 1.0.0 callers.
- Wire format is identical to `kxco-post-quantum-webhook` ≥ 0.3.0 and to the spec in [`docs/webhook-contract.md`](https://github.com/JackKXCO/kxco-post-quantum-webhook/blob/main/docs/webhook-contract.md#key-rotation-and-history).

### Added
- `SECURITY.md` — scope, threat model, disclosure window
- `.github/dependabot.yml` — weekly Mon 06:00 UTC for gomod, pip, cargo, github-actions
- Bench scripts per language (`bench_kxco_verify.py`, `go test -bench`, `cargo run --example bench`)
- Root `README.md` rewritten as the multi-language landing page with badge row
- Trusted Publishing for PyPI (`pypa/gh-action-pypi-publish`) and crates.io
  (`rust-lang/crates-io-auth-action`) — no long-lived token secrets after one-time
  web UI configuration on each registry

### Security
- No cryptographic code changed. Production behaviour is bit-for-bit identical to:
  - JavaScript: `kxco-post-quantum@1.0.3` on npm (separate repo)
  - Python: `kxco-verify@1.0.0` on PyPI
  - Rust: `kxco-verify@1.0.0` on crates.io
  - Go: `kxco-post-quantum-verifiers/go@go/v1.0.0` on proxy.golang.org

## [python/v1.0.0] — 2026-05-21
First Python release. `pip install kxco-verify`. See https://pypi.org/project/kxco-verify/

## [rust/v1.0.0] — 2026-05-21
First Rust release. `cargo add kxco-verify`. See https://crates.io/crates/kxco-verify

## [go/v1.0.0] — 2026-05-21
First Go release. `go get github.com/JackKXCO/kxco-post-quantum-verifiers/go@v1.0.0`.
See https://pkg.go.dev/github.com/JackKXCO/kxco-post-quantum-verifiers/go
