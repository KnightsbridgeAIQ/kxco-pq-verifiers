# kxco-verify (Rust)

Receiver-side verifier for the KXCO hybrid HMAC + ML-DSA-65 webhook signature scheme. Wire-format compatible with `@kxco/post-quantum` (npm), the Go verifier, and the Python verifier.

## Add to your project

```toml
[dependencies]
kxco-verify = "1.0"
```

## Quick start (axum)

```rust
use axum::{Router, routing::post, response::IntoResponse, http::StatusCode, body::Bytes, http::HeaderMap};
use kxco_verify::{verify_delivery, VerifyDeliveryArgs};
use std::collections::HashMap;

async fn webhook(headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    let headers_map: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let pinned_pubkey = hex::decode(std::env::var("KXCO_PUBLIC_KEY_HEX").unwrap()).unwrap();
    let pinned_kid    = std::env::var("KXCO_PUBLIC_KID").unwrap();
    let hmac_secret   = std::env::var("KXCO_WEBHOOK_SECRET").unwrap();

    let now = chrono::Utc::now().timestamp();
    let result = verify_delivery(VerifyDeliveryArgs {
        headers:        &headers_map,
        raw_body:       &body,
        hmac_secret:    Some(hmac_secret.as_bytes()),
        pq_public_key:  Some(&pinned_pubkey),
        pinned_kid:     Some(&pinned_kid),
        window_seconds: 0, // use default
        now_unix:       now,
    });

    if !result.ok() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    StatusCode::OK.into_response()
}
```

## Running tests

```bash
cd rust
cargo test
```

This runs the shared vector tests against `vectors.json`. Expected: all tests pass — proving the Rust implementation produces identical outputs to the JavaScript, Go, and Python verifiers.

The ML-DSA verification uses the pure-Rust [`fips204`](https://crates.io/crates/fips204) crate. No C dependencies; no liboqs build step.

## License

MIT.
