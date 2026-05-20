//! kxco-verify — receiver-side verifier for the KXCO hybrid HMAC + ML-DSA-65
//! webhook signature scheme.
//!
//! Wire-format compatible with `@kxco/post-quantum` (npm), the Go verifier,
//! and the Python verifier.
//!
//! ## Wire format
//!
//! ```text
//! Envelope:               timestamp + "." + raw_body
//! X-KXCO-Signature:       sha256=<HMAC-SHA-256 hex>
//! X-KXCO-PQ-Signature:    ml-dsa-65=<ML-DSA-65 hex, 6618 chars>
//! X-KXCO-PQ-Kid:          16-hex SHA-256 prefix of the platform public key
//! X-KXCO-Timestamp:       Unix seconds
//! ```

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Default replay window: a delivery timestamp must be within this many
/// seconds of local clock for the timestamp check to pass.
pub const DEFAULT_REPLAY_WINDOW: i64 = 300;

/// Outcome of a delivery verification. A delivery is acceptable when
/// `(hmac_ok || pq_ok) && timestamp_ok && kid_ok` — see [`VerifyResult::ok`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyResult {
    pub hmac_ok:      bool,
    pub pq_ok:        bool,
    pub timestamp_ok: bool,
    pub kid_ok:       bool,
}

impl VerifyResult {
    pub fn ok(&self) -> bool {
        (self.hmac_ok || self.pq_ok) && self.timestamp_ok && self.kid_ok
    }
}

/// Canonical signed envelope: `timestamp + "." + raw_body`.
///
/// Construct from the timestamp header and the **raw** request body bytes as
/// received. Re-serialising a parsed JSON object will not produce the same
/// bytes.
pub fn envelope(timestamp: &str, raw_body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(timestamp.len() + 1 + raw_body.len());
    out.extend_from_slice(timestamp.as_bytes());
    out.push(b'.');
    out.extend_from_slice(raw_body);
    out
}

/// HMAC-SHA-256 of the envelope, hex-encoded. No `sha256=` prefix.
pub fn hmac_hex(secret: &[u8], timestamp: &str, raw_body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC keys can be any size");
    mac.update(&envelope(timestamp, raw_body));
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time HMAC verify. Accepts the header value with or without the
/// `sha256=` prefix.
pub fn verify_hmac(secret: &[u8], timestamp: &str, raw_body: &[u8], sig_header: &str) -> bool {
    let expected = format!("sha256={}", hmac_hex(secret, timestamp, raw_body));
    let given = if sig_header.starts_with("sha256=") {
        sig_header.to_string()
    } else {
        format!("sha256={}", sig_header)
    };
    if expected.len() != given.len() {
        return false;
    }
    expected.as_bytes().ct_eq(given.as_bytes()).into()
}

/// Verify the X-KXCO-PQ-Signature ML-DSA-65 signature.
///
/// Accepts the header value with or without the `ml-dsa-65=` prefix.
/// `public_key` must be the raw 1952-byte ML-DSA-65 public key (decoded from
/// the `publicKey` hex field of `/.well-known/kxco-pq-pubkey`).
///
/// Returns `false` on any error (bad hex, invalid key, signature mismatch).
pub fn verify_pq(public_key: &[u8], timestamp: &str, raw_body: &[u8], sig_header: &str) -> bool {
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes, Verifier};

    let hex_sig = sig_header.strip_prefix("ml-dsa-65=").unwrap_or(sig_header);
    let sig_bytes = match hex::decode(hex_sig) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // FIPS-204 ML-DSA-65 public key is exactly 1952 bytes.
    let pk_arr: [u8; 1952] = match public_key.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; 3309] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let pk = match ml_dsa_65::PublicKey::try_from_bytes(pk_arr) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let env = envelope(timestamp, raw_body);
    pk.verify(&env, &sig_arr, &[])
}

/// 16-hex kid fingerprint: first 8 bytes of SHA-256 of the public key.
pub fn fingerprint(public_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(public_key);
    let digest = h.finalize();
    hex::encode(&digest[..8])
}

/// Constant-time string compare for kid values.
pub fn kid_equals(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Inputs to a full delivery verification.
pub struct VerifyDeliveryArgs<'a> {
    pub headers:        &'a dyn Headers,
    pub raw_body:       &'a [u8],
    pub hmac_secret:    Option<&'a [u8]>,
    pub pq_public_key:  Option<&'a [u8]>,
    pub pinned_kid:     Option<&'a str>,
    pub window_seconds: i64,
    pub now_unix:       i64,
}

/// Trait for header lookups. Implement on your HTTP framework's header map.
/// All lookups MUST be by lowercase key.
pub trait Headers {
    fn get(&self, key: &str) -> Option<&str>;
}

impl Headers for std::collections::HashMap<String, String> {
    fn get(&self, key: &str) -> Option<&str> {
        std::collections::HashMap::get(self, key).map(String::as_str)
    }
}

/// Full delivery verifier. Either signature alone is sufficient; verifying
/// both is defence-in-depth.
pub fn verify_delivery(args: VerifyDeliveryArgs<'_>) -> VerifyResult {
    let timestamp = args.headers.get("x-kxco-timestamp").unwrap_or("");
    let sig_hmac  = args.headers.get("x-kxco-signature").unwrap_or("");
    let sig_pq    = args.headers.get("x-kxco-pq-signature").unwrap_or("");
    let kid       = args.headers.get("x-kxco-pq-kid").unwrap_or("");

    let ts: i64 = timestamp.parse().unwrap_or(i64::MIN);
    let window  = if args.window_seconds == 0 { DEFAULT_REPLAY_WINDOW } else { args.window_seconds };
    let timestamp_ok = ts != i64::MIN && (args.now_unix - ts).abs() <= window;
    let kid_ok = args.pinned_kid.map_or(true, |pk| kid_equals(kid, pk));

    let hmac_ok = match (args.hmac_secret, !sig_hmac.is_empty() && timestamp_ok) {
        (Some(secret), true) => verify_hmac(secret, timestamp, args.raw_body, sig_hmac),
        _ => false,
    };
    let pq_ok = match (args.pq_public_key, !sig_pq.is_empty() && timestamp_ok && kid_ok) {
        (Some(pk), true) => verify_pq(pk, timestamp, args.raw_body, sig_pq),
        _ => false,
    };

    VerifyResult { hmac_ok, pq_ok, timestamp_ok, kid_ok }
}
