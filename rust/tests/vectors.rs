//! Vector-driven tests for kxco_verify. Loads the shared vectors.json and
//! asserts that this Rust implementation produces identical outputs to the
//! JavaScript, Go, and Python implementations.

use kxco_verify::{envelope, fingerprint, hmac_hex, kid_equals, verify_hmac};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Vectors {
    webhook_envelope: Vec<EnvelopeVec>,
    webhook_hmac:     Vec<HmacVec>,
    fingerprint:      Vec<FingerprintVec>,
}

#[derive(Debug, Deserialize)]
struct EnvelopeVec {
    name:                String,
    timestamp:           String,
    body_utf8:           String,
    expect_envelope_hex: String,
}

#[derive(Debug, Deserialize)]
struct HmacVec {
    name:            String,
    secret_utf8:     String,
    timestamp:       String,
    body_utf8:       String,
    expect_hmac_hex: String,
}

#[derive(Debug, Deserialize)]
struct FingerprintVec {
    name:        String,
    #[serde(default)]
    input_hex:   Option<String>,
    #[serde(default)]
    input_utf8:  Option<String>,
    expect_kid:  String,
}

fn load_vectors() -> Vectors {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("vectors");
    path.push("vectors.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {:?}: {}", path, e));
    serde_json::from_str(&raw).expect("vectors.json failed to parse")
}

#[test]
fn envelope_matches_vectors() {
    let v = load_vectors();
    for vec in &v.webhook_envelope {
        let got = hex::encode(envelope(&vec.timestamp, vec.body_utf8.as_bytes()));
        assert_eq!(got, vec.expect_envelope_hex, "[envelope:{}]", vec.name);
    }
}

#[test]
fn hmac_matches_vectors() {
    let v = load_vectors();
    for vec in &v.webhook_hmac {
        let got = hmac_hex(vec.secret_utf8.as_bytes(), &vec.timestamp, vec.body_utf8.as_bytes());
        assert_eq!(got, vec.expect_hmac_hex, "[hmac:{}]", vec.name);
        assert!(
            verify_hmac(
                vec.secret_utf8.as_bytes(),
                &vec.timestamp,
                vec.body_utf8.as_bytes(),
                &format!("sha256={}", got),
            ),
            "[hmac:{}] verify_hmac returned false on its own output",
            vec.name
        );
    }
}

#[test]
fn fingerprint_hex_input_matches() {
    let v = load_vectors();
    for vec in &v.fingerprint {
        let Some(h) = &vec.input_hex else { continue };
        let raw = hex::decode(h).expect("vector input_hex was not valid hex");
        let got = fingerprint(&raw);
        assert_eq!(got, vec.expect_kid, "[fingerprint:{}]", vec.name);
    }
}

#[test]
fn fingerprint_utf8_input_matches() {
    let v = load_vectors();
    for vec in &v.fingerprint {
        let Some(s) = &vec.input_utf8 else { continue };
        let got = fingerprint(s.as_bytes());
        assert_eq!(got, vec.expect_kid, "[fingerprint:{}]", vec.name);
    }
}

#[test]
fn kid_equals_constant_time() {
    assert!(kid_equals("4a7c9e2f1b3d5680", "4a7c9e2f1b3d5680"));
    assert!(!kid_equals("4a7c9e2f1b3d5680", "0000000000000000"));
    assert!(!kid_equals("short", "longer"));
}

#[test]
fn verify_hmac_accepts_prefixed_and_bare() {
    let v = load_vectors();
    let vec = &v.webhook_hmac[0];
    let bare = &vec.expect_hmac_hex;
    let prefixed = format!("sha256={}", bare);

    assert!(verify_hmac(vec.secret_utf8.as_bytes(), &vec.timestamp, vec.body_utf8.as_bytes(), bare));
    assert!(verify_hmac(vec.secret_utf8.as_bytes(), &vec.timestamp, vec.body_utf8.as_bytes(), &prefixed));

    let mut tampered = bare.to_string();
    tampered.replace_range(0..1, "0");
    assert!(!verify_hmac(vec.secret_utf8.as_bytes(), &vec.timestamp, vec.body_utf8.as_bytes(), &tampered));
}
