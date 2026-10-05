//! Vector-driven tests for kxco_verify. Loads the shared vectors.json and
//! asserts that this Rust implementation produces identical outputs to the
//! JavaScript, Go, and Python implementations.

use kxco_verify::{envelope, fingerprint, hmac_hex, kid_equals, verify_hmac, verify_pq};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Vectors {
    webhook_envelope: Vec<EnvelopeVec>,
    webhook_hmac:     Vec<HmacVec>,
    fingerprint:      Vec<FingerprintVec>,
    ml_dsa_verify:    MlDsaVerify,
}

#[derive(Debug, Deserialize)]
struct MlDsaVerify {
    public_keys: std::collections::HashMap<String, BytesHex>,
    signatures:  std::collections::HashMap<String, BytesHex>,
    cases:       Vec<MlDsaCase>,
}

#[derive(Debug, Deserialize)]
struct BytesHex {
    bytes: usize,
    hex:   String,
}

#[derive(Debug, Deserialize)]
struct MlDsaCase {
    name:          String,
    public_key:    String,
    signature:     String,
    header_prefix: String,
    timestamp:     String,
    body_utf8:     String,
    expect_valid:  bool,
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

// ── v1.1.0 — pinned_kids multi-kid rotation tests ────────────────────────

use kxco_verify::{verify_delivery, VerifyDeliveryArgs};
use std::collections::HashMap;

fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
#[should_panic(expected = "mutually exclusive")]
fn pinned_kids_rejects_mixed_with_singular() {
    let zero = vec![0u8; 1952];
    let headers = make_headers(&[]);
    let kids: Vec<(&str, &[u8])> = vec![("aaaaaaaaaaaaaaaa", &zero)];
    let _ = verify_delivery(VerifyDeliveryArgs {
        headers:        &headers,
        raw_body:       b"{}",
        hmac_secret:    None,
        pq_public_key:  Some(&zero),
        pinned_kid:     Some("aaaaaaaaaaaaaaaa"),
        pinned_kids:    Some(&kids),
        window_seconds: 0,
        now_unix:       0,
    });
}

#[test]
fn pinned_kids_kid_mismatch_sets_kid_not_ok() {
    let zero = vec![0u8; 1952];
    let pq_sig = format!("ml-dsa-65={}", "00".repeat(3309));
    let now: i64 = 1_000_000_000;
    let headers = make_headers(&[
        ("x-kxco-timestamp",    "1000000000"),
        ("x-kxco-pq-kid",       "cccccccccccccccc"),
        ("x-kxco-pq-signature", pq_sig.as_str()),
    ]);
    let kids: Vec<(&str, &[u8])> = vec![
        ("aaaaaaaaaaaaaaaa", &zero),
        ("bbbbbbbbbbbbbbbb", &zero),
    ];
    let r = verify_delivery(VerifyDeliveryArgs {
        headers:        &headers,
        raw_body:       b"{}",
        hmac_secret:    None,
        pq_public_key:  None,
        pinned_kid:     None,
        pinned_kids:    Some(&kids),
        window_seconds: 0,
        now_unix:       now,
    });
    assert!(!r.kid_ok, "expected kid_ok=false for unmatched kid");
    assert!(r.resolved_kid.is_none(), "expected resolved_kid=None, got {:?}", r.resolved_kid);
    assert!(!r.pq_ok);
    assert!(!r.ok());
}

#[test]
fn pinned_kids_kid_match_resolves() {
    let zero = vec![0u8; 1952];
    let now: i64 = 1_000_000_000;
    let headers = make_headers(&[
        ("x-kxco-timestamp", "1000000000"),
        ("x-kxco-pq-kid",    "aaaaaaaaaaaaaaaa"),
        // no pq signature — testing kid resolution only
    ]);
    let kids: Vec<(&str, &[u8])> = vec![
        ("aaaaaaaaaaaaaaaa", &zero),
        ("bbbbbbbbbbbbbbbb", &zero),
    ];
    let r = verify_delivery(VerifyDeliveryArgs {
        headers:        &headers,
        raw_body:       b"{}",
        hmac_secret:    None,
        pq_public_key:  None,
        pinned_kid:     None,
        pinned_kids:    Some(&kids),
        window_seconds: 0,
        now_unix:       now,
    });
    assert!(r.kid_ok, "expected kid_ok=true for matched kid");
    assert_eq!(r.resolved_kid.as_deref(), Some("aaaaaaaaaaaaaaaa"));
    assert!(!r.pq_ok, "expected pq_ok=false (no signature provided)");
    assert!(r.timestamp_ok);
}

// ── ML-DSA-65 and ML-DSA-87 verification vectors ─────────────────────────

/// Resolve a case's key and header, checking the declared byte counts so a
/// damaged vectors file cannot pass.
fn ml_dsa_case_inputs(v: &MlDsaVerify, c: &MlDsaCase) -> (Vec<u8>, String) {
    let k = v.public_keys.get(&c.public_key).unwrap_or_else(|| panic!("unknown public_key {}", c.public_key));
    let s = v.signatures.get(&c.signature).unwrap_or_else(|| panic!("unknown signature {}", c.signature));
    let pk = hex::decode(&k.hex).expect("public key hex");
    let sig = hex::decode(&s.hex).expect("signature hex");
    assert_eq!(pk.len(), k.bytes, "public key {}", c.public_key);
    assert_eq!(sig.len(), s.bytes, "signature {}", c.signature);
    (pk, format!("{}{}", c.header_prefix, s.hex))
}

#[test]
fn ml_dsa_verify_vectors() {
    let v = load_vectors().ml_dsa_verify;
    assert!(!v.cases.is_empty(), "no ml_dsa_verify cases in vectors.json");
    let mut failures = Vec::new();
    for c in &v.cases {
        let (pk, header) = ml_dsa_case_inputs(&v, c);
        let got = verify_pq(&pk, &c.timestamp, c.body_utf8.as_bytes(), &header);
        if got != c.expect_valid {
            failures.push(format!("[ml_dsa_verify:{}] expected {}, got {}", c.name, c.expect_valid, got));
        }
    }
    assert!(failures.is_empty(), "{} case(s) failed:\n{}", failures.len(), failures.join("\n"));
}

/// A rotation set may hold an ML-DSA-65 and an ML-DSA-87 key side by side;
/// each delivery is verified under the set of the key its kid resolves to.
#[test]
fn pinned_kids_mixed_ml_dsa_parameter_sets() {
    let v = load_vectors().ml_dsa_verify;
    let find = |name: &str| {
        v.cases.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("missing case {}", name))
    };
    let c87 = find("ML-DSA-87 valid, ml-dsa-87= prefix");
    let c65 = find("ML-DSA-65 valid, ml-dsa-65= prefix (unchanged behaviour)");
    let (pk87, h87) = ml_dsa_case_inputs(&v, c87);
    let (pk65, h65) = ml_dsa_case_inputs(&v, c65);
    let (kid87, kid65) = (fingerprint(&pk87), fingerprint(&pk65));
    let kids: Vec<(&str, &[u8])> = vec![(kid87.as_str(), pk87.as_slice()), (kid65.as_str(), pk65.as_slice())];

    let deliver = |kid: &str, header: &str, c: &MlDsaCase| {
        let headers = make_headers(&[
            ("x-kxco-timestamp",    c.timestamp.as_str()),
            ("x-kxco-pq-kid",       kid),
            ("x-kxco-pq-signature", header),
        ]);
        verify_delivery(VerifyDeliveryArgs {
            headers:        &headers,
            raw_body:       c.body_utf8.as_bytes(),
            hmac_secret:    None,
            pq_public_key:  None,
            pinned_kid:     None,
            pinned_kids:    Some(&kids),
            window_seconds: 0,
            now_unix:       c.timestamp.parse().expect("timestamp"),
        })
    };

    for (name, kid, header, c) in [("ML-DSA-87", &kid87, &h87, c87), ("ML-DSA-65", &kid65, &h65, c65)] {
        let r = deliver(kid, header, c);
        assert!(r.pq_ok && r.ok(), "{}: expected pq_ok, got {:?}", name, r);
        assert_eq!(r.resolved_kid.as_deref(), Some(kid.as_str()), "{}", name);
    }

    // An ML-DSA-87 signature under the ML-DSA-65 key's kid is refused.
    let r = deliver(&kid65, &h87, c87);
    assert!(!r.pq_ok && !r.ok(), "ML-DSA-87 header under ML-DSA-65 kid: expected refusal, got {:?}", r);
}
