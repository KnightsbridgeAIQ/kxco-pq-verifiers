//! Micro-benchmark: how many KXCO webhook envelopes can this machine
//! sign + verify per second?
//!
//! Run:   cargo run --release --example bench
//!        BENCH_N=10000 cargo run --release --example bench
//!
//! Pure-Rust, no extra dev-dependencies. Uses std::time.

use kxco_verify::{envelope, fingerprint, hmac_hex, verify_hmac};
use std::env;
use std::time::Instant;

fn measure<F: FnMut()>(label: &str, n: u64, mut f: F) {
    // warm-up
    for _ in 0..50.min(n) {
        f();
    }
    let start = Instant::now();
    for _ in 0..n {
        f();
    }
    let elapsed = start.elapsed();
    let ms = elapsed.as_secs_f64() * 1000.0;
    let ops = (n as f64) / (ms / 1000.0);
    let per = ms / (n as f64);
    println!("  {:<38}  {:>10} ops/s   {:>8.3} ms/op", label, ops as u64, per);
}

fn main() {
    let n: u64 = env::var("BENCH_N").ok().and_then(|s| s.parse().ok()).unwrap_or(1000);
    let body = br#"{"event":"payment.settled","amount":1000,"ref":"INV-2026-001"}"#;
    let secret: &[u8] = b"32-byte-shared-secret-bench-key-";
    let ts = "1748000000";

    println!("kxco-verify (rust) bench — N={}", n);
    println!("rustc on {}/{}", env::consts::OS, env::consts::ARCH);
    println!();

    measure("envelope construction", n * 100, || {
        let _ = envelope(ts, body);
    });

    measure("HMAC-SHA-256 sign", n * 10, || {
        let _ = hmac_hex(secret, ts, body);
    });

    let sig = format!("sha256={}", hmac_hex(secret, ts, body));
    measure("HMAC-SHA-256 verify", n * 10, || {
        let _ = verify_hmac(secret, ts, body, &sig);
    });

    let key = vec![0xaa; 1952];
    measure("fingerprint (kid)", n * 100, || {
        let _ = fingerprint(&key);
    });

    println!();
    println!("ML-DSA-65 sign/verify benches are intentionally omitted here — the");
    println!("fips204 crate exposes those via Verifier::verify; on commodity x86-64");
    println!("hardware expect ~200-400 verify ops/sec/core.");
}
