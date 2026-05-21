package kxcoverify

import (
	"crypto/rand"
	"strconv"
	"testing"
	"time"
)

// Micro-benchmarks. Run: `go test -bench=. -benchmem ./...`

var benchBody = []byte(`{"event":"payment.settled","amount":1000,"ref":"INV-2026-001"}`)

func benchSecret() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func benchTs() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func BenchmarkEnvelope(b *testing.B) {
	ts := benchTs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Envelope(ts, benchBody)
	}
}

func BenchmarkHMACSign(b *testing.B) {
	secret := benchSecret()
	ts := benchTs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HMACHex(secret, ts, benchBody)
	}
}

func BenchmarkHMACVerify(b *testing.B) {
	secret := benchSecret()
	ts := benchTs()
	sig := "sha256=" + HMACHex(secret, ts, benchBody)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyHMAC(secret, ts, benchBody, sig)
	}
}

func BenchmarkFingerprint(b *testing.B) {
	key := make([]byte, 1952)
	rand.Read(key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Fingerprint(key)
	}
}

func BenchmarkKidEquals(b *testing.B) {
	a := "aa29f37ab7f4b2cf"
	c := "aa29f37ab7f4b2cf"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = KidEquals(a, c)
	}
}
