package kxcoverify

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	Version             string `json:"version"`
	WebhookEnvelope     []envelopeVector `json:"webhook_envelope"`
	WebhookHmac         []hmacVector     `json:"webhook_hmac"`
	Fingerprint         []fingerprintVector `json:"fingerprint"`
}

type envelopeVector struct {
	Name              string `json:"name"`
	Timestamp         string `json:"timestamp"`
	BodyUtf8          string `json:"body_utf8"`
	ExpectEnvelopeHex string `json:"expect_envelope_hex"`
}

type hmacVector struct {
	Name          string `json:"name"`
	SecretUtf8    string `json:"secret_utf8"`
	Timestamp     string `json:"timestamp"`
	BodyUtf8      string `json:"body_utf8"`
	ExpectHmacHex string `json:"expect_hmac_hex"`
}

type fingerprintVector struct {
	Name      string `json:"name"`
	InputHex  string `json:"input_hex,omitempty"`
	InputUtf8 string `json:"input_utf8,omitempty"`
	ExpectKid string `json:"expect_kid"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	path := filepath.Join("..", "vectors", "vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("could not parse vectors: %v", err)
	}
	return v
}

func TestEnvelope(t *testing.T) {
	v := loadVectors(t)
	for _, vec := range v.WebhookEnvelope {
		got := hex.EncodeToString(Envelope(vec.Timestamp, []byte(vec.BodyUtf8)))
		if got != vec.ExpectEnvelopeHex {
			t.Errorf("[envelope:%s]\n  expected: %s\n  actual:   %s", vec.Name, vec.ExpectEnvelopeHex, got)
		}
	}
}

func TestHMAC(t *testing.T) {
	v := loadVectors(t)
	for _, vec := range v.WebhookHmac {
		got := HMACHex([]byte(vec.SecretUtf8), vec.Timestamp, []byte(vec.BodyUtf8))
		if got != vec.ExpectHmacHex {
			t.Errorf("[hmac:%s]\n  expected: %s\n  actual:   %s", vec.Name, vec.ExpectHmacHex, got)
		}
		if !VerifyHMAC([]byte(vec.SecretUtf8), vec.Timestamp, []byte(vec.BodyUtf8), "sha256="+got) {
			t.Errorf("[hmac:%s] VerifyHMAC returned false on its own output", vec.Name)
		}
	}
}

func TestFingerprintHexInput(t *testing.T) {
	v := loadVectors(t)
	for _, vec := range v.Fingerprint {
		if vec.InputHex == "" {
			continue
		}
		raw, err := hex.DecodeString(vec.InputHex)
		if err != nil {
			t.Errorf("[fingerprint:%s] bad input hex: %v", vec.Name, err)
			continue
		}
		got := Fingerprint(raw)
		if got != vec.ExpectKid {
			t.Errorf("[fingerprint:%s]\n  expected: %s\n  actual:   %s", vec.Name, vec.ExpectKid, got)
		}
	}
}

func TestFingerprintUtf8Input(t *testing.T) {
	v := loadVectors(t)
	for _, vec := range v.Fingerprint {
		if vec.InputUtf8 == "" {
			continue
		}
		got := Fingerprint([]byte(vec.InputUtf8))
		if got != vec.ExpectKid {
			t.Errorf("[fingerprint:%s]\n  expected: %s\n  actual:   %s", vec.Name, vec.ExpectKid, got)
		}
	}
}

func TestKidEquals(t *testing.T) {
	if !KidEquals("4a7c9e2f1b3d5680", "4a7c9e2f1b3d5680") {
		t.Error("identical kids should be equal")
	}
	if KidEquals("4a7c9e2f1b3d5680", "0000000000000000") {
		t.Error("different kids should not be equal")
	}
	if KidEquals("short", "longer") {
		t.Error("different-length kids should not be equal")
	}
}

func TestVerifyHMACAcceptsBareAndPrefixed(t *testing.T) {
	v := loadVectors(t)
	vec := v.WebhookHmac[0]
	bare := vec.ExpectHmacHex
	prefixed := "sha256=" + bare
	if !VerifyHMAC([]byte(vec.SecretUtf8), vec.Timestamp, []byte(vec.BodyUtf8), bare) {
		t.Error("VerifyHMAC should accept bare hex header value")
	}
	if !VerifyHMAC([]byte(vec.SecretUtf8), vec.Timestamp, []byte(vec.BodyUtf8), prefixed) {
		t.Error("VerifyHMAC should accept sha256=-prefixed header value")
	}
	tampered := strings.Replace(bare, bare[:1], "0", 1)
	if VerifyHMAC([]byte(vec.SecretUtf8), vec.Timestamp, []byte(vec.BodyUtf8), tampered) {
		t.Error("VerifyHMAC should reject tampered HMAC")
	}
}

// ── v1.1.0 — PinnedKids multi-kid rotation tests ───────────────────────────

func TestVerifyDeliveryPinnedKidsRejectsMixedWithSingular(t *testing.T) {
	zeroPubKey := make([]byte, 1952)
	_, err := VerifyDelivery(VerifyDeliveryArgs{
		Headers:     map[string]string{},
		RawBody:     []byte("{}"),
		PQPublicKey: zeroPubKey,
		PinnedKid:   "aaaaaaaaaaaaaaaa",
		PinnedKids: map[string][]byte{
			"aaaaaaaaaaaaaaaa": zeroPubKey,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}
}

func TestVerifyDeliveryPinnedKidsKidMismatch(t *testing.T) {
	zeroPubKey := make([]byte, 1952)
	now := time.Now().Unix()
	r, err := VerifyDelivery(VerifyDeliveryArgs{
		Headers: map[string]string{
			"x-kxco-timestamp":    strconv.FormatInt(now, 10),
			"x-kxco-pq-kid":       "cccccccccccccccc",
			"x-kxco-pq-signature": "ml-dsa-65=" + strings.Repeat("00", 3309),
		},
		RawBody: []byte("{}"),
		PinnedKids: map[string][]byte{
			"aaaaaaaaaaaaaaaa": zeroPubKey,
			"bbbbbbbbbbbbbbbb": zeroPubKey,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.KidOk {
		t.Error("expected KidOk=false for unmatched kid")
	}
	if r.ResolvedKid != "" {
		t.Errorf("expected empty ResolvedKid, got %q", r.ResolvedKid)
	}
	if r.PqOk {
		t.Error("expected PqOk=false when KidOk=false")
	}
	if r.Ok() {
		t.Error("expected Ok=false for unmatched kid")
	}
}

func TestVerifyDeliveryPinnedKidsKidMatchResolves(t *testing.T) {
	zeroPubKey := make([]byte, 1952)
	now := time.Now().Unix()
	r, err := VerifyDelivery(VerifyDeliveryArgs{
		Headers: map[string]string{
			"x-kxco-timestamp": strconv.FormatInt(now, 10),
			"x-kxco-pq-kid":    "aaaaaaaaaaaaaaaa",
		},
		RawBody: []byte("{}"),
		PinnedKids: map[string][]byte{
			"aaaaaaaaaaaaaaaa": zeroPubKey,
			"bbbbbbbbbbbbbbbb": zeroPubKey,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.KidOk {
		t.Error("expected KidOk=true for matched kid")
	}
	if r.ResolvedKid != "aaaaaaaaaaaaaaaa" {
		t.Errorf("expected ResolvedKid='aaaa…', got %q", r.ResolvedKid)
	}
	if r.PqOk {
		t.Error("expected PqOk=false (no signature provided)")
	}
	if !r.TimestampOk {
		t.Error("expected TimestampOk=true for fresh timestamp")
	}
}
