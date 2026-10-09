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
	MlDsaVerify         mlDsaVerifyVectors  `json:"ml_dsa_verify"`
}

type mlDsaVerifyVectors struct {
	PublicKeys map[string]struct {
		Algorithm *string `json:"algorithm"`
		Bytes     int     `json:"bytes"`
		Hex       string  `json:"hex"`
	} `json:"public_keys"`
	Signatures map[string]struct {
		Bytes int    `json:"bytes"`
		Hex   string `json:"hex"`
	} `json:"signatures"`
	Cases []mlDsaVerifyCase `json:"cases"`
}

type mlDsaVerifyCase struct {
	Name           string  `json:"name"`
	PublicKey      string  `json:"public_key"`
	Signature      string  `json:"signature"`
	HeaderPrefix   string  `json:"header_prefix"`
	Timestamp      string  `json:"timestamp"`
	BodyUtf8       string  `json:"body_utf8"`
	ExpectValid    bool    `json:"expect_valid"`
	RefusedBecause *string `json:"refused_because"`
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

// ── ML-DSA-65 and ML-DSA-87 verification vectors ───────────────────────────

// mlDsaCaseInputs resolves a case's key and header from the shared vectors,
// checking the declared byte counts so a damaged vectors file cannot pass.
func mlDsaCaseInputs(t *testing.T, v mlDsaVerifyVectors, c mlDsaVerifyCase) ([]byte, string) {
	t.Helper()
	k, ok := v.PublicKeys[c.PublicKey]
	if !ok {
		t.Fatalf("unknown public_key %q", c.PublicKey)
	}
	s, ok := v.Signatures[c.Signature]
	if !ok {
		t.Fatalf("unknown signature %q", c.Signature)
	}
	pk, err := hex.DecodeString(k.Hex)
	if err != nil || len(pk) != k.Bytes {
		t.Fatalf("public key %q: %d bytes, want %d (err %v)", c.PublicKey, len(pk), k.Bytes, err)
	}
	sig, err := hex.DecodeString(s.Hex)
	if err != nil || len(sig) != s.Bytes {
		t.Fatalf("signature %q: %d bytes, want %d (err %v)", c.Signature, len(sig), s.Bytes, err)
	}
	return pk, c.HeaderPrefix + s.Hex
}

func TestMLDSAVerifyVectors(t *testing.T) {
	v := loadVectors(t).MlDsaVerify
	if len(v.Cases) == 0 {
		t.Fatal("no ml_dsa_verify cases in vectors.json")
	}
	// Refusals the API reports as an error rather than a plain false.
	errReasons := map[string]bool{
		"declared algorithm disagrees with the key": true,
		"public key size is neither 1952 nor 2592":  true,
		"an ML-DSA-87 key takes no bare-hex form":   true,
	}
	for _, c := range v.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			pk, header := mlDsaCaseInputs(t, v, c)
			ok, err := VerifyPQ(pk, c.Timestamp, []byte(c.BodyUtf8), header)
			if c.ExpectValid {
				if err != nil || !ok {
					t.Fatalf("expected valid, got ok=%v err=%v", ok, err)
				}
				return
			}
			if ok {
				t.Fatalf("expected refusal (%v), got ok=true", *c.RefusedBecause)
			}
			if wantErr := errReasons[*c.RefusedBecause]; wantErr != (err != nil) {
				t.Fatalf("refused because %q: want error=%v, got err=%v", *c.RefusedBecause, wantErr, err)
			}
		})
	}
}

// A rotation set may hold an ML-DSA-65 and an ML-DSA-87 key side by side; each
// delivery is verified under the set of the key its kid resolves to.
func TestVerifyDeliveryPinnedKidsMixedParameterSets(t *testing.T) {
	v := loadVectors(t).MlDsaVerify
	find := func(name string) mlDsaVerifyCase {
		for _, c := range v.Cases {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("missing case %q", name)
		return mlDsaVerifyCase{}
	}
	c87 := find("ML-DSA-87 valid, ml-dsa-87= prefix")
	c65 := find("ML-DSA-65 valid, ml-dsa-65= prefix (unchanged behaviour)")
	pk87, h87 := mlDsaCaseInputs(t, v, c87)
	pk65, h65 := mlDsaCaseInputs(t, v, c65)
	kid87, kid65 := Fingerprint(pk87), Fingerprint(pk65)
	kids := map[string][]byte{kid87: pk87, kid65: pk65}
	// The vectors carry a fixed 2025 timestamp; widen the window so only the
	// signature and kid predicates are under test.
	const window = int64(1) << 40

	deliver := func(kid, header string, c mlDsaVerifyCase) (Result, error) {
		return VerifyDelivery(VerifyDeliveryArgs{
			Headers: map[string]string{
				"x-kxco-timestamp":    c.Timestamp,
				"x-kxco-pq-kid":       kid,
				"x-kxco-pq-signature": header,
			},
			RawBody:       []byte(c.BodyUtf8),
			PinnedKids:    kids,
			WindowSeconds: window,
		})
	}

	for _, tc := range []struct {
		name, kid, header string
		c                 mlDsaVerifyCase
	}{
		{"ML-DSA-87 kid", kid87, h87, c87},
		{"ML-DSA-65 kid", kid65, h65, c65},
	} {
		r, err := deliver(tc.kid, tc.header, tc.c)
		if err != nil || !r.PqOk || !r.Ok() || r.ResolvedKid != tc.kid {
			t.Errorf("%s: expected PqOk and ResolvedKid=%s, got %+v err=%v", tc.name, tc.kid, r, err)
		}
	}

	// An ML-DSA-87 signature presented under the ML-DSA-65 key's kid is refused.
	r, err := deliver(kid65, h87, c87)
	if r.PqOk || r.Ok() || err == nil {
		t.Errorf("ML-DSA-87 header under ML-DSA-65 kid: expected refusal with error, got %+v err=%v", r, err)
	}
}
