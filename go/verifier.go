// Package kxcoverify is a receiver-side verifier for the KXCO hybrid HMAC +
// ML-DSA-65 webhook signature scheme, and for its ML-DSA-87 form. The
// receiver's pinned public key decides which parameter set a signature is
// verified under.
//
// Wire format is documented in the parent repository's README. The same wire
// format is implemented in @kxco/post-quantum (npm), the Python verifier, and
// the Rust verifier — signatures are interchangeable across all four.
package kxcoverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// DefaultReplayWindow is the time window (seconds) within which a delivery
// timestamp must fall, relative to local clock, for the timestamp check to pass.
const DefaultReplayWindow = 300

// Result captures which of the verification predicates passed for a delivery.
// A delivery is acceptable if (HmacOk || PqOk) && TimestampOk && KidOk.
type Result struct {
	HmacOk      bool
	PqOk        bool
	TimestampOk bool
	KidOk       bool
	// ResolvedKid is populated when PinnedKids is used and the incoming
	// X-KXCO-PQ-Kid header matched one of the pinned entries. Empty for
	// single-kid mode.
	ResolvedKid string
}

// Ok reports whether the delivery should be accepted.
func (r Result) Ok() bool {
	return (r.HmacOk || r.PqOk) && r.TimestampOk && r.KidOk
}

// Envelope returns the canonical signed envelope: timestamp + "." + body.
//
// This is the exact byte sequence the sender signs. Receivers MUST construct
// the envelope from the timestamp header and the raw body bytes as received —
// re-serialising a parsed JSON object will not produce the same bytes.
func Envelope(timestamp string, rawBody []byte) []byte {
	out := make([]byte, 0, len(timestamp)+1+len(rawBody))
	out = append(out, timestamp...)
	out = append(out, '.')
	out = append(out, rawBody...)
	return out
}

// HMACHex computes the HMAC-SHA-256 over the envelope and returns the hex.
// No "sha256=" prefix.
func HMACHex(secret []byte, timestamp string, rawBody []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(Envelope(timestamp, rawBody))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyHMAC checks the X-KXCO-Signature header against the envelope.
// Accepts the value with or without the "sha256=" prefix.
func VerifyHMAC(secret []byte, timestamp string, rawBody []byte, sigHeader string) bool {
	expected := "sha256=" + HMACHex(secret, timestamp, rawBody)
	given := sigHeader
	if !strings.HasPrefix(given, "sha256=") {
		given = "sha256=" + given
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(given)) == 1
}

// mlDsaSet is one ML-DSA parameter set the verifier accepts.
type mlDsaSet struct {
	name    string // header prefix without the "=", e.g. "ml-dsa-65"
	label   string // e.g. "ML-DSA-65"
	sigSize int
	verify  func(publicKey, msg, sig []byte) (bool, error)
}

var (
	mlDsa65Set = mlDsaSet{name: "ml-dsa-65", label: "ML-DSA-65", sigSize: mldsa65.SignatureSize,
		verify: func(publicKey, msg, sig []byte) (bool, error) {
			var pk mldsa65.PublicKey
			if err := pk.UnmarshalBinary(publicKey); err != nil {
				return false, fmt.Errorf("invalid ML-DSA-65 public key: %w", err)
			}
			return mldsa65.Verify(&pk, msg, nil, sig), nil
		}}
	mlDsa87Set = mlDsaSet{name: "ml-dsa-87", label: "ML-DSA-87", sigSize: mldsa87.SignatureSize,
		verify: func(publicKey, msg, sig []byte) (bool, error) {
			var pk mldsa87.PublicKey
			if err := pk.UnmarshalBinary(publicKey); err != nil {
				return false, fmt.Errorf("invalid ML-DSA-87 public key: %w", err)
			}
			return mldsa87.Verify(&pk, msg, nil, sig), nil
		}}
)

// mlDsaSetForPublicKey picks the parameter set from the public key size:
// 1952 bytes is ML-DSA-65, 2592 bytes is ML-DSA-87, anything else is refused.
func mlDsaSetForPublicKey(publicKey []byte) (mlDsaSet, error) {
	switch len(publicKey) {
	case mldsa65.PublicKeySize:
		return mlDsa65Set, nil
	case mldsa87.PublicKeySize:
		return mlDsa87Set, nil
	}
	return mlDsaSet{}, fmt.Errorf("invalid ML-DSA public key: %d bytes, want %d (ML-DSA-65) or %d (ML-DSA-87)",
		len(publicKey), mldsa65.PublicKeySize, mldsa87.PublicKeySize)
}

// VerifyPQ verifies the X-KXCO-PQ-Signature ML-DSA signature.
//
// publicKey is the raw ML-DSA public key (decoded from the hex value of
// /.well-known/kxco-pq-pubkey) and it decides the parameter set: 1952 bytes
// is ML-DSA-65 and 2592 bytes is ML-DSA-87. Any other size is an error.
//
// The header value may be bare hex or carry an "ml-dsa-65=" or "ml-dsa-87="
// prefix. A prefix naming the other parameter set from the key's is an error.
// A signature that is not the size of the key's set (3309 bytes for
// ML-DSA-65, 4627 for ML-DSA-87) does not verify.
func VerifyPQ(publicKey []byte, timestamp string, rawBody []byte, sigHeader string) (bool, error) {
	set, err := mlDsaSetForPublicKey(publicKey)
	if err != nil {
		return false, err
	}

	hexSig := sigHeader
	for _, declared := range []mlDsaSet{mlDsa65Set, mlDsa87Set} {
		if rest, found := strings.CutPrefix(sigHeader, declared.name+"="); found {
			if declared.name != set.name {
				return false, fmt.Errorf("signature header declares %s but the public key is %s", declared.label, set.label)
			}
			hexSig = rest
			break
		}
	}

	sigBytes, err := hex.DecodeString(hexSig)
	if err != nil {
		return false, fmt.Errorf("%s signature is not hex: %w", set.name, err)
	}
	if len(sigBytes) != set.sigSize {
		return false, nil
	}

	return set.verify(publicKey, Envelope(timestamp, rawBody), sigBytes)
}

// Fingerprint returns the 16-hex kid of a public key: first 8 bytes of SHA-256.
func Fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:8])
}

// KidEquals is a constant-time string compare suitable for header kids.
func KidEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// VerifyDeliveryArgs bundles the inputs to a full verification.
type VerifyDeliveryArgs struct {
	Headers       map[string]string // lowercase header keys
	RawBody       []byte
	HMACSecret    []byte // optional: omit to skip HMAC check
	PQPublicKey   []byte // optional: omit to skip PQ check
	PinnedKid     string // required when PQPublicKey is set
	// PinnedKids is a map of kid hex → raw ML-DSA pubkey (1952 bytes for
	// ML-DSA-65, 2592 bytes for ML-DSA-87; the two may be mixed).
	// When set, the verifier looks up the incoming X-KXCO-PQ-Kid header
	// against the map and uses the matched pubkey. Mutually exclusive
	// with PQPublicKey / PinnedKid (combining them returns an error).
	//
	// Added in v1.1.0 for Phase 5 multi-kid rotation support — see the
	// rotation playbook in kxco-post-quantum-webhook.
	PinnedKids    map[string][]byte
	WindowSeconds int64 // default DefaultReplayWindow
}

// VerifyDelivery checks every available signature and the timestamp window.
// Either signature alone is sufficient; verifying both is defence-in-depth.
func VerifyDelivery(args VerifyDeliveryArgs) (Result, error) {
	if args.PinnedKids != nil && (args.PinnedKid != "" || args.PQPublicKey != nil) {
		return Result{}, errors.New("VerifyDelivery: PinnedKids is mutually exclusive with PinnedKid/PQPublicKey — pick one shape")
	}

	if args.WindowSeconds == 0 {
		args.WindowSeconds = DefaultReplayWindow
	}
	timestamp := args.Headers["x-kxco-timestamp"]
	sigHmac := args.Headers["x-kxco-signature"]
	sigPq := args.Headers["x-kxco-pq-signature"]
	kid := args.Headers["x-kxco-pq-kid"]

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return Result{}, errors.New("missing or invalid x-kxco-timestamp")
	}
	delta := time.Now().Unix() - ts
	if delta < 0 {
		delta = -delta
	}

	// Resolve which pubkey to verify against this delivery.
	var (
		effPubKey  = args.PQPublicKey
		effPinned  = args.PinnedKid
		resolved   string
		kidOk      bool
	)
	if args.PinnedKids != nil {
		if k, found := args.PinnedKids[kid]; found {
			effPubKey = k
			effPinned = kid
			resolved = kid
			kidOk = true
		} else {
			effPubKey = nil
			effPinned = ""
			kidOk = false // no match in the pin set
		}
	} else {
		kidOk = args.PinnedKid == "" || KidEquals(kid, args.PinnedKid)
	}

	r := Result{
		TimestampOk: delta <= args.WindowSeconds,
		KidOk:       kidOk,
		ResolvedKid: resolved,
	}

	if args.HMACSecret != nil && sigHmac != "" && r.TimestampOk {
		r.HmacOk = VerifyHMAC(args.HMACSecret, timestamp, args.RawBody, sigHmac)
	}
	if effPubKey != nil && sigPq != "" && r.TimestampOk && r.KidOk {
		ok, err := VerifyPQ(effPubKey, timestamp, args.RawBody, sigPq)
		if err != nil {
			return r, err
		}
		r.PqOk = ok
	}
	_ = effPinned // currently unused but reserved for future log/metric annotation
	return r, nil
}
