# kxco-verify (Go)

Receiver-side verifier for the KXCO hybrid HMAC + ML-DSA-65 webhook signature scheme. Wire-format compatible with `@kxco/post-quantum` (npm), the Python verifier, and the Rust verifier.

## Install

```bash
go get go.kxco.ai/verifiers
```

## Quick start

```go
import (
    "encoding/hex"
    "net/http"
    "io"

    kxcoverify "go.kxco.ai/verifiers"
)

// Pin these from /.well-known/kxco-pq-pubkey on first integration
// Current KXCO production kid. Fetch fresh from /.well-known if KXCO ever rotates.
var PinnedKid    = "aa29f37ab7f4b2cf"
var PinnedPubkey, _ = hex.DecodeString("...3904 hex chars...")

func handleWebhook(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)

    // Lowercase the headers
    headers := make(map[string]string)
    for k, v := range r.Header {
        headers[strings.ToLower(k)] = v[0]
    }

    result, err := kxcoverify.VerifyDelivery(kxcoverify.VerifyDeliveryArgs{
        Headers:     headers,
        RawBody:     body,
        HMACSecret:  []byte(os.Getenv("KXCO_WEBHOOK_SECRET")),
        PQPublicKey: PinnedPubkey,
        PinnedKid:   PinnedKid,
    })
    if err != nil || !result.Ok() {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    // Process the webhook
}
```

## Running tests

The HMAC, envelope, and fingerprint test vectors use only Go's standard library and run immediately:

```bash
cd go
go test ./...
```

The ML-DSA verification depends on Cloudflare's `circl/sign/mldsa/mldsa65` and `circl/sign/mldsa/mldsa87`. `go mod tidy` will pull them on first run. The pinned public key decides the parameter set: 1952 bytes is ML-DSA-65 and 2592 bytes is ML-DSA-87.

## Wire format

| Header | Value |
|---|---|
| `X-KXCO-Timestamp`   | Unix seconds (string) |
| `X-KXCO-Signature`    | `sha256=<HMAC-SHA-256 hex>` |
| `X-KXCO-PQ-Signature` | `ml-dsa-65=<ML-DSA-65 hex, 6618 chars>` or `ml-dsa-87=<ML-DSA-87 hex, 9254 chars>`; the prefix must match the pinned key's set |
| `X-KXCO-PQ-Kid`       | 16-hex SHA-256 prefix of the platform public key |

Signed envelope: `timestamp + "." + raw_body`

## License

MIT.
