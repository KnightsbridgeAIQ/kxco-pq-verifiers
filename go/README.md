# kxco-verify (Go)

Receiver-side verifier for the KXCO hybrid HMAC and ML-DSA webhook signature scheme, ML-DSA-87 and ML-DSA-65 (FIPS 204). Wire-format compatible with `kxco-post-quantum` (npm), the Python verifier, and the Rust verifier.

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
// Current KXCO production kid (ML-DSA-87). Fetch fresh from /.well-known if KXCO ever rotates.
var PinnedKid    = "1fd9ed3b769c28fc"
var PinnedPubkey, _ = hex.DecodeString("...5184 hex chars...")

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

The ML-DSA verification depends on Cloudflare's `circl/sign/mldsa/mldsa87` and `circl/sign/mldsa/mldsa65`. `go mod tidy` will pull them on first run. The pinned public key decides the parameter set: 2592 bytes is ML-DSA-87 and 1952 bytes is ML-DSA-65.

## Wire format

| Header | Value |
|---|---|
| `X-KXCO-Timestamp`   | Unix seconds (string) |
| `X-KXCO-Signature`    | `sha256=<HMAC-SHA-256 hex>` |
| `X-KXCO-PQ-Signature` | `ml-dsa-87=<ML-DSA-87 hex, 9254 chars>` or `ml-dsa-65=<ML-DSA-65 hex, 6618 chars>`; the prefix must match the pinned key's set |
| `X-KXCO-PQ-Kid`       | 16-hex SHA-256 prefix of the platform public key |

Signed envelope: `timestamp + "." + raw_body`

## License

MIT.
