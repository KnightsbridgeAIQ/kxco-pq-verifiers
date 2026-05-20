# kxco-verify (Go)

Receiver-side verifier for the KXCO hybrid HMAC + ML-DSA-65 webhook signature scheme. Wire-format compatible with `@kxco/post-quantum` (npm), the Python verifier, and the Rust verifier.

## Install

```bash
go get github.com/JackKXCO/kxco-post-quantum-verifiers/go
```

## Quick start

```go
import (
    "encoding/hex"
    "net/http"
    "io"

    kxcoverify "github.com/JackKXCO/kxco-post-quantum-verifiers/go"
)

// Pin these from /.well-known/kxco-pq-pubkey on first integration
var PinnedKid    = "4a7c9e2f1b3d5680"
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

The full ML-DSA-65 verification depends on Cloudflare's `circl/sign/dilithium/mode3`. `go mod tidy` will pull it on first run.

## Wire format

| Header | Value |
|---|---|
| `X-KXCO-Timestamp`   | Unix seconds (string) |
| `X-KXCO-Signature`    | `sha256=<HMAC-SHA-256 hex>` |
| `X-KXCO-PQ-Signature` | `ml-dsa-65=<ML-DSA-65 hex, 6618 chars>` |
| `X-KXCO-PQ-Kid`       | 16-hex SHA-256 prefix of the platform public key |

Signed envelope: `timestamp + "." + raw_body`

## License

MIT.
