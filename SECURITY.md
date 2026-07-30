# Security Policy

## Reporting a vulnerability
Email **john@knightsbridgelaw.com**. Do not open public issues for security reports.
PGP key available on request. We credit reporters in `CHANGELOG.md` unless they
request otherwise.

Acknowledgement within **2 business days**. Triage decision within **5 business days**.

Full policy: <https://kxco.ai/security>

## Safe harbour
If you make a good-faith effort to comply with this policy, we will treat your
research as authorised, and we will not pursue or support legal action against
you. Good faith means: do not access, modify, exfiltrate, or destroy data that
is not yours; use test accounts where possible; do not degrade service for
others; and stop and report as soon as you have established that a
vulnerability exists. This cannot bind third parties, and it does not cover
extortion, data sale, or public disclosure ahead of the window below.

## Scope
In scope:
- Cryptographic correctness of the verifier wrappers in each language
- Constant-time guarantees on HMAC and kid comparison across languages
- Replay-window enforcement in `webhook.verifyDelivery` (and language equivalents)
- Cross-language compatibility: a payload signed in one language MUST verify in every other

Out of scope (report upstream):
- Bugs in the underlying ML-DSA-65 implementations
  (`@noble/post-quantum`, `cloudflare/circl/sign/mldsa/mldsa65`, `fips204`,
   `liboqs-python`, `pqcrypto`)
- Bugs in standard-library `HMAC-SHA-256` / `SHA-256`

## Algorithms used
- ML-DSA-65 — NIST FIPS 204 (lattice signatures)
- HMAC-SHA-256 — FIPS 198-1
- SHA-256 — FIPS 180-4 (truncated for kid fingerprints)

## Wire format
See the root `README.md`. The signed envelope is `timestamp + "." + raw_body`.
Any change to envelope construction is a breaking change and bumps the major
version of every language.

## Test vectors
`vectors/vectors.json` is the canonical record. Every language's test suite
asserts identical bytes against this file. Tampering with vectors and bypassing
the cross-language CI is a security issue — report it.

## Disclosure
We follow coordinated disclosure with a 90-day default window.
For actively-exploited issues we ship a patch release within 48 hours.
