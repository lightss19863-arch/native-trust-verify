# native-trust-verify

Signature verification for desktop apps that need to validate cloud-issued receipts before trusting them.

## Why

My desktop app gets generated legal documents from a cloud runtime. Before those documents can be saved into the user's local workspace, the desktop needs to cryptographically verify that the cloud actually produced them and nothing was tampered with in transit. If verification fails, the document gets rejected — no exceptions, no "verify later," no "the hash was probably fine."

The trust bundle (a JSON file with the cloud's public keys) is baked into the binary at build time so it can't be swapped out by modifying a config file. Each key is scoped to a specific `purpose` (e.g., "runtime" keys can't forge "billing" receipts) and tied to an issuer identity.

## Supported algorithms

- **Ed25519** (RFC 8032) — primary, fast, small signatures
- **P-256 ECDSA** (FIPS 186-4) — because one cloud provider I integrate with uses this instead of Ed25519, and no, I didn't get to choose

The P-256 verifier accepts both raw `(r || s)` format and DER-encoded signatures because different providers serialize ECDSA differently. Because of course they do.

## Usage

```rust,no_run
use native_trust_verify::{TrustBundle, verify_signature};
use serde_json::json;

let bundle: TrustBundle = serde_json::from_str(bundle_json).unwrap();

let receipt = json!({
    "issuer": "cloud-runtime",
    "signingKeyId": "key-001",
    "issuerCapabilityDigest": "sha256:...",
    "signatureAlgorithm": "ed25519",
    "signedPayloadDigest": "sha256:...",
    "signature": "<base64url>"
});

verify_signature(&bundle, "runtime", &receipt).unwrap();
```

## Trust bundle format

```json
{
  "version": 1,
  "keys": [
    {
      "purpose": "runtime",
      "issuer": "cloud-runtime",
      "signingKeyId": "key-001",
      "issuerCapabilityDigest": "sha256:...",
      "signatureAlgorithm": "ed25519",
      "publicJwk": { "x": "<base64url-encoded public key>" }
    }
  ]
}
```

## Security notes

- Verification is fail-closed: any missing field, unknown algorithm, or mismatched purpose results in rejection.
- Error messages are intentionally non-specific about *what* failed (you don't want to give an attacker a verification oracle). They're specific enough to debug your own integration though — I learned that lesson after staring at "verification failed" for an hour when the actual problem was base64url padding.
- The trust bundle must contain exactly one key matching the receipt's `(issuer, keyId, capability, algorithm, purpose)` tuple. Zero matches = untrusted, multiple matches = ambiguous, both rejected.

## License

MIT
