# Signature test vectors (Appendix C.1, C.2)

Each `*.json` file in this directory is a single test vector that exercises one signed AFAuth request. Vectors are signed by the reference test keypair in [`../keypair.json`](../keypair.json).

## File shape

```jsonc
{
  "name":                       "<unique-kebab-case-name>",
  "description":                "<one-paragraph human-readable summary>",
  "section":                    "<spec section reference>",
  "request": {
    "method":     "GET | POST",
    "target_uri": "<absolute URL>",
    "body":       null | "<UTF-8 string>"
  },
  "content_digest":             null | "sha-256=:<base64>:",
  "covered_components":         ["@method", "@target-uri", "content-digest"?],
  "signature_params": {
    "created":  <unix-seconds>,
    "expires":  <unix-seconds>,
    "nonce":    "<opaque>",
    "keyid":    "did:key:...",
    "alg":      "ed25519"
  },
  "canonical_signature_input":  "<exact UTF-8 bytes per RFC 9421 §2.5>",
  "signature_hex":              "<128 hex chars; raw Ed25519 signature>",
  "public_key_did":             "did:key:..."
}
```

A conformant signer, given the `request`, `covered_components`, and `signature_params`, MUST produce the same `canonical_signature_input` (byte-exact) and the same `signature_hex` (with the reference private key).

A conformant verifier, given the full vector, MUST accept the signature.

## Regenerating

Vectors are deterministic. To regenerate after a fixture change:

```bash
node _generate.js
```

The generator reads `../keypair.json`, computes content-digest, builds the canonical input, signs with Ed25519, and writes one JSON file per fixture. It is idempotent: re-running produces identical output unless a fixture, the keypair, or the canonicalisation rule has changed.

## Coverage

| Vector | Method | Body | Recipient type |
|---|---|---|---|
| `get-account-introspection` | GET  | – | – |
| `get-discovery` | GET | – | – |
| `post-owner-invitation-email` | POST | JSON | `email` |
| `post-owner-invitation-phone` | POST | JSON | `phone` |
| `post-owner-invitation-oidc` | POST | JSON | `oidc` |
| `post-owner-invitation-did` | POST | JSON | `did` |
| `post-key-rotation` | POST | JSON | – |
| `post-claim-completion` | POST | JSON | – |

Eight vectors covering both verbs, both body modes, all four registered recipient types, and three of the protocol's endpoints. This is the minimum-viable set for §C.1 / §C.2 conformance; replay-window vectors (§C.6), discovery-document vectors (§C.3), recipient-normalisation vectors (§C.4), and error-envelope vectors (§C.5) are tracked separately.
