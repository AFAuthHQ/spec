# AFAuth conformance harness

Minimum-viable conformance runner for the v0.1 test vectors.

## What it does

Loads every `*.json` vector across three categories and runs the
appropriate checks per category. Any failure prints the offending
vector name and a short diagnostic, and the runner exits with
status `1`.

### Signatures (§C.1, §C.2)

For every `*.json` under [`../vectors/signatures/`](../vectors/signatures/):

1. Confirms the `content_digest` field is a SHA-256 of the request body (or `null` if no body).
2. Re-builds the RFC 9421 canonical signature input from `request` + `covered_components` + `signature_params`, and asserts byte-equality with the committed `canonical_signature_input`.
3. Decodes the `did:key` from `public_key_did`, derives the Ed25519 public key, and verifies the committed `signature_hex` against the canonical input.
4. Asserts `signature_params.keyid == public_key_did`.

### Error envelopes (§C.5)

For every `*.json` under [`../vectors/errors/`](../vectors/errors/):

1. Asserts `code` is one of the §11.3 reserved values.
2. Asserts `http_status` is one of the §11.2 statuses.
3. Asserts `envelope.error.code === code` and `envelope.error.message` is a string.
4. Rejects unknown fields on `envelope.error` (allowed: `code`, `message`, `details`).

### Replay-window (§C.6)

For every `*.json` under [`../vectors/replay-window/`](../vectors/replay-window/):

1. Builds a verifier with the vector's `verifier_now_unix_seconds`.
2. If `extra_setup.kind === 'prime_nonce_under_other_keyid'`, primes the nonce store under that keyid.
3. Verifies the signed request and asserts the result matches `expected_outcome`.
4. For accept-with-replay vectors, re-verifies on the same nonce store and asserts the second result is `replayed_nonce`.

## Running

```bash
node harness/run.js                 # all vectors
node harness/run.js <name> [<name>] # selected vectors
```

Requires Node.js 18+ (uses the `crypto` module's Ed25519 support).

## Integration surface for third-party implementations

`harness/run.js` exports its building blocks for reuse:

```javascript
const {
  buildCanonicalInput,    // (vector) → string
  verifySignature,        // (canonicalInput, signatureHex, didKey) → boolean
  verifyContentDigest,    // (vector) → boolean
  decodeDidKey,           // (didKey) → Buffer (32-byte ed25519 public key)
  checkVector,            // (vector) → { ok: boolean, errors: string[] }
  loadVectors,            // () → Array<{ file, vector }>
} = require('./harness/run.js');
```

A third-party verifier implementation can be plugged in by replacing `verifySignature` with the implementation under test. A conformant implementation will pass `checkVector` for every committed vector.

## Adding new vectors

1. Add a fixture to `vectors/signatures/_generate.js`.
2. Run `node vectors/signatures/_generate.js` to regenerate the JSON file.
3. Run `node harness/run.js` to confirm the new vector passes.
4. Commit all changes together.

Vectors are deterministic: the generator produces byte-identical output for an unchanged fixture, so a regenerated diff against `main` flags any change to the canonicalisation rule, the keypair, or a fixture's signed material.

## What this harness does NOT cover

Appendix C.1, C.2, C.5, and C.6 are exercised. The remaining sections
are still to land as separate vector directories under `vectors/`:

- **C.3** discovery-document parsing (well-formed, malformed, forward-compatible).
- **C.4** recipient-value normalisation (NFKC, E.164, OIDC issuer+sub, DID canonical form).
