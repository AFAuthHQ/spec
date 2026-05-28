# Trust attestation vectors (AFAP-0006 §10.4, §10.5)

Each `*.json` file in this directory is a single test vector exercising verification of an `afauth-trust` attestation JWT (§10). Vectors are signed by a fixed EdDSA test keypair (derived deterministically in `_generate.js`) and carry deterministic claims so that conforming verifiers produce byte-identical accept/reject decisions on each run.

## File shape

```jsonc
{
  "name":            "<unique-kebab-case-name>",
  "description":     "<one-paragraph human-readable summary>",
  "section":         "<spec section reference>",
  "jwt":             "<encoded JWS, three base64url-joined parts>",
  "header_decoded":  { "alg": "EdDSA", "typ": "JWT", "kid": "..." },
  "payload_decoded": {
    "iss": "afauth-trust",
    "sub": "did:key:...",
    "sub_h": "<base64url, 43 chars>" | undefined,
    "aud": "did:web:svc.example",
    "verification": "email" | "oauth" | "payment" | undefined,
    "iat": <unix-seconds>,
    "exp": <unix-seconds>
  },
  "jwks": { "keys": [ /* one EdDSA key, kid pinned */ ] },
  "verification_inputs": {
    /* The values a verifier MUST supply to reproduce the expected outcome */
    "expected_aud": "did:web:svc.example",
    "expected_agent_did": "did:key:..."
  },
  "expected": {
    "accept": true | false,
    /* When accept=false, the conforming code per §11.3 */
    "error_code": "invalid_attestation" | null
  }
}
```

## Time

All vectors use `iat = 1715000000` (2024-05-06T15:33:20Z) and `exp = iat + 900` (the §10.3.1 ceiling). A verifier evaluating these vectors MUST treat the "current time" as a value within `[iat, exp)` — typically `iat + 10`. Verifiers that pull wall-clock time MUST be configurable for tests.

## Pseudonym key

For vectors that carry `sub_h`, the value is computed per §10.4.3 with the deterministic key:

```
K_pseudonym = sha256("afauth-trust-vectors-pseudonym-key-v1")
```

This is published in plain so vector consumers can recompute and confirm `sub_h` matches. **Test only — never use this key in production.**

## Regenerating

Vectors are deterministic. To regenerate after a fixture change:

```bash
node _generate.js
```

Re-run after editing this directory's spec coverage or after the §10.4 / §10.5 normative rules change.

## Scope

These vectors cover the JWT-shape and verification rules in §10.4. They do not exercise the agent–principal uniqueness rule in §10.5, which is enforced at the attestor's binding layer (out of the JWT verifier's reach). Implementations should test §10.5 against their attestor of choice; the trust attestor reference impl ships its own integration tests at `trust/test/link-flow.test.ts`.

## Harness

The harness in `../../harness/run.js` does not yet consume these vectors — it focuses on signed-request verification per §5. Adding attestation coverage is tracked separately.
