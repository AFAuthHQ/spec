# Replay-window test vectors (Appendix C.6)

Sequence vectors for the §5.6 replay window. Each fixture extends the
shape of a §C.1/§C.2 signature vector with two additional fields:

- `verifier_now_unix_seconds`: the value the verifier should treat as
  "now" while evaluating this vector. Lets the same signed request
  describe both an accepted and a rejected scenario (deterministic).
- `expected_outcome`: either `{ "type": "accept" }` or
  `{ "type": "reject", "code": "<§11.3 code>", "status": <int> }`.

A small number of vectors also carry:

- `replay_behaviour`: prose describing the behaviour the verifier
  MUST exhibit when the same vector is replayed (re-verified) on the
  same nonce store.
- `extra_setup`: harness instructions for vectors that depend on
  prior state (e.g., the cross-keyid nonce-reuse case primes the
  nonce store under a different keyid before verification).

## Coverage

| Vector | Outcome | Tests |
|---|---|---|
| `expired-signature` | reject `expired_signature` (401) | `expires` is well in the past relative to `verifier_now` |
| `future-dated-signature` | reject `invalid_signature` (401) | `created` is well in the future relative to `verifier_now` (beyond clock skew) |
| `fresh-signature-accepted` | accept | positive control; also documents the replay invariant — a second verification of the same vector MUST yield `replayed_nonce` (401) |
| `cross-keyid-nonce-reuse` | accept | a nonce that was used under a different `keyid` is still fresh under this keyid; §5.6 scopes uniqueness to (keyid, nonce) |

## Regenerating

```bash
node _generate.js
```

Deterministic: same inputs produce byte-identical output. Reviewers
should run the script and confirm the committed JSON files match.

## How the harness uses these

For `expect.type === "reject"` vectors, the harness calls the
verifier with `now` forced to `verifier_now_unix_seconds` and asserts
the verifier throws an error whose `code` and HTTP status match
`expected_outcome`.

For `expect.type === "accept"` vectors, the harness asserts the
verifier completes successfully. For `fresh-signature-accepted`, the
harness additionally re-verifies on the same nonce store and asserts
the second verification rejects with `replayed_nonce`.

For `cross-keyid-nonce-reuse`, the harness first calls
`nonceStore.seen(extra_setup.other_keyid, nonce, …)` to prime the
store before verifying the vector itself.
