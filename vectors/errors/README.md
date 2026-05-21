# Error-envelope test vectors (Appendix C.5)

One JSON fixture per reserved error code in §11.3, documenting:

- the canonical envelope shape per §11.1 (`{ "error": { "code": ..., "message": ... } }`)
- the HTTP status the §11.2 table maps the code to
- the spec sections that produce / define the code
- a representative human-readable `message`

`message` is informational — implementations are free to vary the
exact string. The wire-level invariants are: `error.code` matches the
fixture's `code`, `error` contains no unknown required fields, and the
HTTP status matches the fixture's `http_status`.

## Regenerating

```bash
node _generate.js
```

The script is deterministic; the JSON output is byte-identical
unless the metadata table inside the generator is edited.

## Coverage

All 17 codes reserved by §11.3:

| Code | HTTP | Section |
|---|---|---|
| `invalid_signature` | 401 | §5.5 |
| `expired_signature` | 401 | §5.6 |
| `replayed_nonce` | 401 | §5.6 |
| `unknown_account` | 404 | §6.5 |
| `revoked_key` | 401 | §8.3 |
| `invalid_attestation` | 401 | §10 |
| `attestation_required` | 401 | §10 |
| `invitation_expired` | 410 | §7.3 |
| `invitation_not_found` | 410 | §7.4 |
| `already_claimed` | 409 | §7.2 |
| `not_claimed` | 409 | (general) |
| `owner_authentication_required` | 403 | §7.4, §7.5, §8.2 |
| `owner_binding_blocked` | 403 | §7.5 |
| `account_expired` | 410 | §6.1 |
| `rate_limit_exceeded` | 429 | §11.2 |
| `malformed_request` | 400 | (general) |
| `unsupported_recipient_type` | 400 | §4.4, §7.2 |

Not every code is reachable in every v0.1 SDK build (e.g.,
attestation codes require optional §10 attestation support). The
vectors are normative for envelope shape regardless of which codes a
particular implementation emits.
