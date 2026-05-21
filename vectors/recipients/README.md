# Recipient-normalisation test vectors (Appendix C.4)

Each fixture exercises a single recipient value against the §7.7
normalisation rule for its type. Outcomes:

- **accept** — the canonical form is supplied; conformant
  implementations MUST produce it byte-for-byte.
- **reject** — the value is malformed per the type's rule.
  Conformant implementations MUST reject it.

## Coverage

| Type | Vectors | Tests |
|---|---|---|
| `email` (§7.7.1) | 5 | ASCII passthrough; case-fold of uppercase + mixed-case; NFKC of decomposed combining sequences; NFKC compatibility decomposition (`ﬁ` → `fi`). |
| `phone` (§7.7.2) | 5 | canonical E.164 passthrough; reject whitespace, dashes, `;ext=…` extensions, and national-format (missing `+`). |
| `oidc` (§7.7.3) | 4 | canonical passthrough; trailing slash IS significant (issuer is opaque); reject fragment and query in issuer. |
| `did` (§7.7.4) | 5 | did:key canonical passthrough; reject did:web with uppercase host; reject DID URL components (path, fragment, query). |

## Fixture shape

```jsonc
{
  "name":           "email-uppercase-lowercased",
  "description":    "…",
  "section":        "C.4",
  "recipient_type": "email",
  "input":          { "type": "email", "value": "ALICE@EXAMPLE.COM" },
  "expected": {
    "type":      "accept",
    "canonical": { "type": "email", "value": "alice@example.com" }
  }
}
```

For rejection:

```jsonc
{
  "expected": {
    "type":   "reject",
    "reason": "phone contains characters other than + and 0-9"
  }
}
```

`reason` is informational — implementations may produce different
error messages.

## Regenerating

```bash
node _generate.js
```

Deterministic.
