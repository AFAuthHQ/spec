# Discovery-document test vectors (Appendix C.3)

Each fixture carries one candidate `/.well-known/afauth` document and
the expected parse outcome. Categories:

- **Well-formed (accept)** — minimal, with each optional field
  individually, and the complete shape.
- **Forward-compatible (accept)** — documents containing unknown
  top-level fields or unknown keys inside `endpoints`. §4.2 requires
  these to be treated as opaque.
- **Malformed (reject)** — missing required fields, wrong
  `afauth_version`, `signature_algorithms` that does not include
  `ed25519`. §4.5 makes `ed25519` mandatory for v0.1.

## Fixture shape

```jsonc
{
  "name":        "well-formed-minimal",
  "description": "…",
  "section":     "C.3",
  "document":    { /* the candidate document */ },
  "expected":    { "type": "accept" }
                  // or
                  // { "type": "reject", "reason": "<informational>" }
}
```

`reason` on reject fixtures is informational — implementations may
produce different error messages, but the wire outcome (parse
accepts or rejects) MUST match.

## Regenerating

```bash
node _generate.js
```

Deterministic: same metadata → byte-identical JSON output.
