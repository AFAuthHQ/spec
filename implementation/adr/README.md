# Architecture Decision Records

Each ADR captures one decision made about the AFAuth v0.1 reference
implementation. ADRs are immutable once accepted; a decision that changes
is recorded as a new ADR that supersedes the old one, with both files
updated to reflect the supersession.

## Index

| # | Title | Status |
|---|---|---|
| [0001](0001-kv-nonce-store.md) | Nonce store backed by Cloudflare KV | Accepted |
| [0002](0002-raw-workers-no-framework.md) | Raw Cloudflare Workers, no router framework | Accepted |
| [0003](0003-did-key-only-resolver.md) | `did:key`-only DID resolver in v0.1 | Accepted |
| [0004](0004-sdk-api-shape.md) | SDK API shape: account store, claim session, signRequest | Accepted |
| [0005](0005-e2e-interop-harness.md) | End-to-end interop harness location and contract | Accepted |

## Template

```markdown
# ADR-NNNN: <Title>

## Status
Accepted YYYY-MM-DD.

## Context
What forced this decision? Why now?

## Decision
What we chose, stated as the rule.

## Consequences
- Positive: …
- Negative: …
- Neutral: …

## Alternatives considered
- <Option> — rejected because …
```
