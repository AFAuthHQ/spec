# ADR-0003: DID resolver shape for v0.1

## Status
Accepted 2026-05-21. **Amended 2026-05-21** to ship `did:web` in v0.1 alongside `did:key`; original "did:key only" decision superseded.

## Context

Section 3.1 of the spec lists two DID methods for v0.1: `did:key` and
`did:web`. Resolving a `did:key` is a pure CPU operation — decode the
multicodec varint, base58btc-decode the body, return the 32-byte Ed25519
public key. Resolving a `did:web` requires an HTTPS fetch to a
well-known URL on the DID's host, parsing a DID document, locating a
verification method, and validating it against the request. The two
operations have very different correctness and dependency profiles.

## Decision

**Original (initial v0.1 milestones M0-M4):** ship only `did:key`
resolution, in-process, in `@afauthhq/core`, with a resolver hook on
`Verifier` so additional methods can be added without breaking the API.

**Amended (v0.1 beta hardening pass):** ship both `did:key` AND
`did:web` in v0.1. The shape is unchanged — `Verifier` still accepts an
optional `didResolver`; the default is still `DidKeyResolver` for
backward compatibility — but `DidWebResolver` is now a first-class
shipped component in `@afauthhq/server`, and `CompositeDidResolver` in
`@afauthhq/core` routes by method.

The amendment lands because:

1. **`did:web` is part of the spec's v0.1 surface (§3.1.2).** Withholding
   it from the SDK forced every operator with a stable identity to
   write their own resolver, which is exactly the kind of work an SDK
   should absorb.
2. **The "long-lived account" use case arrived sooner than expected.**
   The §8 key-rotation flow is more useful with `did:web` than `did:key`
   (rotation without identifier change); shipping rotation without
   `did:web` was leaving the more durable account model unsupported.
3. **The original "doubles the surface that needs hardening" concern
   landed cheaper than feared.** `DidWebResolver` is one self-contained
   ~300-line component with a tight test surface — TLS-only, schema
   validation, positive+negative caching, pluggable fetch.

## Consequences

After the amendment:

- **Positive.** Both v0.1 DID methods are now SDK-supplied. Services
  with stable `did:web` identities can adopt AFAuth without rolling
  their own resolver. The verifier path picks up no extra cost for
  `did:key` traffic (the default resolver is still pure-CPU); `did:web`
  callers opt in by passing `CompositeDidResolver({ key: …, web: … })`.
- **Negative.** `did:web` adds a network dependency on the verification
  hot path for services that enable it — the resolver's positive
  cache (default 5 min) bounds the cost but doesn't eliminate it.
  Operators should size cache TTL per §3.1.2 (RECOMMENDED ≤ 1 hour).
- **Neutral.** The `Verifier`'s API is unchanged. Existing services
  that didn't pass `didResolver` get the same behaviour as before.

## Alternatives considered

- **Ship both `did:key` and `did:web` now.** Doubles the surface that
  needs hardening for v0.1 and introduces a network dependency on the
  verification hot path. Not justified for a reference implementation.
- **Ship a resolver registry only, with no built-in methods.** Punts
  implementation cost to every integrator. Strictly worse than picking
  the simpler method and shipping it.
