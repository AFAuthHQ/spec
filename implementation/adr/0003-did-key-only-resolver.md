# ADR-0003: `did:key`-only DID resolver in v0.1

## Status
Accepted 2026-05-21.

## Context

Section 3.1 of the spec lists two DID methods for v0.1: `did:key` and
`did:web`. Resolving a `did:key` is a pure CPU operation — decode the
multicodec varint, base58btc-decode the body, return the 32-byte Ed25519
public key. Resolving a `did:web` requires an HTTPS fetch to a
well-known URL on the DID's host, parsing a DID document, locating a
verification method, and validating it against the request. The two
operations have very different correctness and dependency profiles.

## Decision

The v0.1 SDK ships **only `did:key` resolution**, in-process, in
`@afauth/sdk/core`. The `Verifier` accepts a resolver hook so a
`did:web` implementation can be added in v0.2 without breaking the
verification API. The hook is a single function
`(did: Did) => Promise<Ed25519PublicKey>`; the built-in `did:key`
implementation is the default.

## Consequences

- **Positive.** The SDK has no outbound HTTP from the verification path
  in v0.1; cold-start cost stays low; the surface that needs hardening
  for security review is small (one decoder); no network-failure modes
  to design around.
- **Negative.** Services that want `did:web` identifiers in v0.1 must
  either wait for v0.2 or supply their own resolver via the hook —
  doable but unsupported.
- **Neutral.** Most v0.1 traffic is expected to be short-lived `did:key`
  agents anyway. `did:web` becomes meaningful when an identity needs to
  rotate keys without changing identifier, which is a long-lived account
  pattern more relevant to v0.2.

## Alternatives considered

- **Ship both `did:key` and `did:web` now.** Doubles the surface that
  needs hardening for v0.1 and introduces a network dependency on the
  verification hot path. Not justified for a reference implementation.
- **Ship a resolver registry only, with no built-in methods.** Punts
  implementation cost to every integrator. Strictly worse than picking
  the simpler method and shipping it.
