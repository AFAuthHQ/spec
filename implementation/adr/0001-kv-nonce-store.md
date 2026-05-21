# ADR-0001: Nonce store backed by Cloudflare KV

## Status
Accepted 2026-05-21.

## Context

Section 5.6 of the spec requires the verifier to detect replays via a nonce
store keyed by `(keyid, nonce)`. The store must survive across Worker
invocations (which run in transient isolates) and must accept one or more
writes per signed request. Cloudflare offers two state primitives the
runtime can talk to natively: **KV** (eventually consistent, TTL-aware,
inexpensive) and **Durable Objects** (strongly consistent, more code, more
billing surface, additional latency on every call via RPC).

## Decision

The reference Worker uses **Cloudflare KV** with TTL equal to
`(expires - created) + clockSkewSeconds`. The `NonceStore` interface in
`@afauth/server` is the abstraction boundary; a Durable-Object–backed
or Redis-backed implementation can be added later without an API change.

## Consequences

- **Positive.** Trivial to deploy; no Worker→DO RPC on the hot path; minimal
  billing footprint; KV's built-in TTL handles §5.6 expiry without a cron
  job.
- **Negative.** KV is eventually consistent. During the inconsistency window
  (typically tens of seconds globally), a replayed request that lands on a
  different edge may not see the original nonce write yet. The window is
  upper-bounded by the signature's own `expires` parameter — the protocol
  already accepts replays inside the signature lifetime as the threat-model
  bound, so the KV window is a strict subset of that surface.
- **Neutral.** The chosen interface (`seen(keyid, nonce, ttl) → was-new`)
  is small enough to wrap almost any KV-shaped store. The companion
  `RevocationList` (§8.3) shares the same KV namespace pattern with
  a different key prefix (`revoked:<did>` vs `nonce:<keyid>:<nonce>`),
  and does NOT use TTL — revoked entries are durable.

## Alternatives considered

- **Durable Objects.** Strongly consistent and the textbook answer for
  per-key serialisation, but ~10× the cost at expected request volumes and
  adds an RPC hop to every signed request. Reserved for a v0.2 option if
  consistency requirements tighten.
- **In-memory only.** Violates the spec's implicit requirement that the
  store survive process restarts; Worker isolate recycling alone would
  invalidate this.
- **Hosted Redis (Upstash, etc.).** Workable but adds a third-party
  dependency outside the Cloudflare runtime; not justified for the
  reference implementation.
