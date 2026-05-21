# ADR-0002: Raw Cloudflare Workers, no router framework

## Status
Accepted 2026-05-21.

## Context

The reference Worker handles five endpoints: discovery, owner-invitation,
claim-completion, key-rotation, account-introspection. A typical
Worker project of this size reaches for Hono or itty-router for routing,
parameter parsing, and middleware composition. The SDK is intended as a
foundation other implementations build on, so its runtime dependency tree
is effectively part of the public contract — every dependency the SDK
pulls in is one downstream consumers must also accept.

## Decision

The reference Worker uses **raw Cloudflare Workers** (`export default { fetch }`
shape) plus a small in-house router (target: ≤30 lines of router code).
No Hono, no itty-router, no Express-style middleware in the runtime
dependency tree of `@afauth/worker`.

## Consequences

- **Positive.** SDK bundle stays small; no third-party API to track or
  pin; debugging is more transparent (a stack trace points at AFAuth code,
  not framework internals); no risk of framework choices leaking into the
  protocol surface.
- **Negative.** Contributors familiar with Hono need to learn the routing
  convention; certain ergonomic patterns (typed params, middleware chains)
  are hand-written. The router is small enough that this is a one-time cost.
- **Neutral.** Downstream services that prefer Hono can wrap the SDK's
  `Server` class in their own Hono routes with a few lines of glue. The
  decision is about what the SDK ships, not what consumers must use.

## Alternatives considered

- **Hono.** Idiomatic for Workers and pleasant to use, but adds ~10 KB
  minified and a moving API surface for features AFAuth does not need.
- **itty-router.** Smaller than Hono but still a third-party dependency
  with its own release cadence; not enough win over a 30-line in-house
  router to justify.
