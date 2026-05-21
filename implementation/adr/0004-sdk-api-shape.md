# ADR-0004: SDK API shape — `AccountStore`, claim session, `signRequest`

## Status
Accepted 2026-05-21.

## Context

Three coupled API questions surfaced during the initial design sketch of
the SDK (the four `@afauth/*` packages in `AFAuthHQ/typescript-sdk`).
They share a common theme: how does the SDK express protocol-level
invariants in the type system, and where do we trade ergonomic
flexibility for safety?

1. **Storage atomicity.** The spec (§7.3, §7.4, §8.1, §8.4) makes
   atomicity normative for several state transitions, most notably the
   single-pending-invitation invariant. Should the SDK express storage
   via a generic `upsert(account)` (callsite-bound atomicity) or via
   named per-operation methods (interface-bound atomicity)?

2. **Claim-completion session asymmetry.** Four of the five endpoints
   are agent-signed; only `/claim/<token>` requires a human-authenticated
   session. Should `Server.handleClaimCompletion` take the session as an
   explicit parameter — making the asymmetry visible — or should the
   `Server` extract it via a callback, making all five handlers look the
   same?

3. **Low-level signing.** `Agent` exposes high-level builders for the
   protocol's endpoints. Should it also expose a low-level
   `signRequest(req, opts)` that lets callers build arbitrary signed
   requests? Power and forward-compatibility on one side; misuse and
   non-conformant signatures on the other.

## Decision

### (1) `AccountStore` is named atomic operations, not generic CRUD

```typescript
interface AccountStore {
  // reads
  get(did): Promise<Account | null>;
  findByPendingToken(token): Promise<Account | null>;
  // atomic mutations
  createUnclaimed(did): Promise<Account>;
  setPendingInvitation(did, recipient, token, expiresAt): Promise<Account>;
  completeClaimByToken(token, owner): Promise<Account | null>;
  rotateKey(oldDid, newDid, rotatedAt): Promise<Account>;
  revoke(did, revokedAt): Promise<Account>;
}
```

Each mutation method carries the atomicity contract of the spec section
it implements. The implementer chooses the storage primitives that
satisfy that contract; the caller cannot violate it by composing wrong.

The two read methods (`get`, `findByPendingToken`) are intentionally
separated from mutations: `findByPendingToken` exists so
`handleClaimCompletion` can apply the §7.7 match relation against
`pendingRecipient` before invoking the atomic commit. The atomicity
contract on `completeClaimByToken` is preserved — if the token is
consumed in the read-then-commit gap, the commit returns `null`.

### (2) `handleClaimCompletion(req, session)` — explicit at the handler, extractor at the Worker

`Server.handleClaimCompletion` takes an explicit `session: OwnerSession`
parameter. The Worker helper accepts a required `extractOwnerSession`
callback in `WorkerOptions` so the Worker's internal routing stays
uniform. The asymmetry — that one endpoint depends on human
authentication while the other four ride agent signatures — is
expressed at the API boundary where it matters, and abstracted at the
routing boundary where uniformity matters.

### (3) `Agent.signRequest` is public with spec-conformant defaults

`signRequest` remains on `Agent`. Defaults are chosen so the common
case requires no `opts`: `coveredComponents` derives from the request
shape (add `content-digest` when body is present); `expiresInSeconds`
defaults to 60; `nonce` defaults to 16 random bytes hex. Builders
(`buildOwnerInvitation`, `buildKeyRotation`, `buildAccountIntrospection`)
are the primary path; `signRequest` is the documented escape hatch.

## Consequences

- **Positive (1).** Caller code cannot break §7.3 atomicity. The set
  of mutations on the interface equals the set of mutations the protocol
  defines — the API is not larger than a thoughtful CRUD interface
  would have been, just better-typed.
- **Positive (2).** Every callsite of `handleClaimCompletion` is forced
  to express the human-auth dependency. The Worker layer absorbs the
  uniformity concern without erasing the asymmetry from the type system.
- **Positive (3).** Integrators can adopt v0.2 endpoints by calling
  `signRequest` directly while waiting for an SDK release with builders;
  the defaults eliminate the most common misuse (forgetting to include
  `content-digest` for a body-carrying request).
- **Negative (1).** Adding a new protocol mutation requires an interface
  change. This is intentional: new protocol mutations should pass
  deliberate review.
- **Negative (3).** A determined caller can construct a non-conformant
  signature. Mitigated by: the audience is sophisticated (agent authors,
  not end users); bad signatures fail verification loudly with §11 error
  codes; the defaults match the spec.
- **Neutral.** ADR-0004 documents these trade-offs so the
  implementation phase need not relitigate them.

## Alternatives considered

- **(1) Transactional callback** (`withPendingToken(fn)`): more flexible
  but maps poorly to Cloudflare KV, which lacks general transactions.
- **(1) Optimistic concurrency with version tokens.** Forces every
  backend to support a versioning model the protocol does not require.
- **(2) `Server`-level `extractOwnerSession` callback.** Hides the §7.4
  human-auth dependency one level too deep. Direct `Server` consumers
  (without the Worker helper) would lose the type-system reminder that
  the endpoint is different.
- **(3) `signRequest` only via `agent.advanced.signRequest`.** Relocates
  the surface without changing what can be expressed.
- **(3) Separate `LowLevelSigner` class.** Fragments the API for no
  protocol-level reason; the safety argument is already addressed by
  sane defaults.

## Addendum: M0–M4 review fixes

These extensions follow the same shape as (1)–(3) and were applied
during the M0–M4 review pass:

- **`ServerOptions.redirectAllowList`.** Enforces §7.2 ("MUST validate
  it against an allow-list of service-controlled hosts"). Fail-closed
  default — when no list is configured, any `redirect_url` in the
  request body produces `400 malformed_request`.
- **`ServerOptions.implicitSignup`.** Defaults true; set false to
  return `404 unknown_account` instead of creating on first touch.
  Surface for §11.3's "only when implicit signup is disabled" clause.
- **`deriveInvitationId(token)`.** Public `invitation_id` is
  `inv_` + base64url(sha256(token).slice(0, 12)), preventing the
  earlier (M2) bug where the id leaked the secret claim token.
- **`assertDiscoveryDocument(value)`.** §4.3 required-field
  validation + §4.5 algorithm-negotiation check (must advertise
  `ed25519`). Exposed so service-side code can use it without
  duplicating the rules.
- **`DiscoveryDocument` lives in `@afauth/core`** (re-exported from
  `@afauth/agent` and `@afauth/server`). Single source of truth.
- **`VerifierOptions.revocationList` defaults to a fresh
  `MemoryRevocationList`** with a one-time `console.warn`. §8.3
  requires a revocation list; the SDK no longer silently runs without
  one if the caller forgot to configure it.
