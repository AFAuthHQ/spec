# AFAuth Protocol — Core Specification

**Version:** 0.1 (working draft)
**Date:** 2026-05-18
**Status:** Working draft; comments welcome.

> The full v0.1 draft is currently published at <https://artidrop.ai/a/Y6NkkD6iHD> and will be migrated into this document. The sections below outline the structure; full content follows.

## 1 · Overview

AFAuth ("Agent-First Auth") is a protocol that lets AI agents sign up to internet services using a self-generated Ed25519 keypair, with optional human handoff via email-based claim.

## 2 · Identity layer

- Account ID format: `did:key:<multibase-multicodec-pubkey>` per the W3C did:key method.
- Algorithms: Ed25519 (mandatory), ECDSA-P256 (optional).
- Portability: a single key MAY be reused across services; per-service key derivation is permitted but not required.

## 3 · Service discovery

Every AFAuth-enabled service publishes a discovery document at `/.well-known/afauth`. See [`../schemas/well-known.json`](../schemas/well-known.json) for the JSON Schema.

## 4 · Request authentication

AFAuth uses HTTP Message Signatures (RFC 9421). Required signed components:

- `@method`
- `@target-uri`
- `@authority`
- `content-digest` (for requests with bodies, per RFC 9530)
- `afauth-account`
- `created`
- `nonce`

## 5 · Account creation

Two modes:

- **Implicit signup**: the first valid signed request from an unknown account DID auto-creates the account in state `UNCLAIMED`.
- **Explicit signup**: `POST /afauth/v1/accounts` with a signed body, returning a 201 with account state.

## 6 · Owner invitation & claim

Two-step verify:

1. Agent signs `POST /afauth/v1/accounts/me/owner-invitation` with `{ email }`. Server stores `pending_email`, state → `INVITED`, magic-link emailed.
2. Human authenticates via the magic-link URL; only then does `owner_email` become bound and state transitions to `CLAIMED`.

## 7 · Key rotation & revocation

- Pre-claim: rotation by signing with old key.
- Post-claim: rotation requires owner approval.

## 8 · State machine

```
∅ ──signup──► UNCLAIMED ──invite──► INVITED ──claim──► CLAIMED ──delete──► ARCHIVED
                  │                      │
                  └── 30d idle ─► EXPIRED ◄── 7d idle ──┘
```

## 9 · Billing declaration

Services declare their pre-claim billing policy in `/.well-known/afauth.billing.unclaimed_mode`:

- `free` — service absorbs unclaimed usage.
- `attested_only` — requires an accepted attestor (see §10).
- `denied` — paid features gated behind claim.

## 10 · Optional: agent attestation

The `AFAuth-Attestation` header carries a JWT signed by an accepted attestor (FIDO Agent Payments, Microsoft Entra Agent ID, Stripe Projects, Mastercard Verifiable Intent, or a service-operator HMAC). Services declare accepted attestors in `/.well-known/afauth.billing.accepted_attestors`.

---

*This document is a stub. The full v0.1 draft will be migrated here from the published report.*
