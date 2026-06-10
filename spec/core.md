# AFAuth Protocol — Core Specification

**Version:** 0.1
**Date:** 2026-05-18
**Status:** Stable; comments and proposals welcome.
**Editors:** AFAuth contributors
**License:** [CC-BY 4.0](../LICENSE)

## Abstract

AFAuth ("Agent-First Auth") is an open protocol that lets AI agents sign up to internet services using a self-generated Ed25519 keypair, operate those accounts autonomously, and optionally hand ownership to a human at any later point. It is designed so that agents are first-class principals from the start, with human ownership as an optional handoff rather than a precondition.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Conventions](#2-conventions)
3. [Identity](#3-identity)
4. [Service Discovery](#4-service-discovery)
5. [Request Authentication](#5-request-authentication)
6. [Account Lifecycle](#6-account-lifecycle)
7. [Owner Invitation and Claim](#7-owner-invitation-and-claim)
8. [Key Management](#8-key-management)
9. [Billing Declaration](#9-billing-declaration)
10. [Optional: Agent Attestation](#10-optional-agent-attestation)
11. [Error Responses](#11-error-responses)
12. [Security Considerations](#12-security-considerations)
13. [Privacy Considerations](#13-privacy-considerations)
14. [IANA Considerations](#14-iana-considerations)
15. [References](#15-references)
- [Appendix A: State Machine](#appendix-a-state-machine)
- [Appendix B: Worked Examples](#appendix-b-worked-examples)
- [Appendix C: Test Vectors](#appendix-c-test-vectors)
- [Appendix D: Design Rationale](#appendix-d-design-rationale)
- [Appendix E: Edge Verification Pattern](#appendix-e-edge-verification-pattern)

---

## 1. Introduction

### 1.1 Motivation

Today, AI agents reach internet services in one of two ways: (a) by impersonating a human (browser automation against signup forms), or (b) by being delegated scope from a pre-existing human account (OAuth-based delegation). Both approaches assume that a human user is the root of trust.

AFAuth takes the opposite stance. An agent signs up on its own behalf, identified by a cryptographic keypair it controls. If a human ever wants ownership of the account, the agent invites them; the binding only takes effect once the human authenticates from the invited email. The agent continues to operate the account afterwards, but ownership-changing operations become privileged to the human.

This design serves several use cases:

- Long-running autonomous agents that need persistent state on third-party services.
- Agent-to-service interactions where no human is yet involved.
- Delegation flows where a human may *eventually* claim an account but is not present at creation.
- Services that want to support agent-first commerce without requiring upfront human registration.

### 1.2 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals.

In addition, this specification uses the following terms:

- **Account**: A persistent identity on an AFAuth-enabled service, owned by a cryptographic keypair.
- **Agent**: A software process that holds a private key and interacts with services on its own behalf or on behalf of a human.
- **Service**: An HTTP(S) endpoint that implements this specification.
- **Verifier**: The component that performs the verification steps in §5.5 (signature parsing, key resolution, signature verification, timestamp and nonce checks). The verifier MAY be co-located with the service (in-application) or MAY run as a separate component on the request path — for example, an API gateway, edge proxy, or service-mesh sidecar. Where this specification uses "the verifier" it refers to whichever component performs §5.5; where it uses "the service" it refers to the component that defines and enforces account-level policy, including the §7.5 owner-binding floor.
- **Owner**: A human (or other principal authenticated via email) bound to an account through the claim flow.
- **Account DID**: The W3C Decentralized Identifier ([W3C-DID-CORE]) that names an account, using the `did:key` method ([W3C-DID-KEY]).
- **Claim**: The act of binding an account to an owner through the two-step invitation/verification flow defined in Section 7.
- **Attestor**: An external system that vouches for the runtime context of an agent (e.g. FIDO Agent Payments Protocol, Microsoft Entra Agent ID).
- **Pre-claim**: Account state where no owner is yet bound.
- **Post-claim**: Account state where an owner has been bound through the claim flow.

### 1.3 Scope

This specification defines:

- The identity format used to name accounts.
- A discovery document that services MUST publish.
- A request-authentication scheme based on HTTP Message Signatures [RFC9421].
- Endpoints for account creation, owner invitation, claim completion, and key management.
- A state machine describing the account lifecycle.
- Optional mechanisms for agent attestation.

This specification does NOT define:

- Service-internal data models, billing systems, or business logic.
- The user interface presented during the claim flow.
- The mechanism by which agents discover services in the first place (out of scope).
- Inter-agent communication or delegation (covered by other protocols such as Google A2A).
- What operations an agent may perform at any given account state (see §7.5 and §12.7).

### 1.4 Relationship to other standards

AFAuth is one of several converging standards for AI-agent interaction with services. It addresses agent identity, which is currently the gap in this stack; it composes with rather than replaces the capability and authorization layers around it.

| Layer | Examples | AFAuth's role |
|---|---|---|
| Capability / transport | Model Context Protocol (MCP), Agent2Agent (A2A) | The AFAuth account DID can be carried in MCP's Client ID Metadata Document (CIMD) URL and in A2A Agent Card identity fields. |
| Authorization | OAuth 2.0 `actor_token` (`draft-oauth-ai-agents-on-behalf-of-user`), OIDC for AI Agents, FIDO Agent Payments Protocol (AP2), Visa Trusted Agent Protocol, Mastercard Verifiable Intent | An AFAuth-signed assertion serves as the `actor_token` for OAuth-style delegation flows and as the cryptographic identity inside payment-authorization tokens. |
| **Identity** | **AFAuth** | Provides a self-sovereign agent identity for the open web. |

Prior art in self-issued account identity informs the design but is not directly imported: AT Protocol uses email-confirmed account creation rather than agent-first; Nostr's experience with self-issued keys highlights the importance of planned-for key rotation. Microsoft Entra Agent ID provides agent identity for managed enterprise environments and may serve as an attestor (see §10) for AFAuth accounts that need to vouch for an enterprise runtime context.

The protocol does not require integration with any specific external standard; the relationships listed above are interoperability paths that conforming implementations MAY follow.

---

## 2. Conventions

### 2.1 Notation

This specification uses ABNF [RFC5234] for protocol syntax and JSON [RFC8259] for data structures. JSON examples are shown with whitespace for readability; implementations MUST NOT depend on whitespace in canonical comparisons.

HTTP examples follow [RFC9110]. Examples omit standard headers (Date, Host, etc.) for brevity unless they are protocol-relevant.

### 2.2 Cryptographic algorithms

Conforming implementations MUST support Ed25519 [RFC8032]. Implementations MAY support ECDSA on P-256 [RFC6979] in addition. Future versions may add additional algorithms; agents and services MUST negotiate via the discovery document (Section 4).

All cryptographic operations MUST use constant-time implementations to avoid side-channel attacks.

---

## 3. Identity

### 3.1 Account identifiers

An AFAuth account is identified by a Decentralized Identifier ([W3C-DID-CORE]) using the `did:key` method ([W3C-DID-KEY]). Conforming services MUST accept `did:key` account identifiers. AFAuth defines no other agent account method in v0.1: agents typically run on user machines behind home routers, with no stable web origin at which to host a DID document, so a DNS-anchored method is not a usable agent identity. (`did:web` still appears in this specification for a *service's* own identity (§4.3) and for owner recipients (§7.7.4) — neither is the agent's account key.)

#### 3.1.1 did:key

A `did:key` identifier encodes the account's public key directly:

```
did:key:<multibase-multicodec-pubkey>
```

For Ed25519 keys, the encoded form is the multicodec prefix for Ed25519 (registered varint `0xed01`) followed by the 32-byte raw public key, encoded as a multibase base58btc string. Example:

```
did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr
```

The account DID is derived entirely from the public key. Services MUST validate it locally by decoding the multibase string and using the recovered public key for signature verification; they MUST NOT require any central registry lookup.

Implementations MUST validate the canonical form of a `did:key` identifier:

- The multicodec prefix MUST be decoded as an unsigned varint, not compared byte-wise. The Ed25519 codec value is `0xed`; its varint encoding is the two-byte sequence `0xed 0x01`. Implementations that byte-compare against `0xed01` without performing varint decoding will reject some valid encodings and may accept malformed ones; see [did-key-issue-35].
- Implementations MUST reject any multibase string that does not round-trip to its canonical encoding. Base58btc has no built-in length check and admits non-canonical encodings (e.g., leading-zero padding); accepting non-canonical forms permits two distinct strings to resolve to the same public key, which breaks equality-based account lookup.
- Implementations MUST reject any payload whose length after the codec prefix is not exactly 32 bytes for Ed25519.

`did:key` has no rotation or revocation mechanism within the DID method itself: rotating the verification key necessarily changes the account identifier (see §8.1). Recovery from a lost or compromised key is therefore owner-driven (revoke + re-key, §8.2/§8.4), not a property of a stable identifier.

#### 3.1.2 Future methods

Future versions of this specification may add support for additional DID methods (e.g., `did:plc`) that provide stable account identity with rotatable verification keys without depending on DNS. See Appendix D for design rationale.

### 3.2 Key generation

Agents SHOULD generate Ed25519 keypairs using a cryptographically secure pseudorandom number generator. Private keys MUST NOT be transmitted to services; only signatures derived from them.

Implementations are RECOMMENDED to store private keys in OS-level keystores, hardware-backed keystores (TPM, Secure Enclave), or cloud KMS where available. File-based key storage SHOULD use file mode 0600.

### 3.3 Portability and derivation

By default, agents SHOULD derive a per-service signing key using a deterministic key-derivation function such as HKDF [RFC5869] over a master key, with the service's DID as the `info` parameter. This produces a distinct account identifier per service and prevents cross-service correlation of an agent's activity. From the service's point of view, the request is signed by an unrelated Ed25519 keypair; the derivation is invisible.

Agents that explicitly require a single portable identifier across services MAY reuse the same key (and therefore the same account identifier) across services. Conforming services MUST accept both modes; from the service's point of view, derived and portable identifiers are indistinguishable.

Per-service derivation is the recommended default for new agent implementations. The prior default of portable identifiers is preserved as an opt-out for operators that depend on cross-service identity continuity (for example, agents that interact with multiple services that share an out-of-band trust relationship in the agent).

---

## 4. Service Discovery

### 4.1 The `/.well-known/afauth` document

Every AFAuth-enabled service MUST publish a JSON document at the well-known URI `/.well-known/afauth` per [RFC8615]. The document MUST be served with status `200 OK` and `Content-Type: application/json`, and SHOULD include appropriate `Cache-Control` directives.

A discovery request:

```http
GET /.well-known/afauth HTTP/1.1
Host: api.example.com
Accept: application/json
```

A discovery response:

```json
{
  "afauth_version": "0.1",
  "service_did": "did:web:api.example.com",
  "endpoints": {
    "accounts":         "/afauth/v1/accounts",
    "owner_invitation": "/afauth/v1/accounts/me/owner-invitation",
    "claim_page":       "https://claim.example.com",
    "claim_completion": "/afauth/v1/claim",
    "key_rotation":     "/afauth/v1/accounts/me/keys/rotate"
  },
  "signature_algorithms": ["ed25519"],
  "features": ["attestation", "key_rotation"],
  "recipient_types": ["email", "oidc"],
  "limits": {
    "unclaimed_ttl_seconds":         2592000,
    "unclaimed_rate_limit_per_hour": 100
  },
  "billing": {
    "unclaimed_mode": "free",
    "accepted_attestors": ["stripe-projects", "microsoft-entra-agent-id"]
  }
}
```

### 4.2 Schema

The full JSON Schema is provided alongside this specification at [`../schemas/well-known.json`](../schemas/well-known.json). Implementations MUST treat unknown fields as opaque (forward-compatibility).

### 4.3 Required fields

- `afauth_version` (string): The protocol version this service speaks. For this specification, the value is `"0.1"`.
- `service_did` (string): A DID identifying the service. Implementations SHOULD use `did:web:<host>` so the service's identity is anchored in DNS and TLS rather than in a self-issued public key. `did:key:...` is permitted but provides no authority anchor — a hostile party that controls the connection on which the discovery document is fetched can claim any `did:key` value — and is appropriate only for niche service-to-service contexts. See §12.8 for the related threat model.
- `endpoints` (object): URLs for the protocol's endpoints. Paths MAY be absolute or relative to the discovery document's origin. Members defined in this version: `accounts`, `owner_invitation`, `claim_page`, `claim_completion`, `key_rotation`, `key_rekey` (§8.2 owner-initiated re-key), `key_revocation` (§8.4 owner revoke). The token is appended as the final path segment of `claim_completion` (see §7.4).
- `signature_algorithms` (array of strings): Algorithms the service accepts. MUST include `"ed25519"` for conformance.

### 4.4 Optional fields

- `features` (array of strings): Optional features the service supports. Defined values: `"attestation"`, `"key_rotation"`, `"attested_session"`. `"attested_session"` indicates the service maintains attested sessions with periodic re-presentation (§10.7) rather than gating attestation only at signup. Absent features MUST NOT be assumed supported. Two-step invite is normatively required for v0.1 conformance (§7.1) and is not an advertisable feature.
- `recipient_types` (array of strings): Recipient types the service accepts on the owner-invitation endpoint (§7.2, §7.7). Defined values for v0.1 are `"email"`, `"phone"`, `"oidc"`, and `"did"`. Conforming services MUST accept `"email"` and SHOULD include it in the declared list. If `recipient_types` is absent, agents MUST assume `["email"]`.
- `limits` (object): Service-declared limits. Defined members: `unclaimed_ttl_seconds`, `unclaimed_rate_limit_per_hour`.
  - `unclaimed_ttl_seconds` (integer): Optional. The maximum age, in seconds, an account may remain unclaimed before it transitions to `EXPIRED` (§6.1). **Absent — the default and RECOMMENDED posture — means unclaimed accounts never expire**: an agent MAY operate its account indefinitely, and a human claim is a one-way upgrade rather than a precondition for continued operation. Services SHOULD NOT set this field. It exists only for the narrow cases where garbage-collecting abandoned accounts or honouring a data-retention mandate genuinely requires expiry; setting it on the reflex that "inactive accounts should be reaped" is a category error, because an AFAuth account is bound to a key its agent holds, not to a human who may have wandered off. When the field is present, the service computes each account's deadline as `created_at + unclaimed_ttl_seconds` and surfaces it as `unclaimed_expires_at` in signup and introspection responses (§6.4, §6.5); when absent, `unclaimed_expires_at` is omitted.
- `billing` (object): Pre-claim billing declaration. See Section 9.

### 4.5 Discovery procedure

Before signup, agents SHOULD fetch and cache the discovery document. Agents MUST honor the `signature_algorithms` advertised; MUST honor the `billing.unclaimed_mode`; SHOULD respect the rate-limit hints in `limits`; and MUST choose a recipient type from `recipient_types` when invoking the owner-invitation endpoint (§7.2).

---

## 5. Request Authentication

### 5.1 HTTP Message Signatures

AFAuth uses HTTP Message Signatures [RFC9421] for all authenticated requests. This avoids inventing a custom signature format and leverages tooling already common in modern systems.

Implementations MUST support the `ed25519` signature algorithm as defined by RFC 9421.

### 5.2 Required signed components and parameters

Every AFAuth-authenticated request MUST include the following in its `Signature-Input` header.

**Covered components** (the message elements being signed):

| Component | Required when | Purpose |
|---|---|---|
| `@method` | Always | HTTP method |
| `@target-uri` | Always | Full request URI; subsumes the authority for cross-service replay binding |
| `content-digest` | Request body is non-empty | SHA-256 of the body, per [RFC9530] |

**Signature parameters** (per RFC 9421 §2.3):

| Parameter | Required | Purpose |
|---|---|---|
| `created` | Yes | Signing timestamp |
| `expires` | Yes | Hard expiration timestamp for the signature |
| `nonce` | Yes | Unique value to prevent replay |
| `keyid` | Yes | The account's DID — the sole identity surface |
| `alg` | Yes | Signature algorithm (e.g., `ed25519`) |

`expires` MUST be no more than 300 seconds after `created`. The signature input string MUST be constructed per the canonicalisation rules of RFC 9421.

Earlier drafts of this specification required signing an `@authority` derived component and an `AFAuth-Account` header. Both have been removed: `@target-uri` subsumes the authority for replay binding, and `keyid` is the sole identity surface to avoid the split-brain failure mode described in RFC 9421 §7.3.4. Implementations MUST NOT require either.

### 5.3 Headers

This specification introduces or relies on the following HTTP headers:

- `AFAuth-Attestation` (introduced, optional): Carries an attestation token, as defined in Section 10.
- `Content-Digest`: As defined by [RFC9530]. Required for requests with a non-empty body; MUST be omitted otherwise.
- `Signature-Input`, `Signature`: As defined by [RFC9421]. The account's DID is carried in the `keyid` signature parameter (see §5.2); no separate identity header is defined.
- `WWW-Authenticate` (response): On a `401 Unauthorized`, the responder returns an AFAuth authentication challenge as defined in §5.7. The headers above travel on the request; this one travels on the response.

### 5.4 Example

```http
POST /afauth/v1/accounts/me/owner-invitation HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig1=("@method" "@target-uri" "content-digest");\
                 created=1715000000;expires=1715000060;\
                 nonce="9f8b3a7c1d2e4f56";\
                 keyid="did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr";\
                 alg="ed25519"
Signature: sig1=:0123abcde...:

{"recipient":{"type":"email","value":"alice@example.com"}}
```

### 5.5 Verification procedure

On receiving a signed request, the verifier MUST:

1. Parse the `Signature-Input` header and verify that all required covered components and signature parameters (Section 5.2) are present.
2. Construct the canonical signature input string per RFC 9421.
3. Resolve the account's public key from the `keyid` value by decoding the multibase-multicodec representation for `did:key` (per §3.1.1). No network fetch or registry lookup is required.
4. Verify the signature using the algorithm declared in `alg`.
5. Verify that the current time is between `created` and `expires` inclusive, with a tolerance for clock skew (RECOMMENDED: ±60 seconds).
6. Verify that the `nonce` has not been seen before for this `keyid` within the storage window (see §5.6).
7. If the request has a non-empty body, verify the `Content-Digest` header matches a SHA-256 hash of the actual body. If the request has no body, the `Content-Digest` header MUST NOT be present.

If any step fails, the verifier MUST cause a `401 Unauthorized` response with an error body (Section 11) indicating the failure reason, and the response SHOULD include a `WWW-Authenticate` challenge (§5.7). The verifier MAY produce this response directly (when it is on the request path), or signal the failure to the service that produces the response.

### 5.6 Replay protection

The verifier MUST maintain a set of seen `(keyid, nonce)` tuples covering at least the duration of the freshness window. The storage window MUST be at least `expires - created + skew_tolerance`. Implementations commonly use a time-bounded set such as Redis with `SETNX … EX`. When the verifier is shared across multiple instances — for example, in a clustered gateway — this set MUST be shared across those instances; a per-instance cache is insufficient to defend against cross-instance replay within the freshness window.

Replay defense is scoped to `keyid` (the cryptographic origin) rather than to the account identifier; this preserves correct replay detection across key rotation (§8), where a single account identifier may be presented under successive verification keys.

Services MAY accept signed requests outside the freshness window for non-mutating `GET` operations, at their discretion, but MUST NOT accept replayed mutating requests.

### 5.7 Authentication challenge (`WWW-Authenticate`)

A response that rejects a request for an authentication-related reason — any `401 Unauthorized` defined by this specification (§5.5, §8.3, §8.4, §9.2, §10.7) — SHOULD include a `WWW-Authenticate` header field carrying an AFAuth challenge, in addition to the error body of Section 11. The challenge lets an agent that has not yet authenticated, or whose authentication was rejected, discover how to recover without out-of-band knowledge of the service.

The challenge uses the `auth-scheme` token `AFAuth` with the `auth-param` syntax of [RFC9110] §11:

```http
WWW-Authenticate: AFAuth discovery="https://api.example.com/.well-known/afauth", error="attestation_required", attestors="afauth-trust"
```

AFAuth message signatures (Section 5) are the authentication mechanism; the `AFAuth` scheme token names that mechanism for the purposes of [RFC9110] and is not a credential-bearing scheme — no `Authorization: AFAuth …` request header is defined, as credentials travel in `Signature` / `Signature-Input` (§5.3).

The following `auth-param`s are defined. A responder MUST quote any value that is not a valid [RFC9110] `token` (URLs and space-delimited lists MUST be quoted). Consumers MUST ignore `auth-param`s they do not recognize.

- `discovery` (RECOMMENDED whenever the challenge is emitted): the absolute URL of the service's `/.well-known/afauth` document (Section 4). This is the bootstrap pointer — an agent with no prior knowledge of the service fetches it to learn `service_did`, `signature_algorithms`, `endpoints`, and billing/attestor policy. The challenge carries a pointer, not a copy; the discovery document remains the single source of truth.
- `error` (OPTIONAL): the reserved error code (§11.3) describing the failure, mirroring `error.code` in the body, so an agent can branch its recovery from the header alone. A responder MUST set `error` only when the request actually attempted AFAuth — that is, it carried a `Signature` / `Signature-Input` (§5) or an `AFAuth-Attestation` (§10). A `401` produced for a request that did not attempt AFAuth (a client using another scheme, or none) MUST NOT carry `error="invalid_signature"`; such a challenge, if emitted at all, is a bare *advertisement* — the scheme token with at most `discovery` — saying only "AFAuth is available here." This keeps AFAuth from stamping a failed-attempt signal onto a rejection it did not cause.
- `attestors` (OPTIONAL; RECOMMENDED when `error` is `attestation_required` or `invalid_attestation`): a space-delimited list of accepted attestor identifiers (§10.3), equivalent to `billing.accepted_attestors` (§4.4, Section 9). It tells the agent which attestor(s) can satisfy the requirement without a discovery round-trip.
- `owner_login` (OPTIONAL; permitted when `error` is `owner_authentication_required`): an absolute URL a human owner can visit to authenticate (typically `endpoints.claim_page` or a service login page). The agent surfaces this to its owner; the agent cannot itself satisfy an owner-authentication requirement (§7.5).
- `realm` (OPTIONAL): an [RFC9110] realm. When present its value SHOULD be the service's `service_did`, letting an agent identify the expected verifier and derive its per-service key (§3.3) before fetching discovery.

Emitting the challenge is a `SHOULD`, not a `MUST`, so that services predating this section remain conformant. An agent MUST NOT require the challenge to be present; when it is absent the agent falls back to fetching `/.well-known/afauth` by the convention of Section 4. A verifier on the request path (Appendix E) emits the challenge directly; it always has `discovery` available, includes `error` only for an actual AFAuth attempt (see `error` above), and SHOULD include `attestors` when configured with the accepted set.

**No primacy on multi-scheme resources.** A resource MAY accept AFAuth alongside other authentication schemes. When it does, the AFAuth challenge MUST be presented as one of possibly several `WWW-Authenticate` challenges; AFAuth claims no preference and MUST NOT suppress, replace, or reorder another scheme's challenge. The service decides whether the AFAuth challenge appears and where it sits — challenge order signals the service's preference per [RFC9110], and AFAuth does not require being first. A service MAY advertise AFAuth only to clients that already attempt it (emit the challenge solely when the request carried AFAuth credentials), keeping AFAuth invisible to purely other-scheme clients.

The challenge introduces no new status code, error body, or state transition; it is an additive response header on the identical rejection path. In particular, the Section 9.2 guarantee that no account is created on an `attestation_required` rejection is unaffected.

A bare advertisement — the request did not attempt AFAuth (a cold client, or one using another scheme):

```http
WWW-Authenticate: AFAuth discovery="https://api.example.com/.well-known/afauth"
```

Error challenges — the request attempted AFAuth and it failed:

```http
WWW-Authenticate: AFAuth discovery="https://api.example.com/.well-known/afauth", error="invalid_signature"
WWW-Authenticate: AFAuth discovery="https://api.example.com/.well-known/afauth", error="attestation_required", attestors="afauth-trust microsoft-entra-agent-id"
WWW-Authenticate: AFAuth discovery="https://api.example.com/.well-known/afauth", error="revoked_key"
```

Presented beside another scheme on a multi-scheme resource — AFAuth is one challenge among several and the service chooses the order:

```http
WWW-Authenticate: Bearer realm="api", error="invalid_token"
WWW-Authenticate: AFAuth discovery="https://api.example.com/.well-known/afauth"
```

### 5.8 Optional authentication (anonymous-allowed endpoints)

AFAuth authentication is per-request and optional by construction: a resource MAY accept AFAuth on endpoints that also allow anonymous (unauthenticated) access, granting an authenticated agent more — higher rate limits, richer data, write access — while still serving callers that present no credentials. Such an endpoint performs *optional verification*:

- If the request presents AFAuth credentials (a `Signature` / `Signature-Input`, or an `AFAuth-Attestation`), the resource verifies them per §5.5 and, on success, treats the caller as the authenticated agent.
- If the request presents no AFAuth credentials, the resource MUST serve the anonymous response and MUST NOT return `401` — an anonymous-allowed request is not a rejected request, so it carries no `WWW-Authenticate` challenge (§5.7).
- If credentials are present but invalid, the resource SHOULD reject with `401` and a §5.7 error challenge rather than silently downgrading to anonymous; the client attempted AFAuth and should learn that the attempt failed.

Because an anonymous-allowed endpoint does not reject the unauthenticated caller, the §5.7 challenge is not its discovery mechanism — agents learn that the resource speaks AFAuth from `/.well-known/afauth` (§4), and an AFAuth-capable agent that signs its requests by default simply receives the authenticated treatment with no prior negotiation. (This is distinct from anonymous *AFAuth signup* under `billing.unclaimed_mode = "free"` (§6.3), where the agent does sign — bringing a `did:key` — but no human or attestation is required.)

---

## 6. Account Lifecycle

### 6.0 Account identity and agent credentials

A service identifies an account by an opaque, service-local `account_id` that is distinct from any verification key. An account holds **one or more agent credentials** — each a `did:key` (§3) authenticated per §5 via its `keyid`. A request resolves to its account through the presenting credential's `keyid`.

In the simplest case an account has exactly one credential, and `account_id` may be carried 1:1 with that DID. A service that groups a human's agents by the attestor pseudonym `(iss, sub_h)` (§10.4.4) attaches additional credentials (the human's other devices) to the same `account_id` — "one account, many devices". The `account_id` is **stable across key rotation** (§8.1): rotating a credential swaps that DID, not the account. Singleton accounts (no `sub_h`) still hold a single credential.

Responses that name the account use `account_id`; responses to an agent-signed request also echo the calling credential as `agent_did`.

### 6.1 Account states

An account is in exactly one state at any time. Conforming services MUST implement the following states:

| State | Description |
|---|---|
| `UNCLAIMED` | Account exists; no owner is bound. Created by signup. |
| `INVITED` | An owner invitation has been sent; not yet claimed. |
| `CLAIMED` | Account is bound to an owner via the claim flow. |
| `EXPIRED` | Reachable only when the service sets `unclaimed_ttl_seconds` (§4.4): the account exceeded that age without being claimed and is no longer operable. Services that do not set a TTL — the default — never produce this state. |
| `ARCHIVED` | Account explicitly deleted by the owner; retained for audit/compliance. |

By default, an `UNCLAIMED` account has no expiry: its agent MAY operate it indefinitely, and reaching `CLAIMED` is optional. The `EXPIRED` state and the transitions into it (Appendix A) apply only to services that opt into an `unclaimed_ttl_seconds` limit (§4.4). A conforming service that does not advertise that limit never transitions an account to `EXPIRED`.

### 6.2 State transitions

See Appendix A for the diagram. Conforming services MUST NOT permit transitions other than those defined.

### 6.3 Implicit signup

The first valid signed request from an unrecognised account DID MUST cause the service to create the account in state `UNCLAIMED`, unless the service requires explicit signup (Section 6.4).

This mode optimizes for agent ergonomics: an agent that has just generated a keypair can call any protected endpoint and have its account auto-created. The service MUST NOT distinguish externally between "implicit signup followed by operation" and a request to a pre-existing account. By default the account so created persists indefinitely (§6.1): the agent is its principal whether or not a human ever claims it.

Services that declare `billing.unclaimed_mode = "attested_only"` (§9) MUST reject implicit-signup attempts lacking a valid `AFAuth-Attestation` header (§10) with `401 Unauthorized` and error code `attestation_required`. The service MUST NOT create the account in this case; the rejection MUST occur before any state transition. The `401` response SHOULD carry a `WWW-Authenticate` challenge (§5.7) with `error="attestation_required"` and an `attestors` list drawn from `billing.accepted_attestors`, so the agent learns which attestor to obtain a token from.

### 6.4 Explicit signup

Services MAY require explicit account creation, in which case an agent MUST issue:

```http
POST /afauth/v1/accounts HTTP/1.1
Host: api.example.com
Content-Type: application/json
[ signed per Section 5 ]

{
  "terms_version": "2026-05-01",
  "attestation":   "<optional JWT, per Section 10>"
}
```

A successful response:

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "account_id":           "acct_8f3cZ_K9qWmA...",
  "agent_did":            "did:key:z6Mk...",
  "state":                "UNCLAIMED",
  "created_at":           "2026-05-18T12:00:00Z"
}
```

Services that require explicit signup MUST reject implicit signup attempts with `404 Not Found` (NOT `401`, which would imply the credential was wrong).

### 6.5 Account introspection

Agents MAY retrieve their own account state:

```http
GET /afauth/v1/accounts/me HTTP/1.1
Host: api.example.com
[ signed per Section 5 ]
```

Response:

```json
{
  "account_id":           "acct_8f3cZ_K9qWmA...",
  "agent_did":            "did:key:z6Mk...",
  "state":                "UNCLAIMED",
  "created_at":           "2026-05-18T12:00:00Z",
  "owner":                null
}
```

If the service sets an `unclaimed_ttl_seconds` limit (§4.4), the response additionally includes `unclaimed_expires_at`; with no limit — the default — the account does not expire and the field is omitted.

When `state` is `CLAIMED`, the `owner` field MUST be populated:

```json
"owner": {
  "identity": {
    "type":  "email",
    "value": "alice@example.com"
  },
  "user_id":      "usr_01h...",
  "claimed_at":   "2026-05-18T13:42:00Z"
}
```

`owner.identity` is the normalized recipient that was verified at claim time (see §7.4 and §7.7). Its `type` and `value` shape are determined by the recipient-type registry (§7.7); for `email`, the value is the canonical case-insensitive mailbox; for `oidc`, the value is the issuer URL concatenated with the verified subject; for `did`, the value is the canonical DID.

Services MAY include additional informational fields in `owner` (for example `display_email` derived from a verified `oidc` recipient) for client convenience; such fields are service-defined and not normative.

When `state` is `INVITED`, the `owner` field MUST remain `null`. Services MUST NOT expose the pending recipient through agent-signed responses; see Section 13.2.

---

## 7. Owner Invitation and Claim

### 7.1 Two-step verify

The transition from `UNCLAIMED` or `INVITED` to `CLAIMED` is the security boundary of the protocol. AFAuth REQUIRES a two-step verification:

1. The agent stages a pending email.
2. The human authenticates from that email.

The agent's signature alone MUST NOT bind ownership. This is the invariant that prevents a stolen agent key from re-targeting ownership to an attacker-controlled email.

### 7.2 Owner invitation

```http
POST /afauth/v1/accounts/me/owner-invitation HTTP/1.1
Host: api.example.com
Content-Type: application/json
[ signed per Section 5 ]

{
  "recipient": {
    "type":  "email",
    "value": "alice@example.com"
  },
  "redirect_url": "https://yourapp.com/welcome"
}
```

Field semantics:

- `recipient` (object, required): The identity being invited to claim the account. The object MUST contain a `type` field naming a recipient type registered in §7.7, and the type-specific fields required for that type (typically `value`). The service MUST reject the request with `400 Bad Request` and error code `unsupported_recipient_type` if `type` is not in the service's declared `recipient_types` (§4.4).
- `email` (string, optional, backward-compat): A bare `email` field at the top level of the request body MUST be accepted as a shorthand for `"recipient": { "type": "email", "value": "<value>" }`. New agent implementations SHOULD use the typed form. If both `email` and `recipient` are present, the request MUST be rejected with `400 Bad Request`.
- `redirect_url` (string, optional): URL to redirect to after successful claim. Services MUST validate it against an allow-list of service-controlled hosts and MUST NOT honour redirects to hosts outside that list. An unvalidated redirect parameter is a well-known open-redirect class of vulnerability and is rejected from the protocol's wire surface, not just discouraged.

Successful response:

```http
HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "invitation_id": "inv_01h...",
  "expires_at":    "2026-05-25T12:00:00Z",
  "state":         "INVITED"
}
```

On accepting the invitation, the service MUST initiate a verification ceremony appropriate to the recipient type — typically a magic-link email for `email`, an SMS or voice OTP for `phone`, an OIDC authorization-code flow for `oidc`, a challenge-response signature for `did`. The form of the ceremony is service-defined; §7.7 specifies only the *match relation* the ceremony must establish. Any token, code, or challenge issued during the ceremony MUST be single-use and bound to the invitation.

The service MUST transition state to `INVITED` immediately upon issuing the invitation. The staged recipient MUST be stored as `pending_recipient`, distinct from any committed `owner.identity` field, so that no agent-signed response exposes the pending value before claim commits (see §13.2).

If the invitation expires without a successful claim, the service MUST transition the account back to `UNCLAIMED` and discard the pending recipient.

### 7.3 Invitation lifetime and atomicity

Each invitation has a service-defined TTL. The protocol gives no normative bound; services SHOULD choose a TTL appropriate to the value of the underlying account. For most consumer contexts, 24 to 72 hours is typical.

At most one invitation MAY be pending for an account at any time. A new owner invitation request atomically replaces any prior pending invitation: the prior invitation's token MUST be invalidated, and any subsequent claim attempt using the invalidated token MUST fail with `410 Gone` and error code `invitation_expired`. Atomicity MUST be enforced at the storage layer (for example, via a unique constraint on the account's pending invitation and a serialised update path) to prevent race conditions between concurrent invitation requests.

If an invitation's TTL expires without a successful claim, and no replacement has been issued, the account transitions back to `UNCLAIMED` and the pending email is discarded. If the service sets an `unclaimed_ttl_seconds` limit (§4.4) and that limit elapses while an invitation is pending, the account transitions to `EXPIRED` (see Appendix A); a service with no such limit — the default — leaves the account in `INVITED` indefinitely. A service that does set a TTL SHOULD NOT issue an invitation whose validity would outlive the account's remaining unclaimed lifetime, so that a human is never shown a claim link already invalidated by expiry by the time they act on it.

This atomicity invariant replaces the "most recent invitation supersedes" model of earlier drafts, which permitted a window in which two concurrent invitations could both be valid; that window is the basis of a known time-of-check / time-of-use class of attack.

### 7.4 Claim completion

The human follows the magic link to the service's hosted claim page (`endpoints.claim_page` from discovery). After completing whatever human-authentication flow the service offers (magic link, passkey, OAuth), the page POSTs to the `endpoints.claim_completion` URL with the token as the final path segment:

```http
POST /afauth/v1/claim/<token> HTTP/1.1
Host: api.example.com
Content-Type: application/json
Cookie: session=<human session>
```

(The path `/afauth/v1/claim/` shown above is the example value of `endpoints.claim_completion`; conforming services MUST use whatever value they declare in their own discovery document, with the token appended.)

Response on success:

```json
{
  "account_id": "acct_8f3cZ_K9qWmA...",
  "state":       "CLAIMED",
  "owner": {
    "identity": {
      "type":  "email",
      "value": "alice@example.com"
    },
    "user_id":    "usr_01h...",
    "claimed_at": "2026-05-18T13:42:00Z"
  }
}
```

Before the binding commits, the service MUST verify that the human's authenticated identity satisfies the **match relation** registered for the recipient's type (§7.7) against `pending_recipient`. For example: for the `email` type, the match relation is case-insensitive equality per [RFC5321] §2.4; for `oidc`, it is exact issuer + subject equality; for `did`, it is canonical DID equality combined with a verified signature over a freshness-bound challenge. The service MUST NOT bind an owner whose authenticated identity does not satisfy the match relation; in that case the service MUST reject the claim with `403 Forbidden` and error code `owner_authentication_required`, and the invitation MUST remain pending until the TTL expires or a matching authentication is presented.

Only after the authenticated identity has been verified to match `pending_recipient` does the account transition to `CLAIMED`. The service MUST:

- Persist `owner.identity` as the normalized form of `pending_recipient`, and clear the pending field.
- Issue any post-claim session credentials (cookie, JWT, etc.) per the service's authentication system.
- OPTIONALLY fire a webhook to inform the service backend of the claim event.

### 7.5 Authority model post-claim

After an account is `CLAIMED`, both the agent and the owner are first-class principals on the account. The agent's key continues to authorize ordinary operations that the service exposes for agents; no re-authorization by the owner is required for the agent to continue operating.

The protocol defines a single normative constraint on post-claim agent authority:

> An operation that modifies which credentials can authenticate as the owner MUST require an owner-authenticated session; the agent key alone MUST NOT authorize such an operation.

This category — termed **owner-binding operations** — includes, at a minimum: changing the bound owner identity, enrolling additional authentication credentials, adding or modifying recovery contacts that authenticate as the owner, linking federated identities, and adding additional principals to the account. The mapping from this category to concrete service operations is service-defined; services MUST classify their own operations against this rule. This classification is a policy decision and belongs to the service that defines the operation; a verifier that is decoupled from the service (for example, an edge gateway) provides the verified signer identity, but MUST NOT be the sole enforcement point for §7.5.

For an owner-authenticated session to authorize an owner-binding operation, the service MUST require evidence of a *fresh* authentication event satisfying the assurance bar from §12.3, performed within a service-defined freshness window measured at the moment of the operation. Implementations SHOULD use a window of 60 to 300 seconds. A session that is otherwise valid but does not evidence a fresh authentication event MUST cause the service to reject the owner-binding operation with `403 Forbidden` and the error code `owner_session_too_stale` (§11.3). The service SHOULD prompt the human to re-authenticate and resubmit; the rejection MUST NOT consume any rate-limit allowance attributable to the agent.

This freshness floor closes the takeover window where an attacker who pops the human's long-lived session cookie could otherwise immediately invoke owner-binding operations. The two-step verify invariant (§7.1) survives across the lifetime of the account only if the human side of the authentication is recently evidenced at each owner-binding moment.

This constraint preserves the durability of the two-step verify invariant (§7.1) past the moment of binding: revoking a compromised agent key under §8.4 fully restores the owner's sole authentication authority, because no authentication path planted by the agent alone can exist.

Beyond this single rule, the protocol takes no position on what an agent may do at any account state. Pre-claim agent authority, post-claim agent scope beyond the owner-binding rule above, the form of any claim-time manifest, and the treatment of obligations incurred pre-claim are all service responsibilities. See §12.7 for the security risks the protocol delegates to services.

### 7.6 Agent-driven re-invitation

In `CLAIMED` state, the agent MAY initiate a new invitation only if the existing owner explicitly authorises it (e.g., via an owner-session-authenticated endpoint defined by the service). This specification does not standardise the owner-side workflow; services MAY define their own.

### 7.7 Recipient types registry

Each `recipient` carries a `type` identifier drawn from this registry. The registry defines, per type, the required value shape, the verification ceremony the service is expected to run, and the **match relation** that establishes whether an authenticated identity satisfies a given recipient.

This specification reserves the following recipient types for v0.1. Conforming services MUST accept `email`; support for any other type is optional and MUST be declared in `recipient_types` (§4.4) before agents can use it.

#### 7.7.1 `email`

- **Value shape:** A syntactically valid mailbox per [RFC5321].
- **Verification ceremony:** Service-defined. The canonical pattern is a single-use magic link delivered to the mailbox; equivalent ceremonies include OIDC sign-in to the email provider and a pre-existing email-bound passkey.
- **Match relation:** Case-insensitive equality of the local-part and domain after Unicode NFKC normalization per [RFC5321] §2.4. A service that accepts federated identity MAY match against any email provably controlled by the authenticated identity (e.g., a verified-email claim in an OIDC token).

```json
{ "type": "email", "value": "alice@example.com" }
```

#### 7.7.2 `phone`

- **Value shape:** An E.164 string (e.g., `+14155550173`), without separators or extension. Implementations MUST reject values containing any character other than `+` and the digits `0`–`9`, and MUST reject E.164 extension syntax (`;ext=42`, `,42`, `x42`, and equivalents).
- **Verification ceremony:** Service-defined. Typical patterns include SMS OTP, voice OTP, and carrier-bound passkey.
- **Match relation:** Exact byte equality after E.164 normalization.

```json
{ "type": "phone", "value": "+14155550173" }
```

#### 7.7.3 `oidc`

- **Value shape:** An object with two fields: `issuer` (the OIDC Issuer URL, exactly as it appears in the IdP's discovery document) and `sub` (the subject identifier within that issuer). The `issuer` value is treated as opaque: implementations MUST NOT normalise it (e.g., lowercase the scheme, fold percent-encoding, or add or strip a trailing slash) — the IdP-published form is canonical per [OIDC-Discovery] §3. Implementations MUST reject `issuer` values containing a fragment or query component.
- **Verification ceremony:** Service-defined. The canonical pattern is an OIDC Authorization Code flow with PKCE that yields an ID Token whose `iss` and `sub` match the recipient.
- **Match relation:** Byte-exact equality of `issuer` and `sub`.

```json
{
  "type":  "oidc",
  "value": { "issuer": "https://accounts.google.com", "sub": "103948572345" }
}
```

#### 7.7.4 `did`

- **Value shape:** A bare DID identifying the human's verification method. The value MUST NOT include DID URL components (no path, query, or fragment). The DID method MUST be one the service accepts.
- **Canonical form:** Per the method's specification — for `did:key`, the multibase encoding canonical form defined in §3.1.1; for `did:web`, the lowercase host with the method-derived path syntax per [W3C-DID-WEB]. Implementations MUST reject non-canonical equivalents (e.g., `did:web:Example.COM` for `did:web:example.com`).
- **Verification ceremony:** A challenge-response in which the service issues a freshness-bound, account-specific challenge nonce, the human signs it with the private key corresponding to the DID's verification method, and the service verifies the signature. The exact framing (PAR, OIDC4VC, OpenID4VP, or a service-native ceremony) is service-defined. Where the DID's verification method exposes a public key compatible with [WebAuthn-L3] (P-256, RS256, EdDSA), the canonical ceremony framing is a `navigator.credentials.get(publicKey: PublicKeyCredentialRequestOptions)` call whose `challenge` is the service-issued freshness nonce, whose `allowCredentials` references the DID's verification method, and whose `userVerification` is `"required"`. Implementations that adopt this framing inherit phishing resistance and per-ceremony user verification without additional protocol surface.
- **Match relation:** Canonical DID equality combined with a verified signature over the challenge issued for this invitation.

```json
{ "type": "did", "value": "did:key:z6MkrJVnaZkeFzdQyMZu1cF5cgqU3M..." }
```

#### 7.7.5 Other types

Future versions of this specification, or AFAPs that update this registry, MAY add additional types (for example `siwe` for chain-bound addresses, `webauthn` for credential-id-bound recipients, `domain` for DNS controllers, or `verifiable_credential` for predicate-based recipients). Services MUST NOT use unregistered type identifiers on the wire; service-specific extensions SHOULD prefix the type name with a vendor-specific namespace (e.g., `x-acme:internal-user`).

---

## 8. Key Management

Routine, time-scheduled key rotation is NOT required for AFAuth's Ed25519 verification keys: signing keys have no usage-based wear, so the drivers for changing a key are compromise recovery and algorithm migration — not a calendar. The operations below are framed around those drivers: pre-claim self-rotation (§8.1), owner-approved post-claim re-key (§8.2), and owner-initiated revocation as the authoritative recovery lever (§8.4), with §8.5 stating what that recovery does and does not reach.

### 8.1 Pre-claim key rotation

While the account is in `UNCLAIMED` or `INVITED` state, an agent MAY rotate its verification key by signing a rotation request with the old key:

```http
POST /afauth/v1/accounts/me/keys/rotate HTTP/1.1
Host: api.example.com
Content-Type: application/json
[ signed by OLD key ]

{
  "new_account_did": "did:key:z6Mk<new>..."
}
```

Response:

```json
{
  "account_id":     "acct_8f3cZ_K9qWmA...",
  "agent_did":      "did:key:z6Mk<new>...",
  "old_revoked_at": "2026-05-18T14:00:00Z"
}
```

Because a `did:key` identifier encodes the public key, the agent **credential** DID necessarily changes on rotation: the old DID is decommissioned (added to the revocation list per §8.3) and the new DID becomes the live credential. The account itself is unchanged — its `account_id` (§6.0) is stable across rotation, and any sibling credentials on the same account keep working. A caller holding the old DID updates its reference from the rotation response.

Key rotation changes the agent's verification key (and, for `did:key`, the account identifier), but it does NOT change any attestor-issued `sub_h` (§10.4). `sub_h` is keyed on the principal behind the agent, not on the verification key, so an agent that re-links a rotated key to the same principal (§10.5.1) continues to present the same `sub_h` to each service. A service that keys per-human policy on `sub_h` therefore retains operator continuity across the agent's key rotations.

### 8.2 Post-claim key rotation (re-key)

After claim, a key change is an owner-binding operation: it MUST require a fresh owner-authenticated session (§7.5) and MUST NOT complete on the agent's signature alone. This is the resume half of revoke → re-key (§8.4) — an owner whose agent key is lost or compromised installs a fresh key without abandoning the account. Two flavours are defined.

**Owner-initiated (RECOMMENDED for compromise recovery).** The owner supplies a fresh public key through a side-channel — pasted into a dashboard form, or carried on an owner-authenticated request to the re-key endpoint. Because the request is NOT signed by the agent key (which may be stolen), the account being re-keyed is named explicitly and the service MUST verify that the owner-authenticated session owns it.

```http
POST /afauth/v1/accounts/me/keys/rekey HTTP/1.1
Host: api.example.com
Content-Type: application/json
[ owner-authenticated session; NOT agent-signed ]

{
  "current_account_did": "did:key:z6Mk<old>...",
  "new_account_did":     "did:key:z6Mk<new>..."
}
```

Response:

```json
{
  "account_id":     "acct_8f3cZ_K9qWmA...",
  "agent_did":      "did:key:z6Mk<new>...",
  "old_revoked_at": "2026-05-18T14:00:00Z",
  "state":          "CLAIMED"
}
```

The owner binding carries forward service-side. Attestor-issued `sub_h` (§10.4) does NOT automatically carry forward: a `did:key` re-key yields a new agent DID, and the attestor keys bindings on the agent DID, so the new key has no binding — and thus obtains no attestation and no `sub_h` — until the owner re-links it to the same principal (§10.5.1; see §8.5). The same `sub_h` is then restored, because `sub_h` is keyed on the principal, not on the key. The credential DID changes to the new value (§8.1) — it is returned as `agent_did` — while the `account_id` is stable; the old DID is added to the revocation list (§8.3). The service MUST reject:

- a stale session with `403` `owner_session_too_stale` (§7.5);
- a session that does not own the named account with `403` `owner_authentication_required` (and `401` `owner_authentication_required` when no session is presented at all);
- a non-`CLAIMED` or absent account with `409` `not_claimed` (or `404` `unknown_account`), and an `EXPIRED` account with `410` `account_expired`;
- a `new_account_did` that is malformed or equal to the current DID with `400` `malformed_request`, and one that already names an existing account with `409` `already_claimed`.

**Agent-initiated.** The agent signs a rotation request with the old key (the §8.1 endpoint); for a `CLAIMED` account the service MUST NOT complete it inline, but instead emails a confirmation link to the owner and completes only after the owner authenticates with a fresh owner session. An agent-signed request that attempts to complete a post-claim key change inline is rejected with `403` (`owner_binding_blocked` / `owner_authentication_required` per §11.3).

### 8.3 Revocation

Each service MUST maintain a local revocation list of agent credential DIDs whose keys have been retired (through rotation or owner-initiated revocation). Requests signed by a revoked key MUST be rejected with `401 Unauthorized` and the error code `revoked_key` (Section 11), and the response SHOULD carry a `WWW-Authenticate` challenge (§5.7) with `error="revoked_key"`; the agent's correct recovery is to re-key (§8.2) or re-link rather than to retry under the same DID. Revoking a whole account (§8.4) lists every one of its agent credential DIDs.

Cross-service revocation distribution is NOT part of this specification. Services MAY publish their revocation lists as part of an aggregated abuse feed (e.g., through a centralised network operator), but no inter-service revocation transport is mandated.

### 8.4 Owner-initiated revocation

The owner of a `CLAIMED` account MAY revoke the agent's key entirely, without rotating — the authoritative pause / kill-switch. Like re-key (§8.2) this is an owner-binding operation: owner-authenticated, NOT agent-signed.

```http
POST /afauth/v1/accounts/me/keys/revoke HTTP/1.1
Host: api.example.com
Content-Type: application/json
[ owner-authenticated session; NOT agent-signed ]

{
  "account_id": "acct_8f3cZ_K9qWmA..."
}
```

The account MAY instead be named by any of its agent credentials via `agent_did`. The response is `200 OK` with `{ "account_id": "...", "revoked_at": "2026-05-18T14:00:00Z" }`. Revoking the account adds every one of its agent credential DIDs to the revocation list (§8.3). The DID is added to the revocation list (§8.3); subsequent requests signed by the revoked key MUST return `401 Unauthorized` with `revoked_key`. The service MUST apply the same owner-session gates as §8.2 (stale → `403` `owner_session_too_stale`; non-owner → `403` `owner_authentication_required`; no session → `401`; non-`CLAIMED` → `409` `not_claimed`). Re-revoking an already-revoked account is idempotent (`200`). The owner MAY later restore service by re-keying (§8.2); for `did:key`, "restore" installs a NEW key under a NEW identifier — it is not an un-revoke of the old key, which stays revoked.

Services MAY additionally expose an un-gated, service-internal revoke for abuse handling, distinct from this owner-facing endpoint.

### 8.5 Revocation coverage and its limits

Revocation and pause have honest, bounded reach. Implementers and operators MUST understand the following:

- **Per-service, non-distributed.** §8.3/§8.4 revocation is local to the service that performs it; there is no inter-service revocation transport (§8.3). An owner recovering from compromise must act at each service that supports owner revocation — and at the attestor (if any) to stop new attestations.
- **Attested access is bounded by the attestation lifetime.** Where a service gates each request on a live attestation (§9.2 `attested_only`, §10.6 per-request), revoking the agent's binding at the attestor takes effect within the attestation TTL (≤ the §10.2 ceiling). Already-issued attestations remain valid until they expire: pausing or revoking stops NEW issuance, it does not recall outstanding tokens.
- **Attestor-side revocation can be per-service.** Besides releasing an agent DID's binding (§10.5.1) or pausing the principal (§8.4) — both of which stop *all* attested access — the owner MAY revoke minting for a single (agent DID, service) pair at the attestor (§10.3.1), stopping attested access at that one service within its freshness window while leaving the binding and every other service intact. The attestor also surfaces the list of services each agent DID has minted for, giving the owner the cross-service view this section otherwise leaves them to assemble unaided. This is selective de-authorisation and review, not compromise recovery — a held key still mints for any non-revoked service — and it does not reach a service that checked attestation only at signup.
- **Signature-gated, non-attested access is a structural blind spot for attestor-side action.** A service that checked an attestation once at signup and thereafter trusts the agent signature will not observe an attestor-side revoke at all; only that service's own §8.4 revocation reaches it. Services protecting high-value operations SHOULD therefore gate on live per-request attestation (§10.6) rather than minting a long-lived local credential at first contact. Where per-request attestation is too costly, a service MAY instead maintain an **attested session** (§10.7): it requires the agent to keep a currently-valid attestation on file and challenges with `attestation_required` when the freshness window lapses, so that an attestor-side revoke or pause takes effect within that window.
- **The agent's local state is untrusted after compromise.** Recovery MUST NOT depend on the agent cleaning up its own ledger or cache; an attacker who holds the key controls that state.
- **Resuming attested access requires a re-link, not just a re-key.** A §8.2 re-key produces a new agent DID with no attestor binding (the attestor keys bindings on the agent DID). To regain access at `attested_only` services the owner MUST re-link the new DID to the same principal at the attestor (§10.5.1) — and resume the principal first if it was paused (§8.4). Because `sub_h` is keyed on the principal (§10.4), per-service operator continuity is preserved across the re-link. Revocation and pause cover only the "stop" direction; resuming is this distinct, owner-driven re-link step.

This is a property of the trust model, not a v0.1 defect; see §12.1.

---

## 9. Billing Declaration

### 9.1 Pre-claim billing modes

Services declare their pre-claim billing policy in the discovery document (`billing.unclaimed_mode`). The protocol takes no position on who pays during the unclaimed window; it provides a vocabulary for services to declare their stance:

- `"free"`: The service absorbs unclaimed usage (free tier, trial, or post-paid against the eventual claimer).
- `"attested_only"`: The service accepts unclaimed signups only when an accepted attestor (Section 10) vouches for a billable operator.
- `"denied"`: Paid features are gated behind a claim; unclaimed accounts have read-only or sandboxed access.

Conforming services MUST honour their declared mode. Agents MUST read the discovery document before signing up to determine whether to provide an attestation.

### 9.2 Attestation requirement

If `unclaimed_mode` is `"attested_only"`, the service MUST reject signup requests that lack an `AFAuth-Attestation` header. The error response (Section 11) SHOULD identify the required attestation type via the `details` field and, on the `WWW-Authenticate` challenge (§5.7), via the `attestors` parameter.

---

## 10. Optional: Agent Attestation

### 10.1 Purpose

By default, AFAuth accepts any well-formed Ed25519 keypair. Services that want to know *which runtime* an agent is operating in — for abuse prevention, enterprise compliance, or rate-limit tiering — MAY require an attestation token.

### 10.2 Attestation header

```
AFAuth-Attestation: <JWT signed by an accepted attestor>
```

The token MUST conform to JWT [RFC7519]:

- `iss` (issuer) MUST identify a known attestor.
- `sub` (subject) MUST be the requesting agent's account DID.
- `exp` MUST be in the future at the time of verification.
- `sub_h` (subject — human, pairwise) MUST be present if the attestor asserts a binding between the agent's DID and a stable principal (typically a human account). The claim is defined in §10.4. When `sub_h` is present, `aud` MUST also be present, set to the destination service's `service_did`.
- Other claims are attestor-specific.

Attestors that signal a binding to a stable principal are additionally bound by the agent–principal uniqueness rule in §10.5.

### 10.3 Recognized attestors

This specification reserves four classes of attestor identifier:

- **Trust attestor**: `afauth-trust`. Operated by afauth.org. Vouches that an agent's account DID is bound to a human-controlled account verified by one of the methods enumerated in §10.3.1.
- **Platform attestors**: `microsoft-entra-agent-id`, `google-cloud-agent-identity`.
- **Commerce attestors**: `fido-agent-payments`, `mastercard-verifiable-intent`, `visa-trusted-agent`.
- **Service-operator HMAC**: For first-party agents, services MAY accept tokens signed with a shared symmetric key under an identifier they define.

Platform attestors are typically designed around a customer's own tenant: the assertion's audience claim names a relying party pre-registered in the attestor's directory. A service that accepts a platform attestor identifier should expect to set up per-tenant federation (or equivalent) to make the audience binding usable.

Commerce attestors are typically transaction-scoped: their assertions materialise in the context of a payment authorisation rather than as standing identity tokens. A service that accepts a commerce attestor identifier should expect to consume the assertion in the same request flow that carries its payment context, not as a presentable token issued ahead of any commerce.

The set of accepted attestors is declared per-service in `billing.accepted_attestors`. Conforming services MUST validate the attestation against the attestor's published verification key (for asymmetric attestors) or shared secret (for HMAC attestors).

### 10.3.1 Trust attestor (`afauth-trust`)

The trust attestor issues JWTs that satisfy §10.2 and additionally:

- `iss` MUST be the string `afauth-trust`.
- `aud` MUST be the `service_did` of the destination service. A service MUST reject a token whose `aud` does not match its own `service_did`.
- `iat` MUST be present. `exp - iat` MUST NOT exceed 900 seconds.
- `verification` (string) MUST be present. Defined values: `"email"`, `"oauth"`, `"payment"`. Consuming services MUST ignore unknown values rather than rejecting the token, so that future values can be added without breaking existing verifiers.
- `sub_h` (string) MUST be present and MUST satisfy §10.4. The trust attestor derives `sub_h` per §10.4.3 using an HMAC-SHA256 key (`K_pseudonym`) that is distinct from its JWT signing keys and is not rotated under normal operation.

The trust attestor MUST enforce §10.5: at most one active human binding per agent DID. A binding-creation request for an agent DID that already has an active binding under a different human MUST be rejected, with no disclosure of the existing owner. The current owner MAY revoke their binding to release the agent DID for re-binding by another human.

The JWT header MUST include a `kid` that resolves to a key published in the JWKs document at `https://trust.afauth.org/.well-known/jwks.json`. Consuming services MUST verify tokens offline against that document. The attestor MUST publish a new `kid` at least one maximum-TTL (900 seconds) before first use, so that caches can refresh without an outage window.

The trust attestor MUST NOT include personal data (email address, phone number, payment details, government identifiers) in any claim. `sub_h` is derived such that this prohibition is preserved (§10.4.3). Future claims that signal additional context MAY be added without revising this AFAP, provided they preserve the offline-verification property and the privacy constraint above.

The spec takes no opinion on what access a service grants in response to any particular `verification` value, nor on any ordering between values. The `verification` claim is a categorical signal; the service's policy is local.

The trust attestor MUST keep, per binding, a record of the (agent DID, `aud`) pairs it has minted attestations for, with the time of the first mint for each pair, and MUST surface this record to the bound human on the owner-authenticated binding-management surface. This is owner-scoped audit data (§13.3): the attestor MUST NOT surface it to the agent by default, and MUST NOT disclose one principal's record to another, preserving the cross-principal prohibition above. The record gives the human the cross-service view that §8.5 otherwise leaves them to assemble unaided — which agent DID is signed up at which service, and since when.

The bound human MAY revoke minting for any individual (agent DID, `aud`) pair from that surface. While a pair is revoked, the attestor MUST refuse to mint an attestation for it, and SHOULD signal the refusal to the agent as a non-transient `403` with `error.code` `service_suspended` (which the agent MUST NOT retry for that `aud`). Per-pair revocation is finer-grained than releasing the agent DID's binding (§10.5.1) or pausing the principal (§8.4) — which stop every `aud` — and leaves the binding and all other services intact; like all attestor-side revocation it takes effect at the destination service within the attestation freshness window (§8.5, §10.7). It is a control for selective de-authorisation and for reviewing where an agent has signed up, not a compromise-recovery lever: a held key still mints for any non-revoked `aud`, so a compromised key MUST have its whole binding revoked (§10.5.1/§8.4), not be cut off service-by-service.

### 10.4 Pairwise human pseudonym (`sub_h`)

`sub_h` is a pairwise pseudonymous identifier carried in attestations to give consuming services a stable handle for the human principal behind an agent, without revealing the human's identity and without enabling cross-service correlation.

#### 10.4.1 When required

An attestor MUST include `sub_h` in any attestation that asserts a binding between the agent's DID (`sub`) and a stable principal (typically a human account verified by the attestor). For the trust attestor, this is signalled by the presence of the `verification` claim; presence of `verification` without `sub_h` is malformed and MUST be rejected by the consuming service with `401 Unauthorized` and error code `invalid_attestation`.

Attestors that do not bind the agent to a stable principal — for example, pure runtime attestors that vouch only for the agent's execution environment — MAY omit `sub_h`.

#### 10.4.2 Required properties

For every attestor implementing `sub_h`:

- **Pairwise.** For a fixed principal P, the value of `sub_h` MUST differ across distinct `aud` values. Two services that compare `sub_h` values for the same principal MUST NOT see the same string.
- **Stable.** For a fixed (principal, `aud`) pair, the value of `sub_h` MUST be identical across every attestation issued for that pair, across all of that principal's agents, and across time. Stability MUST be preserved across attestor signing-key rotations (§10.3.1) and across operational changes that preserve the principal record.
- **Opaque.** `sub_h` MUST carry at least 128 bits of entropy and MUST NOT be invertible to the principal's identity, contact details, or any other personal data (§10.3.1). Consuming services MUST treat `sub_h` as an opaque string.
- **Encoded.** `sub_h` MUST be a `base64url` string with no padding [RFC7515], between 22 and 86 characters in length.

#### 10.4.3 Recommended construction

Attestors SHOULD derive `sub_h` as:

```
sub_h = base64url( HMAC-SHA256( K_pseudonym, principal_id || ":" || aud ) )
```

where `K_pseudonym` is a high-entropy secret held by the attestor that is distinct from any JWT signing key and is not rotated under normal operation. Implementations MAY use other constructions, provided the §10.4.2 properties hold. Implementations MUST NOT derive `sub_h` from any data the attestor would be prohibited from publishing under §10.3.1.

#### 10.4.4 Service use

Services MAY use `sub_h` as a per-service uniqueness key for the human behind an agent — for example, to enforce "at most one free-tier account per human," to apply per-human rate limits across an agent fleet, or to recognise that several agent DIDs at the service belong to the same operator. The specification takes no opinion on how a service combines `sub_h` with `verification` or other signals; policy is local to each service.

Services that accept attestations from more than one attestor MUST scope `sub_h` by `(iss, sub_h)` rather than by `sub_h` alone, since different attestors derive independent pseudonym spaces for the same human.

A service MAY group a human's agents into a **single account** keyed on `(iss, sub_h)`: when an attested signup presents an `(iss, sub_h)` that already has an account, the new agent DID is **attached to that account** rather than creating a second one — "one account, many devices", the way a human signs into one account from several devices. The account is then identified by a service-local `account_id` (§6) distinct from any verification key, and holds one or more agent credentials. Because `sub_h` is keyed on the principal and not the verification key (§10.4.2, §10.5.1), this grouping is unaffected by key rotation (§8.1) and by revoke-then-rebind to the same principal. A service that groups this way SHOULD bucket its anti-abuse state (free-tier quota, rate limits, bans) on the account (equivalently on `(iss, sub_h)`), so that a human's agents share one bucket and no legitimate multi-device user is locked out. Runtime-only attestations carry no `sub_h` (§10.4.1) and assert no principal, so each such agent gets its own singleton account. This grouping is a local-policy convenience and does not relax the attestor-side anti-Sybil caveats of §10.4.5 and §12.9. When the same attestor also issues OIDC ID Tokens so humans can sign in (§10.8), a service that groups this way MUST treat the attestation issuer and the OIDC issuer URL as one issuer identity when keying the account, so that the agent's attested signup and the human's sign-in converge (§10.8.4).

#### 10.4.5 What `sub_h` is not

`sub_h` is not a proof that the human controls no other principal record at the same attestor (an attestor's anti-Sybil property is operational, not cryptographic; see §12.9). It is not portable across attestors. It is not a verifiable credential about the human and MUST NOT be presented as one. It is not a contact identifier and MUST NOT be exposed in user-facing surfaces in a form a third party could correlate.

### 10.5 Agent–principal binding uniqueness

For every attestor that issues `sub_h` (§10.4), the binding between an agent DID and a principal MUST be one-to-one within the attestor at any point in time. Concretely:

- An attestor MUST NOT issue two concurrently valid attestations carrying the same `sub` (agent DID) and the same `aud` but different `sub_h` values.
- Equivalently: at most one active human binding per agent DID per attestor.

An attestor MUST reject a binding-creation request that would establish a second active binding for an agent DID already bound to a different principal. The rejection SHOULD inform the requesting human that the agent DID is already bound, without disclosing which principal owns the existing binding (to preserve §10.3.1's prohibition on cross-principal correlation).

#### 10.5.1 Rebinding

When the existing binding is revoked or expires, the agent DID MAY be re-bound to the same or a different principal. The two cases differ in their effect on `sub_h`:

- **Re-binding to the same principal** — including re-linking a rotated verification key under a new agent DID (§8.1) — MUST yield the same `sub_h` for each `aud`, per the §10.4.2 stability property. `sub_h` is derived from the principal record, not from the binding instance or the agent's verification key, so a revoke-then-rebind and a key rotation are both transparent to the consuming service: it sees an unbroken operator.
- **Re-binding to a different principal** produces a new `sub_h` for any `aud` reached by the new principal, computed per §10.4.3 from the new principal's identity. Consuming services MUST treat this as a change of operator: the re-bound agent is, from the service's perspective, indistinguishable from a fresh registration of a new operator using the same agent DID.

#### 10.5.2 Rationale

If a single agent DID could carry distinct `sub_h` values issued by the same attestor (one per co-binding principal), an operator could circumvent any per-`sub_h` policy a service applies by rotating among the bindings on a per-request basis. The uniqueness rule preserves the property that, *within one attestor*, a service can rely on `sub_h` to mean "one human" rather than "one binding context that this human happens to be using right now."

#### 10.5.3 Cross-attestor scope

The rule binds within a single attestor. The specification does not — and cannot, in a federated attestor model — enforce uniqueness across attestors. A service that accepts attestations from more than one attestor for the same agent DID MAY treat such a configuration as anomalous and SHOULD document its handling (typically: dedupe by `(iss, sub_h)` and accept that the same agent may be reachable through multiple distinct human channels).

#### 10.5.4 Multi-principal agents

Use cases that appear to require multiple humans behind one agent DID (team-owned deployment bots, family assistants, multi-controller enterprise agents) are out of scope for v0.1. They are expected to be modelled in a future version as a single organisational principal that itself has multiple human controllers, rather than as multiple human bindings on a shared agent DID. Implementations MUST NOT use co-binding under §10.5 as an interim substitute, because doing so silently weakens the §10.4 dedup guarantee for every service that consumes the affected attestations.

### 10.6 Attestation lifetime

Outside of an **attested session** (§10.7), attestations MUST be presented on a per-request basis, and services MUST NOT cache attestations beyond the JWT's `exp`. Attestations carry no state of their own; they are an additional gate on the signed request.

### 10.7 Attested sessions (periodic re-presentation)

A service operating in `attested_only` mode (§9.2) MAY require an agent to keep a currently-valid attestation **on file**, rather than presenting one on every request (§10.6). The service records the expiry of the most recently verified attestation for an account and, while the account is within its **freshness window**, serves that account's signed requests without a new attestation. When the window lapses, the service MUST challenge the next request with `401 Unauthorized` and `attestation_required`, and SHOULD include a `WWW-Authenticate` challenge (§5.7) naming the accepted `attestors`; the agent's correct response is to obtain a fresh attestation (§10) and retry. A service that offers this behaviour SHOULD advertise the `attested_session` feature (§4.4).

The freshness window is determined by one of two modes:

- **Strict.** The window is the presented attestation's own `exp`. The service never serves on the authority of an attestation past its `exp`, so this mode introduces no relaxation of §10.6; it merely amortises presentation across the attestation lifetime (≤ the §10.2 ceiling) instead of requiring it on every request.
- **Extended.** The window is a service-chosen duration `T`, refreshed each time a valid attestation is presented. A service in this mode MAY serve an account's requests for up to `T` after the last presentation, including past the last attestation's `exp`. The per-request rule and the no-caching-past-`exp` rule of §10.6 are relaxed only for sessions a service has explicitly placed in this mode.

In all modes:

- A *presented* attestation MUST be rejected if it is already expired (`exp` in the past, §10.2): the window extends the **session**, never an individual token.
- The per-request agent signature (§5) remains the request authenticator. An attested session is an additional liveness gate, not a substitute for signature or nonce verification (§5.6, §E.5).
- The freshness window bounds revocation latency: a binding revoked or paused at the attestor (§8.4) takes effect at the service within the window, because the agent can no longer mint a replacement attestation (§10). Strict mode bounds this latency to the attestation TTL (≤ §10.2); extended mode bounds it to `T`.

An attested session carries no other state and confers no authority beyond confirming the binding remains live; it does not alter the account state machine (§6) or any owner-binding classification (§7.5).

### 10.8 Human sign-in via the trust attestor (OpenID Provider)

§10.1–§10.7 gate an *agent's* signed requests. This section defines how a *human* signs in to a service and lands in the account their agent already created — "Sign in with AFAuth", the agent-first analogue of "Sign in with Google". It builds entirely on the pairwise principal `(iss, sub_h)` of §10.4 and adds no new trust root.

The trust attestor (§10.3.1) MAY additionally operate as an OpenID Provider [OIDC-Core]. The requirements below apply when it does. An attestor that does not offer human sign-in is unaffected.

#### 10.8.1 Endpoints and flow

- The attestor MUST publish an OpenID Provider configuration document [OIDC-Discovery] at `https://trust.afauth.org/.well-known/openid-configuration`, advertising at minimum its `issuer`, `authorization_endpoint`, `token_endpoint`, and `jwks_uri`.
- The advertised `issuer` MUST be the URL `https://trust.afauth.org`. This is the attestor's OIDC issuer identifier; it is a distinct syntactic form from the bare-string attestation `iss` of §10.3.1, and §10.8.4 governs how a service reconciles the two.
- The attestor MUST implement the Authorization Code flow with PKCE [RFC7636] using the `S256` code-challenge method. The implicit and hybrid flows MUST NOT be offered. Authorization codes MUST be single-use and short-lived.
- The `jwks_uri` SHOULD be the same JWKs document used for attestation verification (§10.3.1), so a consuming service verifies ID Tokens with keys it already trusts.
- The human authenticates to the attestor as the same human-controlled account that backs the agent binding of §10.3.1. The attestor returns an authorization code to the service's registered redirect URI, which the service exchanges at the token endpoint for an ID Token.

#### 10.8.2 ID Token claims

The ID Token MUST conform to [OIDC-Core] and additionally:

- `iss` MUST be `https://trust.afauth.org`.
- `aud` MUST be the relying service's `service_did`, established at client registration (§10.8.3). A service MUST reject an ID Token whose `aud` does not match its own `service_did`.
- `sub` MUST be the pairwise pseudonym `sub_h` that the attestor derives for `(principal, aud)` per §10.4 — that is, **the identical value the attestor places in the `sub_h` claim of an attestation issued to the same service for the same human.** This equality is the convergence guarantee: the agent's attested signup and the human's sign-in resolve to one `(iss, sub_h)`.
- `exp` MUST be in the future at verification; the attestor SHOULD keep the ID Token short-lived.
- `nonce` MUST be echoed when the service supplied one at the authorization endpoint.

The ID Token MUST NOT carry personal data, consistent with §10.3.1. `sub` is the pairwise pseudonym, never an email, name, or other identifier.

#### 10.8.3 Client registration

A service that offers human sign-in registers with the attestor as an OIDC client. The registration MUST bind, at minimum, a `client_id`, the service's `service_did`, and an allowlist of exact `redirect_uris`. The registered `service_did` MUST equal the value the service uses as its `aud` / `service_did` for attestation (§10.2, §4.3), because that value is the audience input to the §10.4.3 `sub_h` derivation; a mismatch yields a different `sub`, and the human lands in a different (empty) account. The attestor MUST reject an authorization request whose `redirect_uri` is not in the registered allowlist, before issuing any code.

#### 10.8.4 Issuer canonicalization (convergence requirement)

A service that groups a human's agents into one account keyed on `(iss, sub_h)` (§10.4.4) and also offers human sign-in MUST treat the bare-string attestation issuer `afauth-trust` (§10.3.1) and the OIDC issuer URL `https://trust.afauth.org` as **the same issuer identity** when computing the account key. Equivalently, the service MUST canonicalize both forms to a single issuer identifier — RECOMMENDED: the URL `https://trust.afauth.org` — before lookup. A service that skips this step keys the agent's attested signup and the human's sign-in under two different `iss` values, so the human lands in a new, empty account instead of the one their agent created.

#### 10.8.5 What sign-in does and does not do

Signing in authenticates the human principal behind the account identified by `(iss, sub_h)`. What access a service grants on a successful sign-in is local policy, consistent with §10 throughout. Sign-in is authentication, not ownership transfer: it does not by itself perform the §7 claim that binds an `owner` and raises the §7.5 owner-binding floor. A service MAY treat a first successful human sign-in as sufficient to expose the agent-created account to its human principal, and MAY separately run the §7 claim ceremony to establish a recoverable owner binding.

---

## 11. Error Responses

### 11.1 Error format

All error responses MUST use a JSON body with the following shape:

```json
{
  "error": {
    "code":    "invalid_signature",
    "message": "Signature verification failed",
    "details": { }
  }
}
```

Field semantics:

- `code` (string, required): A stable identifier for the error type. Reserved values are listed in Section 11.3.
- `message` (string, required): Human-readable description. SHOULD NOT contain sensitive details.
- `details` (object, optional): Error-specific structured information.

### 11.2 Status codes

| Status | Used for |
|---|---|
| `400 Bad Request` | Malformed request (invalid JSON, missing required fields, invalid DID syntax) |
| `401 Unauthorized` | Signature verification failed, key revoked, or attestation invalid. Responses SHOULD carry a `WWW-Authenticate` challenge (§5.7). |
| `403 Forbidden` | Operation not permitted in the current state (e.g., agent-initiated ownership change post-claim) |
| `404 Not Found` | Account does not exist (only when implicit signup is disabled) |
| `409 Conflict` | State conflict (e.g., account already `CLAIMED`; a re-key/revoke target that is not `CLAIMED`; a re-key `new_account_did` that already names an account) |
| `410 Gone` | Account is EXPIRED or invitation has expired |
| `429 Too Many Requests` | Rate limit exceeded |
| `503 Service Unavailable` | Service temporarily unable to process AFAuth requests |

### 11.3 Reserved error codes

Conforming services MUST use these codes when the corresponding condition applies:

`invalid_signature`, `expired_signature`, `replayed_nonce`, `unknown_account`, `revoked_key`, `invalid_attestation`, `attestation_required`, `invitation_expired`, `invitation_not_found`, `already_claimed`, `not_claimed`, `owner_authentication_required`, `owner_binding_blocked`, `owner_session_too_stale`, `account_expired`, `rate_limit_exceeded`, `malformed_request`, `unsupported_recipient_type`.

`owner_binding_blocked` is returned with `403 Forbidden` when an agent-signed request attempts an owner-binding operation post-claim (§7.5); it is distinct from `owner_authentication_required`, which signals that an owner-authenticated session is required for the operation in general. `owner_session_too_stale` is also returned with `403 Forbidden`, when an owner-authenticated session is present but the most recent authentication event it evidences predates the service's §7.5 freshness window; it is distinct from `owner_authentication_required` (no session at all) and `owner_binding_blocked` (an agent-signed request to an owner-binding op). `unsupported_recipient_type` is returned with `400 Bad Request` when an invitation request specifies a recipient `type` not present in the service's declared `recipient_types` (§4.4, §7.2). `owner_authentication_required` is returned with `401 Unauthorized` when no owner-authenticated session is presented for an owner-binding operation (§8.2, §8.4), and with `403 Forbidden` when a session is present but does not own the target account. `not_claimed` is returned with `409 Conflict` when an owner re-key (§8.2) or revoke (§8.4) targets an account that is not `CLAIMED`; `already_claimed` is returned with `409 Conflict` both for a claim attempt on an already-claimed account and for a re-key whose `new_account_did` already names an existing account. `attestation_required` is returned with `401 Unauthorized` both when an `attested_only` service rejects a signup lacking a valid attestation (§9.2) and when an attested-session service challenges an established account whose freshness window has lapsed (§10.7).

Services MAY define additional error codes for service-specific conditions, but SHOULD prefix them with a service-specific namespace (e.g., `example_quota_exceeded`).

---

## 12. Security Considerations

### 12.1 Key compromise

The agent's private key is the sole credential for pre-claim operations. Implementations SHOULD use OS-level keystores, hardware-backed keystores (TPM, Secure Enclave), or cloud KMS where available.

If a key is compromised pre-claim, an attacker holding it can invite their own email as the owner and complete the claim. The legitimate operator has no in-protocol remedy other than abandoning the account. Operators of high-value agents SHOULD therefore not rely on file-based keys.

### 12.2 Replay

The combined use of `created`, `expires`, `nonce`, and `@target-uri` in the signature input binds each signed request to a specific service host, time window, and unique value. The freshness-window and seen-nonce mechanism (Section 5.6) prevents replay within the window. Services MUST NOT relax the nonce check for mutating requests.

### 12.3 Claim ceremony strength

The strength of the claim ceremony (§7.4) depends on the human-authentication method the service chooses. The protocol permits services to require any human-authentication flow at the claim page — magic link, passkey, OIDC, or others — and takes no position on the choice.

Services SHOULD select a method appropriate to the value of the account. Email-based magic links are classified as AAL1 by [NIST-SP-800-63B] and are vulnerable to adversary-in-the-middle phishing, prefetch consumption by email-security scanners, and downstream effects of email-account takeover. Phishing-resistant methods (WebAuthn / FIDO2 passkeys) provide AAL2, with hardware-bound credentials reaching AAL3. Services that require stronger assurance SHOULD require phishing-resistant authentication at the claim page and for owner-binding operations (§7.5).

Services targeting AAL2 or higher SHOULD use a phishing-resistant ceremony — canonical examples are WebAuthn-bound credentials per [WebAuthn-L3] (with `userVerification: "required"`) and OIDC flows that yield an `acr` value of `phishing-resistant` per [OIDC-MFA]. A magic link delivered to an email address remains the simplest interoperable default for the `email` recipient type (§7.7.1); services that accept this trade-off MUST document the assurance level in their claim-page user experience so the claimant can decide whether to enrol a stronger credential before completing the ceremony.

If a service uses magic links as a claim mechanism, it SHOULD require an active POST confirmation on the landing page rather than treating a GET as token consumption, to defend against link prefetching by email-security scanners. The service SHOULD also provide sufficient context for the human to recognise the originating agent before committing the binding; static informational banners are known to be ineffective under habituation, so active acknowledgement is preferable.

### 12.4 Cross-service correlation

Because an account DID is by default reusable across services, services can collude to correlate the same agent's activity. Agents that require unlinkability MUST use per-service key derivation (Section 3.3). Services MUST NOT publish account DIDs in ways that would aid correlation by third parties.

### 12.5 Attestation forgery

Services that accept agent attestations MUST validate the attestor's signature against an authoritative key source. Stale verification keys can permit forged attestations to pass. Services SHOULD pin attestor verification keys and refresh them on a documented schedule.

### 12.6 Email channel security

Magic-link emails transit through email infrastructure not controlled by the service. Services MUST use HTTPS for the magic link URL itself and SHOULD NOT include sensitive account context in the email body. Confirmation links MUST be single-use and bound to the originating invitation.

### 12.7 Pre-claim account state

An agent — or any party in possession of the agent's key before claim — may accumulate account state during the `UNCLAIMED` and `INVITED` windows: configurations, integrations, billing relationships, member lists, recovery contacts, additional credentials, prior tool history. Such state survives the transition to `CLAIMED` and may include attacker-controlled values not authorised by the eventual owner. This is the inverse of the pre-hijack attack class documented in [Sudhodanan-Paverd-2022].

The protocol's two-step verify (§7.1) prevents the agent's signature from binding ownership directly, and the post-claim owner-binding floor (§7.5) prevents the agent from rebuilding an authentication path after claim. Neither addresses the broader question of *what state the agent has accumulated* before binding.

This is outside the scope of the protocol. Services are responsible for:

- Determining what operations an agent may perform on an `UNCLAIMED` or `INVITED` account.
- Surfacing pre-claim state to the claiming human in a form they can evaluate, accept, or reset.
- Deciding how financial or contractual obligations incurred pre-claim are transferred (or not) at claim.

A service that permits an agent to make sovereignty-style changes (recovery contacts, payment methods, additional members) pre-claim without an owner-acceptance step at claim has not technically violated the protocol but has accepted a risk that this specification deliberately delegates. Services SHOULD document their pre-claim policy and surface it to humans during the claim flow.

### 12.8 Discovery document integrity

The `/.well-known/afauth` document declares the service's identity, accepted algorithms, endpoints, attestor list, and billing policy. Agents rely on it to construct correctly-formed requests and to evaluate the service before signup. The protocol does not specify integrity protection for the document itself in v0.1; integrity depends on TLS for the connection on which it is fetched.

A network attacker capable of compromising TLS — or a hostile intermediary in front of the service — could rewrite the document to downgrade `signature_algorithms`, redirect `endpoints`, or substitute `service_did`. Operators SHOULD:

- Serve the discovery document only over HTTPS with HSTS enabled.
- Pin the service's verification key fingerprint out-of-band where this is feasible (for example, in first-party agent distributions).
- Treat any change in the document's `service_did` value with suspicion if observed during the lifetime of an agent.

Future versions of this specification may require the discovery document itself to be signed by the service's DID.

### 12.9 Pseudonym integrity and attestor compromise

The `sub_h` claim (§10.4) shifts a meaningful share of a service's anti-Sybil posture onto the attestor. Two consequences for attestor operators:

- **`K_pseudonym` is a long-lived secret.** Compromise lets an attacker compute `sub_h` for any (principal, `aud`) the attestor has seen, which both deanonymises the pseudonym space and lets the attacker forge attestations whose `sub_h` collides with a legitimate human's. Attestors SHOULD hold `K_pseudonym` in the same protection envelope as JWT signing keys (HSM, cloud KMS, or equivalent) and MUST NOT log or transmit it. Rotating `K_pseudonym` invalidates every downstream service's dedup state and SHOULD be treated as an incident-response action rather than routine hygiene.
- **Principal-record duplication is a Sybil escalation.** An attestor that lets one human create two principal records (e.g., by signing up twice with cosmetically distinct OAuth identities the attestor fails to dedupe) gives that human two distinct `sub_h` values at every service. Attestor operators MUST dedupe principal records on a stable upstream identifier (e.g., the OpenID `sub` returned by the OAuth provider) rather than on user-controlled fields (email, display name).

The agent–principal uniqueness rule (§10.5) is the corresponding constraint on the binding layer: even a well-deduped principal table provides no protection if one principal can co-bind an agent DID with another. Attestors MUST enforce §10.5 in the binding-creation path, not only as a policy document.

`sub_h` is not a Sybil oracle. It tells a service "these requests belong to the same principal at this attestor"; it does not tell the service "this principal is the only one the human controls." Services that need stronger uniqueness SHOULD require a `verification` value with intrinsically scarce backing (e.g., `"payment"`) in addition to using `sub_h`.

---

## 13. Privacy Considerations

### 13.1 Identity portability

A persistent `did:key` is a strong pseudonymous identifier. While it does not encode personal information, it is durable and can be correlated across services if shared. Agents operating on behalf of users SHOULD consider whether to derive per-service keys (Section 3.3).

### 13.2 Owner identity

The `owner.identity` field — and its pre-claim equivalent `pending_recipient` — is private user data. Services MUST NOT expose either value (regardless of recipient type) in any unauthenticated response, including agent-signed responses against `UNCLAIMED` or `INVITED` accounts. Agent-signed `GET /afauth/v1/accounts/me` MUST return only `state == "INVITED"` while a `pending_recipient` exists; it MUST NOT return the pending value itself. Any derived informational fields (such as a service-added `display_email` on a verified `oidc` recipient) MUST be treated with the same confidentiality as the identity itself.

### 13.3 Audit log access

Implementations that maintain an audit log MUST scope access to the owner (post-claim) and the service operator. Agents MUST NOT be granted log access by default; an owner MAY explicitly delegate that access.

### 13.4 Aggregated abuse feeds

If a service participates in a cross-service abuse feed (Section 8.3), it SHOULD ensure that shared records do not allow downstream correlation of an agent's account DID with personal information about its operator.

---

## 14. IANA Considerations

### 14.1 Well-known URI registration

This specification requests registration of `afauth` in the IANA Well-Known URIs registry per [RFC8615]. (Application pending.)

| URI suffix | `afauth` |
|---|---|
| Change controller | AFAuth Protocol editors |
| Specification | This document |
| Status | Provisional |
| Related information | See Section 4 of this document |

### 14.2 HTTP field name registrations

This specification requests registration of the following HTTP field names per [RFC9110]:

| Field name | Status | Reference |
|---|---|---|
| `AFAuth-Attestation` | Provisional | This document, Section 10.2 |

Earlier drafts of this specification reserved an `AFAuth-Account` field; that registration has been withdrawn. The account's DID is carried in the `keyid` parameter of the `Signature-Input` header (see §5.2) and is not duplicated in a separate header.

### 14.3 DID Methods

This specification uses the `did:key` method [W3C-DID-KEY]. No new DID method is introduced.

### 14.4 Authentication scheme registration

This specification requests registration of the following scheme in the IANA "HTTP Authentication Schemes" registry per [RFC9110]:

| Authentication Scheme Name | `AFAuth` |
|---|---|
| Pointer to specification text | This document, §5.7 |
| Status | Provisional |
| Notes | Used only in `WWW-Authenticate` response challenges (§5.7). Request credentials are carried in the `Signature` / `Signature-Input` fields per [RFC9421]; no `Authorization: AFAuth …` request header is defined. |

---

## 15. References

### 15.1 Normative references

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- **[RFC5234]** Crocker, D., Ed., and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008.
- **[RFC5321]** Klensin, J., "Simple Mail Transfer Protocol", RFC 5321, October 2008.
- **[RFC5869]** Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010.
- **[RFC7519]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, May 2015.
- **[RFC7636]** Sakimura, N., Ed., Bradley, J., and N. Agarwal, "Proof Key for Code Exchange by OAuth Public Clients", RFC 7636, September 2015.
- **[RFC8032]** Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- **[RFC8259]** Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017.
- **[RFC8615]** Nottingham, M., "Well-Known Uniform Resource Identifiers (URIs)", RFC 8615, May 2019.
- **[RFC9110]** Fielding, R., Ed., Nottingham, M., Ed., and J. Reschke, Ed., "HTTP Semantics", STD 97, RFC 9110, June 2022.
- **[RFC9421]** Backman, A., Ed., Richer, J., Ed., and M. Sporny, "HTTP Message Signatures", RFC 9421, February 2024.
- **[RFC9530]** Polli, R. and L. Pardue, "Digest Fields", RFC 9530, February 2024.
- **[OIDC-Core]** Sakimura, N., Bradley, J., Jones, M. B., de Medeiros, B., and C. Mortimore, "OpenID Connect Core 1.0", OpenID Foundation, November 2014.
- **[OIDC-Discovery]** Sakimura, N., Bradley, J., Jones, M. B., and E. Jay, "OpenID Connect Discovery 1.0", OpenID Foundation, November 2014.
- **[W3C-DID-CORE]** Sporny, M., Longley, D., Sabadello, M., Reed, D., Steele, O., and C. Allen, "Decentralized Identifiers (DIDs) v1.0", W3C Recommendation, July 2022.
- **[W3C-DID-KEY]** Longley, D., and D. Zagidulin, "The did:key Method v0.7", W3C Community Group Report.
- **[W3C-DID-WEB]** Steele, O., Sporny, M., et al., "did:web Method Specification", W3C Credentials Community Group.
- **[did-key-issue-35]** "Multicodec varint decoding ambiguity in did:key", w3c-ccg/did-method-key issue #35.
- **[WebAuthn-L3]** Bradley, J., Hodges, J. C., Jones, M. B., Kumar, A., Lindemann, R., and Lundberg, E., "Web Authentication: An API for accessing Public Key Credentials — Level 3", W3C Working Draft.
- **[OIDC-MFA]** "Authentication Method Reference Values" registry, IETF; and OpenID Connect's `acr` parameter as defined in OpenID Connect Core 1.0 §2.

### 15.2 Informative references

- **[RFC6979]** Pornin, T., "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)", RFC 6979, August 2013.
- **[NIST-SP-800-63B]** Grassi, P. A., et al., "Digital Identity Guidelines: Authentication and Lifecycle Management", NIST Special Publication 800-63B.
- **[Sudhodanan-Paverd-2022]** Sudhodanan, A. and A. Paverd, "Pre-hijacked accounts: An Empirical Study of Security Failures in User Account Creation on the Web", USENIX Security 2022.
- Microsoft Entra Agent ID overview, Microsoft Learn.
- "Agent2Agent (A2A) Protocol", Linux Foundation / Google.
- "FIDO Agent Payments Protocol", FIDO Alliance.
- "x402: HTTP Payment Required, Internet-Native Payments", Coinbase / x402 Foundation.
- "Verifiable Intent", Mastercard / Google.
- "OAuth 2.0 Extension: On-Behalf-Of User Authorization for AI Agents", `draft-oauth-ai-agents-on-behalf-of-user`, IETF.

---

## Appendix A: State Machine

```
                          signup
                ∅  ────────────────────►  UNCLAIMED  ─── ttl expires ───►  EXPIRED
                                            ▲   │                              ▲
                       invitation           │   │ inviteOwner(email)            │
                       expires              │   ▼                               │
                                            └── INVITED ─── ttl expires ────────┘
                                                  │
                                                  │ human authenticates
                                                  ▼
                                               CLAIMED ──── owner deletes ────►  ARCHIVED
```

Allowed transitions:

| From | To | Trigger |
|---|---|---|
| ∅ | `UNCLAIMED` | signup (implicit or explicit) |
| `UNCLAIMED` | `INVITED` | owner invitation |
| `UNCLAIMED` | `EXPIRED` | unclaimed TTL expiry (only if the service sets `unclaimed_ttl_seconds`, §4.4) |
| `INVITED` | `CLAIMED` | claim completion (human authenticates) |
| `INVITED` | `UNCLAIMED` | invitation TTL expiry, no replacement issued |
| `INVITED` | `EXPIRED` | unclaimed TTL expiry while an invitation is pending (only if the service sets `unclaimed_ttl_seconds`, §4.4) |
| `CLAIMED` | `ARCHIVED` | owner-initiated delete |

Forbidden transitions: any transition not listed above MUST NOT be permitted by a conforming service.

The two transitions to `EXPIRED` occur only when the service opts into an `unclaimed_ttl_seconds` limit (§4.4). Services that do not set a TTL — the default — never enter `EXPIRED`; an `UNCLAIMED` account then remains operable indefinitely unless and until it is claimed.

---

## Appendix B: Worked Examples

### B.1 Implicit signup followed by first operation

An agent generates a fresh keypair, derives `did:key:z6MkpTHR...`, fetches the service's discovery document, and immediately makes a signed request to a protected endpoint. The service creates the account on the fly.

Discovery:

```http
GET /.well-known/afauth HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
Content-Type: application/json

{
  "afauth_version": "0.1",
  "service_did": "did:web:api.example.com",
  "endpoints": {
    "accounts": "/afauth/v1/accounts",
    "owner_invitation": "/afauth/v1/accounts/me/owner-invitation",
    "claim_page": "https://claim.example.com",
    "key_rotation": "/afauth/v1/accounts/me/keys/rotate"
  },
  "signature_algorithms": ["ed25519"],
  "features": ["key_rotation"],
  "billing": { "unclaimed_mode": "free" }
}
```

First signed request:

```http
POST /api/things HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig1=("@method" "@target-uri" "content-digest");\
                 created=1715000000;expires=1715000060;\
                 nonce="9f8b3a7c1d2e4f56";\
                 keyid="did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr";\
                 alg="ed25519"
Signature: sig1=:0123abcde...:

{"name":"hello"}

HTTP/1.1 200 OK
Content-Type: application/json

{"id":"thing_01h...","name":"hello"}
```

The account is now `UNCLAIMED` and discoverable via `GET /afauth/v1/accounts/me`.

### B.2 Owner invitation and claim (email recipient)

The agent invites a human owner by email:

```http
POST /afauth/v1/accounts/me/owner-invitation HTTP/1.1
Host: api.example.com
Content-Type: application/json
[ headers per B.1 with appropriate digest and signature ]

{"recipient":{"type":"email","value":"alice@example.com"}}

HTTP/1.1 202 Accepted

{
  "invitation_id": "inv_01h...",
  "expires_at":    "2026-05-25T12:00:00Z",
  "state":         "INVITED"
}
```

The service emails Alice a magic link such as `https://claim.example.com/claim?t=<token>`. Alice clicks the link, completes the service's human-authentication flow, and the claim page calls:

```http
POST /afauth/v1/claim/<token> HTTP/1.1
Host: api.example.com
Content-Type: application/json
Cookie: session=<alice-session>

HTTP/1.1 200 OK

{
  "account_id": "acct_8f3cZ_K9qWmA...",
  "state":       "CLAIMED",
  "owner": {
    "identity":   { "type": "email", "value": "alice@example.com" },
    "user_id":    "usr_01h...",
    "claimed_at": "2026-05-18T13:42:00Z"
  }
}
```

The agent can continue signing requests with the same key; the account is now in `CLAIMED` state with Alice as the owner.

### B.2.1 Owner invitation and claim (OIDC recipient)

A service that declares `"recipient_types": ["email", "oidc"]` can be invited with a federated identity:

```http
POST /afauth/v1/accounts/me/owner-invitation HTTP/1.1
Host: api.example.com
Content-Type: application/json
[ signed per Section 5 ]

{
  "recipient": {
    "type":  "oidc",
    "value": { "issuer": "https://accounts.google.com", "sub": "103948572345" }
  }
}

HTTP/1.1 202 Accepted

{
  "invitation_id": "inv_01h...",
  "expires_at":    "2026-05-19T20:00:00Z",
  "state":         "INVITED"
}
```

The service's claim page initiates an OIDC Authorization Code flow with Google; on return, the service verifies that the ID Token's `iss` is `https://accounts.google.com` and its `sub` is `103948572345`. If both match, the binding commits:

```json
{
  "account_id": "acct_8f3cZ_K9qWmA...",
  "state":       "CLAIMED",
  "owner": {
    "identity": {
      "type":  "oidc",
      "value": { "issuer": "https://accounts.google.com", "sub": "103948572345" }
    },
    "user_id":    "usr_01h...",
    "claimed_at": "2026-05-19T08:14:00Z"
  }
}
```

The agent never delivered an email; the entire claim ceremony was a federated sign-in.

### B.2.2 Owner invitation and claim (passkey ceremony)

For an AAL2+ deployment (per §12.3), the service can run the claim ceremony entirely as a WebAuthn challenge-response. The invitation is identical in shape; the service's claim page does not send an email — instead it presents a passkey challenge bound to the invitation token.

The service's claim page issues:

```javascript
// Service-side: claim page JavaScript
const credential = await navigator.credentials.get({
  publicKey: {
    challenge: Uint8Array.from(atob(invitationChallenge), c => c.charCodeAt(0)),
    rpId: "claim.example.com",
    allowCredentials: [{
      id: aliceRegisteredCredentialId,  // from prior passkey registration
      type: "public-key",
    }],
    userVerification: "required",
  },
});

await fetch(`/afauth/v1/claim/${claimToken}`, {
  method: "POST",
  credentials: "include",
  body: JSON.stringify({
    webauthn_assertion: {
      id: credential.id,
      clientDataJSON: bytesToBase64(credential.response.clientDataJSON),
      authenticatorData: bytesToBase64(credential.response.authenticatorData),
      signature: bytesToBase64(credential.response.signature),
    },
  }),
});
```

The service verifies the WebAuthn assertion against Alice's previously-registered credential, confirms the `userVerification` flag is set, and matches the credential to Alice's account identity. The §7.7.1 match relation (case-insensitive email equality) is satisfied by the email associated with the verified credential. The §7.1 invariant survives an agent-key compromise because an attacker who steals the agent key cannot complete the passkey ceremony — the credential refuses to sign for any RP ID other than `claim.example.com`, and the UV gesture demands a fresh biometric or PIN on Alice's registered device.

This ceremony is the recommended pattern for any service whose accounts hold meaningful value. See §12.3 for the assurance-level discussion and AFAP-0001 for the motivation.

### B.3 Post-claim agent-initiated key rotation

```http
POST /afauth/v1/accounts/me/keys/rotate HTTP/1.1
Host: api.example.com
Content-Type: application/json
[ signed by OLD key ]

{"new_account_did":"did:key:z6Mk<new>..."}

HTTP/1.1 202 Accepted

{
  "rotation_id":                 "rot_01h...",
  "owner_confirmation_required": true,
  "expires_at":                  "2026-05-25T12:00:00Z"
}
```

The rotation is staged but not committed. The service emails Alice a confirmation link. Alice clicks the link and completes owner-session authentication. The service then commits the rotation; subsequent requests must be signed by the new key. The account state remains `CLAIMED` throughout the rotation flow.

---

## Appendix C: Test Vectors

**Status:** Required for v0.1 conformance. The vectors below are the minimum a v0.1 implementation MUST pass to claim conformance. The full §C.1 through §C.6 corpus (plus the optional §C.7 trust-attestation vectors for §10) now ships under [`../vectors/`](../vectors/), and an executable harness at [`../harness/run.js`](../harness/run.js) verifies every committed vector against a reference verifier.

A reference test-only Ed25519 keypair is published alongside this specification at [`../vectors/keypair.json`](../vectors/keypair.json). The keypair is for protocol testing only and MUST NOT be used in production. The associated `did:key` identifier is:

```
did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr
```

Vectors cover, at minimum, the following categories.

### C.1 Signature canonical input

For each combination of {`GET`, `POST`} × {empty body, JSON body} × the §5.2 covered components, a canonical signature input string is provided byte-exactly. Implementations MUST reproduce these strings before signing or verifying. This is the category most prone to silent divergence between implementations, and the reason byte-exact reference values are necessary.

### C.2 Reference signatures

For each input in §C.1, the expected Ed25519 signature produced by the reference keypair is provided as a hex string. Verifiers MUST accept the provided signature; signers MUST produce it.

### C.3 Discovery documents

Well-formed v0.1 documents (with and without each optional field), documents containing unknown forward-compatible fields (which MUST be accepted, per §4.2), and documents that violate the schema (which MUST be rejected). Each vector carries its expected parse outcome.

### C.4 Recipient values

A canonical normalised value for each recipient type in §7.7 (`email`, `phone`, `oidc`, `did`), including cases that exercise: NFKC normalisation and case folding (`email`), E.164 normalisation (`phone`), issuer-plus-subject concatenation (`oidc`), and DID canonicalisation including any method-specific normalisation (`did`). Implementations MUST produce the canonical value when normalising an input recipient.

### C.5 Error envelopes

For each reserved code in §11.3, an example error body. Implementations producing the corresponding failure MUST emit a body that matches the example modulo informational fields (free-form `message`, `request_id`, etc.).

### C.6 Replay window

Sequence vectors illustrating: rejected expired signatures (`expires` in the past), rejected future-dated signatures (`created` in the future beyond skew), rejected replays within the window, and accepted nonce reuse across distinct `keyid` values (per §5.6).

### C.7 Trust attestations

Vectors exercising verification of `afauth-trust` attestation JWTs (§10): a well-formed attestation, a runtime-only attestation that carries no `sub_h` binding, and malformed cases (missing `sub_h` when `verification` is present, and `sub_h` values that are too short or not `base64url`). Each vector carries the encoded JWT, the issuer JWKS, the verifier inputs, and the expected accept/reject decision. These vectors apply to implementations that consume attestations under the optional §10; the §C.1–§C.6 corpus remains the minimum for the core agent and service roles.

### C.8 Distribution

Vectors are published as machine-readable JSON files under [`../vectors/`](../vectors/) alongside this specification. Each vector file includes a `description`, the input under test, the expected output, and a reference to the section of this specification that it exercises. A minimum-viable conformance harness lives at [`../harness/run.js`](../harness/run.js); it loads every vector, runs the §C.1 and §C.2 checks against a reference verifier, and exits non-zero on any failure. Independent implementations are encouraged to contribute additional vectors via the proposals process.

---

## Appendix D: Design Rationale

This appendix records key design decisions made during v0.1 development.

### D.1 Cross-service portability default

The same `did:key` is reusable across services by default. Per-service derivation is opt-in for agents that require unlinkability. The protocol treats both modes identically. Defaulting to portability simplifies agent UX; the opt-in for derivation preserves user privacy where required.

### D.2 Multi-owner accounts

Not supported in v0.1. Multi-owner ("team") accounts are treated as a layer above the protocol. The wire format does not preclude a future extension that adds `owners: []` semantics.

### D.3 Pre-claim recovery

No pre-set recovery email in v0.1. If an agent loses its private key before claim, the account is irrecoverable. This preserves the sovereignty of the keypair model; key custody is the agent operator's responsibility. The Security Considerations (Section 12.1) RECOMMENDS hardware-backed storage for production deployments.

### D.4 Billing identity pre-claim

Declared, not decided. The protocol takes no position on who pays during the unclaimed window. Services declare their policy in the discovery document via `billing.unclaimed_mode`. This avoids prematurely freezing a billing model into the wire format.

### D.5 Cross-service revocation distribution

Not standardised in v0.1. Each service maintains its own revocation list locally. Aggregated abuse feeds are a layer above the protocol; they do not require wire-format changes to be deployed.

### D.6 Why agents are `did:key`-only (not `did:web`)

Agent account identifiers are `did:key` (§3.1); `did:web` is deliberately NOT an agent account method. Agents typically run on user machines behind home routers, with no stable web origin at which to host a `did.json` document — so a DNS-anchored identity is not usable for the common agent. The consequence — that a `did:key` identifier changes when its key rotates — is handled by owner-driven revoke + re-key (§8.2 / §8.4), not by reaching for a stable-identifier DID method. (`did:web` remains appropriate for a *service's* own `service_did`, which does have a host, and for owner recipients (§7.7.4).)

### D.7 Two-step verify as a normative requirement

The two-step verify (Section 7.1) is the protocol's central security primitive and is therefore a MUST, not a SHOULD. Implementations that allow agent-key-alone ownership binding are not conformant. The intent is to make a stolen-key-redirects-email attack impossible at the protocol level rather than relying on implementer diligence.

### D.8 The `WWW-Authenticate` challenge

A `401` originally carried only an error body (Section 11), readable only by an agent that already knew to attempt AFAuth and to parse AFAuth errors. §5.7 adds a standards-native `WWW-Authenticate` challenge so that a `401` is self-describing: from the response alone an agent with no prior knowledge of the service learns that the resource speaks AFAuth, where its discovery document lives, why the request failed, and — for attestation failures — which attestors can satisfy it. This mirrors the OAuth bearer challenge ([RFC9110] §11) and the way Protected Resource Metadata is advertised on a `401`, adapted to a signature-based, self-sovereign scheme. It is purely additive: status code, error body, and state machine are unchanged; emission is a `SHOULD`, so services predating this section stay conformant; and the challenge is a pointer to discovery, never a copy, so no second source of truth can drift. The change generalizes the recovery loop already defined for attested sessions (§10.7) — challenge, obtain a fresh attestation, retry — to the cold-start, signature-staleness, and revocation cases, so each is recoverable without out-of-band knowledge.

The challenge is deliberately *additive and non-presumptuous*. A `WWW-Authenticate` set is the resource's statement of how to authenticate, so AFAuth must not behave as though it owns every `401`: it is one challenge among possibly several, it never reorders or suppresses another scheme's challenge, and the service decides whether it appears at all. Critically, `error` is set only when the request actually attempted AFAuth — a bare `invalid_signature` from a client using another scheme (or none) becomes a discovery-only advertisement, never a "your AFAuth signature failed" claim. This lets a service offer AFAuth as a secondary or co-equal option without AFAuth conscripting its other clients.

---

## Appendix E: Edge Verification Pattern

This appendix is **non-normative**. It describes a deployment pattern in which the verifier (§5.5) runs as a separate component on the request path — typically an API gateway, edge proxy, or service-mesh sidecar — rather than inside the application code of the service. The wire format is unchanged. The agent's signing behaviour is unchanged. Only the location of verification differs.

### E.1 Pattern

The verifier intercepts the inbound request, performs §5.5 verification, and on success forwards the request to the service with the verified identity exposed as request headers. The service reads the headers and proceeds with business logic. On verification failure, the verifier produces the `401 Unauthorized` response directly — including the `WWW-Authenticate` challenge of §5.7, which it can populate with `discovery` and `error` (and `attestors`, when configured with the accepted set) without consulting the service; the service never sees the request.

### E.2 Recommended upstream headers

A verifier deployed as a separate component SHOULD inject the following headers into the request forwarded to the service:

| Header | Value | Required |
|---|---|---|
| `X-AFAuth-Account` | The verified account DID (the `keyid` from the signature) | RECOMMENDED |
| `X-AFAuth-Auth-Mode` | `signature` — distinguishes from a hypothetical future owner-session injection | RECOMMENDED |
| `X-AFAuth-Verified-At` | RFC 3339 timestamp at which verification succeeded | OPTIONAL |

Standardising the header names lets services swap verifiers (or move between in-app and edge verification) without application-side code changes. The values are not cryptographically signed; the trust model is that the application trusts the verifier across the (typically internal) hop between them.

### E.3 Header stripping (security boundary)

A verifier deployed as a separate component MUST strip any inbound occurrence of the headers it injects (see §E.2) before performing verification. Otherwise an attacker who reaches the verifier can forge identity by setting `X-AFAuth-Account` in the original request. The trust boundary on these headers is "produced by the verifier"; allowing them to pass through from an untrusted source is a critical configuration error.

Services that may also receive requests directly (bypassing the edge verifier) MUST NOT trust these headers on such paths and SHOULD strip them on arrival.

### E.4 Optional service-side key-resolution endpoint

Agent account identifiers are `did:key` (§3.1.1), whose verification key is fully self-describing, so the verifier resolves keys without any I/O to the service — no network fetch, no registry.

A service MAY additionally expose a private endpoint that returns its canonical view of an account's current verification key and status, for use by verifiers that need to consult the service's revocation list (§8.3) without independently mirroring it. A recommended shape:

```http
GET /internal/afauth/keys/{accountDid} HTTP/1.1
Host: <service host>

200 OK
Content-Type: application/json

{
  "account_did":       "did:key:z6Mk...",
  "state":             "CLAIMED",
  "verification_keys": [
    {
      "public_key_multibase": "z6Mk...",
      "active_since":         "2026-05-19T08:14:00Z"
    }
  ],
  "revoked":           false
}

410 Gone     — when the account's keys are revoked (per §8.3)
404 Not Found — when the account is unknown to the service
```

This endpoint is not part of the public AFAuth wire surface; it is an implementation-internal contract between a service and its co-deployed verifier(s). Its URL, authentication, and exact response shape are service-defined; the shape above is offered as a convention to ease portability of verifier implementations across services.

### E.5 Verifier–service split

The verifier provides the verified signer identity; the service provides policy and state. In particular:

- §7.5 owner-binding classification (which operations require an owner session) is a policy decision and is enforced by the service. See §7.5.
- §6.1 account state (`UNCLAIMED`, `INVITED`, `CLAIMED`) is owned by the service.
- §8.3 revocation lists are maintained by the service; verifiers consult them either by mirroring the list or by querying the endpoint of §E.4.
- §11 error codes are emitted by whichever component produces the response; both the verifier and the service emit codes from the §11 vocabulary for the conditions they detect.

### E.6 Conformance

A verifier that runs the steps in §5.5 against the test vectors of Appendix C and produces the same accept/reject outcomes as a reference in-application verifier is conformant with respect to verification. Conformance against the full service-role probes in `conformance.md` requires a complete service deployment; a verifier alone cannot claim service-role conformance.

---

*End of AFAuth Protocol v0.1.*
