# AFAuth Protocol — Core Specification

**Version:** 0.1 (working draft)
**Date:** 2026-05-18
**Status:** Working draft; comments and proposals welcome.
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

An AFAuth account is identified by a Decentralized Identifier ([W3C-DID-CORE]) using the `did:key` method ([W3C-DID-KEY]):

```
did:key:<multibase-multicodec-pubkey>
```

For Ed25519 keys, the encoded form uses the multicodec prefix `0xed01` followed by the 32-byte raw public key, encoded together as a multibase base58btc string. Example:

```
did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoom5bxQbCDuJ3LZTW
```

The account DID is derived entirely from the public key. Services MUST NOT require any central registry lookup to validate an account DID; they MUST validate it locally by decoding the multibase string and using the recovered public key for signature verification.

### 3.2 Key generation

Agents SHOULD generate Ed25519 keypairs using a cryptographically secure pseudorandom number generator. Private keys MUST NOT be transmitted to services; only signatures derived from them.

Implementations are RECOMMENDED to store private keys in OS-level keystores, hardware-backed keystores (TPM, Secure Enclave), or cloud KMS where available. File-based key storage SHOULD use file mode 0600.

### 3.3 Portability and derivation

By default, an agent's `did:key` is reusable across services: the same key authenticates the same agent to multiple services without modification. Conforming services MUST accept this mode.

Agents that require cross-service unlinkability MAY derive a per-service key using a deterministic key-derivation function such as HKDF [RFC5869] over a master key, with the service's DID as the `info` parameter. This is invisible to services; from the service's point of view, the request is signed by an unrelated Ed25519 keypair.

This specification does not mandate either policy. Both modes are permitted.

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
    "key_rotation":     "/afauth/v1/accounts/me/keys/rotate"
  },
  "signature_algorithms": ["ed25519"],
  "features": ["two_step_invite", "attestation", "key_rotation"],
  "limits": {
    "unclaimed_ttl_seconds":         2592000,
    "unclaimed_rate_limit_per_hour": 100
  },
  "billing": {
    "unclaimed_mode": "free",
    "accepted_attestors": ["stripe-projects", "entra-agent-id"]
  }
}
```

### 4.2 Schema

The full JSON Schema is provided alongside this specification at [`../schemas/well-known.json`](../schemas/well-known.json). Implementations MUST treat unknown fields as opaque (forward-compatibility).

### 4.3 Required fields

- `afauth_version` (string): The protocol version this service speaks. For this specification, the value is `"0.1"`.
- `service_did` (string): A DID identifying the service. RECOMMENDED to use `did:web:<host>`; `did:key:...` is also permitted.
- `endpoints` (object): URLs for the protocol's endpoints. Paths MAY be absolute or relative to the discovery document's origin. Members defined in this version: `accounts`, `owner_invitation`, `claim_page`, `key_rotation`.
- `signature_algorithms` (array of strings): Algorithms the service accepts. MUST include `"ed25519"` for conformance.

### 4.4 Optional fields

- `features` (array of strings): Optional features the service supports. Defined values: `"two_step_invite"`, `"attestation"`, `"key_rotation"`. Absent features MUST NOT be assumed supported.
- `limits` (object): Service-declared limits. Defined members: `unclaimed_ttl_seconds`, `unclaimed_rate_limit_per_hour`.
- `billing` (object): Pre-claim billing declaration. See Section 9.

### 4.5 Discovery procedure

Before signup, agents SHOULD fetch and cache the discovery document. Agents MUST honor the `signature_algorithms` advertised; MUST honor the `billing.unclaimed_mode`; and SHOULD respect the rate-limit hints in `limits`.

---

## 5. Request Authentication

### 5.1 HTTP Message Signatures

AFAuth uses HTTP Message Signatures [RFC9421] for all authenticated requests. This avoids inventing a custom signature format and leverages tooling already common in modern systems.

Implementations MUST support the `ed25519` signature algorithm as defined by RFC 9421.

### 5.2 Required signed components

Every AFAuth-authenticated request MUST include the following signed components in its `Signature-Input` header:

| Component | Purpose |
|---|---|
| `@method` | HTTP method |
| `@target-uri` | Full request URI |
| `@authority` | Pins the host (prevents cross-service replay) |
| `content-digest` | SHA-256 of the body, per [RFC9530], for requests with a non-empty body |
| `afauth-account` | The account's DID (lowercase header name) |
| `created` | Signing timestamp, for freshness |
| `nonce` | Unique value to prevent replay |

The signature input string MUST be constructed per the canonicalisation rules of RFC 9421.

### 5.3 Headers

This specification introduces or relies on the following HTTP headers:

- `AFAuth-Account` (introduced): The account's DID. Required on every authenticated request. Lowercased as `afauth-account` when used as a signed component name.
- `AFAuth-Attestation` (introduced, optional): Carries an attestation token, as defined in Section 10.
- `Content-Digest`: As defined by [RFC9530]. Required for requests with non-empty bodies.
- `Signature-Input`, `Signature`: As defined by [RFC9421].

### 5.4 Example

```http
POST /afauth/v1/accounts/me/owner-invitation HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
AFAuth-Account: did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoom5bxQbCDuJ3LZTW
Signature-Input: sig1=("@method" "@target-uri" "@authority" \
                       "content-digest" "afauth-account");\
                 created=1715000000;nonce="9f8b3a7c1d2e4f56";\
                 keyid="did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoom5bxQbCDuJ3LZTW";\
                 alg="ed25519"
Signature: sig1=:0123abcde...:

{"email":"alice@example.com"}
```

### 5.5 Verification procedure

On receiving a signed request, a service MUST:

1. Parse the `Signature-Input` header and verify that all required components (Section 5.2) are listed.
2. Construct the canonical signature input string per RFC 9421.
3. Decode the public key from the `keyid` (which MUST equal the `AFAuth-Account` DID).
4. Verify the signature using the algorithm declared in `alg`.
5. Verify that `created` is within an acceptable freshness window (RECOMMENDED: 60 seconds).
6. Verify that the `nonce` has not been seen before for this account within the freshness window.
7. If the request has a non-empty body, verify the `Content-Digest` matches a SHA-256 hash of the actual body.

If any step fails, the service MUST respond with `401 Unauthorized` and SHOULD include an error body (Section 11) indicating the failure reason.

### 5.6 Replay protection

Services MUST maintain a sliding window of seen `(account_did, nonce)` tuples covering at least the freshness window. Storage cost is bounded by `unclaimed_rate_limit_per_hour` (Section 4.4).

Services MAY accept signed requests outside the freshness window for non-mutating `GET` operations, at their discretion, but MUST NOT accept replayed mutating requests.

---

## 6. Account Lifecycle

### 6.1 Account states

An account is in exactly one state at any time. Conforming services MUST implement the following states:

| State | Description |
|---|---|
| `UNCLAIMED` | Account exists; no owner is bound. Created by signup. |
| `INVITED` | An owner invitation has been sent; not yet claimed. |
| `CLAIMED` | Account is bound to an owner via the claim flow. |
| `EXPIRED` | Account exceeded `unclaimed_ttl_seconds` without being claimed; no longer operable. |
| `ARCHIVED` | Account explicitly deleted by the owner; retained for audit/compliance. |

### 6.2 State transitions

See Appendix A for the diagram. Conforming services MUST NOT permit transitions other than those defined.

### 6.3 Implicit signup

The first valid signed request from an unrecognised account DID MUST cause the service to create the account in state `UNCLAIMED`, unless the service requires explicit signup (Section 6.4).

This mode optimizes for agent ergonomics: an agent that has just generated a keypair can call any protected endpoint and have its account auto-created. The service MUST NOT distinguish externally between "implicit signup followed by operation" and a request to a pre-existing account.

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
  "account_did":          "did:key:z6Mk...",
  "state":                "UNCLAIMED",
  "created_at":           "2026-05-18T12:00:00Z",
  "unclaimed_expires_at": "2026-06-17T12:00:00Z"
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
  "account_did":          "did:key:z6Mk...",
  "state":                "UNCLAIMED",
  "created_at":           "2026-05-18T12:00:00Z",
  "unclaimed_expires_at": "2026-06-17T12:00:00Z",
  "owner":                null
}
```

When `state` is `CLAIMED`, the `owner` field MUST be populated:

```json
"owner": {
  "email":      "alice@example.com",
  "user_id":    "usr_01h...",
  "claimed_at": "2026-05-18T13:42:00Z"
}
```

When `state` is `INVITED`, the `owner` field MUST remain `null`. Services MUST NOT expose the pending invitation email through agent-signed responses; see Section 13.2.

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
  "email":        "alice@example.com",
  "redirect_url": "https://yourapp.com/welcome"
}
```

Field semantics:

- `email` (string, required): The email address to invite. MUST be a syntactically valid mailbox per [RFC5321].
- `redirect_url` (string, optional): URL to redirect to after successful claim. Services SHOULD validate it against an allow-list and MUST NOT honour redirects to untrusted hosts.

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

The service MUST send a magic-link email to the invited address. The magic link MUST contain a single-use, unguessable token bound to the invitation. The service MUST transition state to `INVITED` immediately; `pending_email` MUST be stored separately from any committed `owner_email` field.

If the invitation expires without a successful claim, the service MUST transition the account back to `UNCLAIMED` and discard the pending email.

### 7.3 Invitation TTL

The default invitation TTL is 7 days. Services MAY configure a shorter TTL but MUST NOT exceed 14 days.

Multiple invitations for the same account are permitted, but the most recent invitation supersedes any prior pending one; older invitations MUST be invalidated.

### 7.4 Claim completion

The human follows the magic link to the service's hosted claim page (`endpoints.claim_page` from discovery). After completing whatever human-authentication flow the service offers (magic link, passkey, OAuth), the page calls:

```http
POST /afauth/v1/claim/<token> HTTP/1.1
Host: api.example.com
Content-Type: application/json
Cookie: session=<human session>
```

Response on success:

```json
{
  "account_did": "did:key:z6Mk...",
  "state":       "CLAIMED",
  "owner": {
    "email":      "alice@example.com",
    "user_id":    "usr_01h...",
    "claimed_at": "2026-05-18T13:42:00Z"
  }
}
```

Only at this moment does the account transition to `CLAIMED`. The service MUST:

- Persist `owner_email = pending_email` and clear the pending field.
- Issue any post-claim session credentials (cookie, JWT, etc.) per the service's authentication system.
- OPTIONALLY fire a webhook to inform the service backend of the claim event.

### 7.5 Authority model post-claim

After an account is `CLAIMED`, the agent's key continues to authorize operations on behalf of the owner. Specifically:

- The agent key MUST continue to authenticate ordinary requests (the operations the service exposes for agents).
- Operations that **change ownership** (e.g., updating `owner_email`, transferring the account to another user, deleting the account) MUST require a fresh **owner session**, NOT the agent's signature.

This split is normative: a service that allows agent-key-alone ownership changes after claim is NOT conformant with v0.1.

### 7.6 Agent-driven re-invitation

In `CLAIMED` state, the agent MAY initiate a new invitation only if the existing owner explicitly authorises it (e.g., via an owner-session-authenticated endpoint defined by the service). This specification does not standardise the owner-side workflow; services MAY define their own.

---

## 8. Key Management

### 8.1 Pre-claim key rotation

While the account is in `UNCLAIMED` or `INVITED` state, an agent MAY rotate its key by signing a rotation request with the old key:

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
  "account_did":    "did:key:z6Mk<new>...",
  "old_revoked_at": "2026-05-18T14:00:00Z"
}
```

The account DID becomes the new value. The old key is added to the revocation list (Section 8.3) and MUST be rejected on future requests.

### 8.2 Post-claim key rotation

After claim, rotation MUST require owner approval. Two flavours are defined:

**Agent-initiated.** The agent signs a rotation request with the old key. The service emails a confirmation link to the owner. The rotation completes only after the owner clicks the link and authenticates with an owner session.

**Owner-initiated.** The owner rotates from their dashboard. A fresh public key is supplied through a side-channel (e.g. the owner pastes a new DID into a form) or via a service-defined bootstrap protocol.

In both cases, the service MUST require an owner-authenticated session step before the rotation takes effect.

### 8.3 Revocation

Each service MUST maintain a local revocation list of account DIDs whose keys have been retired (through rotation or owner-initiated revocation). Requests signed by a revoked key MUST be rejected with `401 Unauthorized` and the error code `revoked_key` (Section 11).

Cross-service revocation distribution is NOT part of this specification. Services MAY publish their revocation lists as part of an aggregated abuse feed (e.g., through a centralised network operator), but no inter-service revocation transport is mandated.

### 8.4 Owner-initiated revocation

The owner of a `CLAIMED` account MAY revoke the agent's key entirely without rotating. This effectively pauses the agent. Subsequent requests signed by the revoked key MUST return `401 Unauthorized`. The owner MAY later restore service by uploading a new agent key (per Section 8.2).

---

## 9. Billing Declaration

### 9.1 Pre-claim billing modes

Services declare their pre-claim billing policy in the discovery document (`billing.unclaimed_mode`). The protocol takes no position on who pays during the unclaimed window; it provides a vocabulary for services to declare their stance:

- `"free"`: The service absorbs unclaimed usage (free tier, trial, or post-paid against the eventual claimer).
- `"attested_only"`: The service accepts unclaimed signups only when an accepted attestor (Section 10) vouches for a billable operator.
- `"denied"`: Paid features are gated behind a claim; unclaimed accounts have read-only or sandboxed access.

Conforming services MUST honour their declared mode. Agents MUST read the discovery document before signing up to determine whether to provide an attestation.

### 9.2 Attestation requirement

If `unclaimed_mode` is `"attested_only"`, the service MUST reject signup requests that lack an `AFAuth-Attestation` header. The error response (Section 11) SHOULD identify the required attestation type via the `details` field.

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
- Other claims are attestor-specific.

### 10.3 Recognized attestors

This specification reserves three classes of attestor identifier:

- **Platform attestors**: `microsoft-entra-agent-id`, `google-cloud-agent-identity`, `aws-iam-agent`.
- **Commerce attestors**: `fido-agent-payments`, `mastercard-verifiable-intent`, `stripe-projects`.
- **Service-operator HMAC**: For first-party agents, services MAY accept tokens signed with a shared symmetric key under an identifier they define.

The set of accepted attestors is declared per-service in `billing.accepted_attestors`. Conforming services MUST validate the attestation against the attestor's published verification key (for asymmetric attestors) or shared secret (for HMAC attestors).

### 10.4 Attestation lifetime

Attestations MUST be presented on a per-request basis. Services MUST NOT cache attestations beyond the JWT's `exp`. Attestations carry no state of their own; they are an additional gate on the signed request.

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
| `401 Unauthorized` | Signature verification failed, key revoked, or attestation invalid |
| `403 Forbidden` | Operation not permitted in the current state (e.g., agent-initiated ownership change post-claim) |
| `404 Not Found` | Account does not exist (only when implicit signup is disabled) |
| `409 Conflict` | State conflict (e.g., account already CLAIMED, key already revoked) |
| `410 Gone` | Account is EXPIRED or invitation has expired |
| `429 Too Many Requests` | Rate limit exceeded |
| `503 Service Unavailable` | Service temporarily unable to process AFAuth requests |

### 11.3 Reserved error codes

Conforming services MUST use these codes when the corresponding condition applies:

`invalid_signature`, `expired_signature`, `replayed_nonce`, `unknown_account`, `revoked_key`, `invalid_attestation`, `attestation_required`, `invitation_expired`, `invitation_not_found`, `already_claimed`, `not_claimed`, `owner_authentication_required`, `account_expired`, `rate_limit_exceeded`, `malformed_request`.

Services MAY define additional error codes for service-specific conditions, but SHOULD prefix them with a service-specific namespace (e.g., `example_quota_exceeded`).

---

## 12. Security Considerations

### 12.1 Key compromise

The agent's private key is the sole credential for pre-claim operations. Implementations SHOULD use OS-level keystores, hardware-backed keystores (TPM, Secure Enclave), or cloud KMS where available.

If a key is compromised pre-claim, an attacker holding it can invite their own email as the owner and complete the claim. The legitimate operator has no in-protocol remedy other than abandoning the account. Operators of high-value agents SHOULD therefore not rely on file-based keys.

### 12.2 Replay

The combined use of `created`, `nonce`, and `@authority` in signed components binds each signed request to a specific service, time window, and unique value. The freshness-window and seen-nonce mechanism (Section 5.6) prevents replay within the window. Services MUST NOT relax the nonce check for mutating requests.

### 12.3 Phishing in the claim flow

The magic-link claim flow is vulnerable to ordinary email phishing (an attacker tricks the recipient into forwarding the link). Services SHOULD:

- Display a summary of agent activity on the claim page before completing the bind, so the human can recognise an unfamiliar context.
- Use short invitation TTLs (default 7 days; lower MAY be appropriate for sensitive services).
- Require an additional human factor (passkey, OAuth) on the claim page beyond clicking the magic link.

### 12.4 Cross-service correlation

Because an account DID is by default reusable across services, services can collude to correlate the same agent's activity. Agents that require unlinkability MUST use per-service key derivation (Section 3.3). Services MUST NOT publish account DIDs in ways that would aid correlation by third parties.

### 12.5 Attestation forgery

Services that accept agent attestations MUST validate the attestor's signature against an authoritative key source. Stale verification keys can permit forged attestations to pass. Services SHOULD pin attestor verification keys and refresh them on a documented schedule.

### 12.6 Email channel security

Magic-link emails transit through email infrastructure not controlled by the service. Services MUST use HTTPS for the magic link URL itself and SHOULD NOT include sensitive account context in the email body. Confirmation links MUST be single-use and bound to the originating invitation.

---

## 13. Privacy Considerations

### 13.1 Identity portability

A persistent `did:key` is a strong pseudonymous identifier. While it does not encode personal information, it is durable and can be correlated across services if shared. Agents operating on behalf of users SHOULD consider whether to derive per-service keys (Section 3.3).

### 13.2 Owner email

The `owner_email` field is private user data. Services MUST NOT expose `owner_email` (or its pre-claim equivalent `pending_email`) in any unauthenticated response, including agent-signed responses against `UNCLAIMED` or `INVITED` accounts. Agent-signed `GET /afauth/v1/accounts/me` MUST return only `state == "INVITED"` while a pending email exists; it MUST NOT return the pending address itself.

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
| `AFAuth-Account` | Provisional | This document, Section 5.3 |
| `AFAuth-Attestation` | Provisional | This document, Section 10.2 |

### 14.3 DID Methods

This specification uses the `did:key` method [W3C-DID-KEY]. No new DID method is introduced.

---

## 15. References

### 15.1 Normative references

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- **[RFC5234]** Crocker, D., Ed., and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008.
- **[RFC5321]** Klensin, J., "Simple Mail Transfer Protocol", RFC 5321, October 2008.
- **[RFC5869]** Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010.
- **[RFC7519]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, May 2015.
- **[RFC8032]** Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- **[RFC8259]** Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017.
- **[RFC8615]** Nottingham, M., "Well-Known Uniform Resource Identifiers (URIs)", RFC 8615, May 2019.
- **[RFC9110]** Fielding, R., Ed., Nottingham, M., Ed., and J. Reschke, Ed., "HTTP Semantics", STD 97, RFC 9110, June 2022.
- **[RFC9421]** Backman, A., Ed., Richer, J., Ed., and M. Sporny, "HTTP Message Signatures", RFC 9421, February 2024.
- **[RFC9530]** Polli, R. and L. Pardue, "Digest Fields", RFC 9530, February 2024.
- **[W3C-DID-CORE]** Sporny, M., Longley, D., Sabadello, M., Reed, D., Steele, O., and C. Allen, "Decentralized Identifiers (DIDs) v1.0", W3C Recommendation, July 2022.
- **[W3C-DID-KEY]** Longley, D., and D. Zagidulin, "The did:key Method v0.7", W3C Community Group Report.

### 15.2 Informative references

- **[RFC6979]** Pornin, T., "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)", RFC 6979, August 2013.
- Microsoft Entra Agent ID overview, Microsoft Learn.
- "Agent2Agent (A2A) Protocol", Linux Foundation / Google.
- "FIDO Agent Payments Protocol", FIDO Alliance.
- "x402: HTTP Payment Required, Internet-Native Payments", Coinbase / x402 Foundation.
- "Verifiable Intent", Mastercard / Google.

---

## Appendix A: State Machine

```
                          signup
                ∅  ────────────────────►  UNCLAIMED  ─── ttl expires ───►  EXPIRED
                                            ▲   │
                       invitation           │   │ inviteOwner(email)
                       expires              │   ▼
                                            └── INVITED
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
| `UNCLAIMED` | `EXPIRED` | TTL expiry |
| `INVITED` | `CLAIMED` | claim completion (human authenticates) |
| `INVITED` | `UNCLAIMED` | invitation expiry |
| `CLAIMED` | `ARCHIVED` | owner-initiated delete |

Forbidden transitions: any transition not listed above MUST NOT be permitted by a conforming service.

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
  "features": ["two_step_invite", "key_rotation"],
  "billing": { "unclaimed_mode": "free" }
}
```

First signed request:

```http
POST /api/things HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
AFAuth-Account: did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoom5bxQbCDuJ3LZTW
Signature-Input: sig1=("@method" "@target-uri" "@authority" \
                       "content-digest" "afauth-account");\
                 created=1715000000;nonce="9f8b3a7c1d2e4f56";\
                 keyid="did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoom5bxQbCDuJ3LZTW";\
                 alg="ed25519"
Signature: sig1=:0123abcde...:

{"name":"hello"}

HTTP/1.1 200 OK
Content-Type: application/json

{"id":"thing_01h...","name":"hello"}
```

The account is now `UNCLAIMED` and discoverable via `GET /afauth/v1/accounts/me`.

### B.2 Owner invitation and claim

The agent invites a human owner:

```http
POST /afauth/v1/accounts/me/owner-invitation HTTP/1.1
Host: api.example.com
Content-Type: application/json
[ headers per B.1 with appropriate digest and signature ]

{"email":"alice@example.com"}

HTTP/1.1 202 Accepted

{
  "invitation_id": "inv_01h...",
  "expires_at": "2026-05-25T12:00:00Z",
  "state": "INVITED"
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
  "account_did": "did:key:z6MkpTHR...",
  "state": "CLAIMED",
  "owner": {
    "email": "alice@example.com",
    "user_id": "usr_01h...",
    "claimed_at": "2026-05-18T13:42:00Z"
  }
}
```

The agent can continue signing requests with the same key; the account is now in `CLAIMED` state with Alice as the owner.

### B.3 Post-claim agent-initiated key rotation

```http
POST /afauth/v1/accounts/me/keys/rotate HTTP/1.1
Host: api.example.com
Content-Type: application/json
[ signed by OLD key ]

{"new_account_did":"did:key:z6Mk<new>..."}

HTTP/1.1 202 Accepted

{
  "rotation_id": "rot_01h...",
  "state": "PENDING_OWNER_APPROVAL",
  "expires_at": "2026-05-25T12:00:00Z"
}
```

The service emails Alice a confirmation link. Alice clicks the link and completes owner-session authentication. The service then commits the rotation; subsequent requests must be signed by the new key.

---

## Appendix C: Test Vectors

*To be provided in a future revision. Test vectors will include:*

- Canonical signature input strings for representative requests, with byte-exact reference values.
- Expected Ed25519 signatures for a published reference keypair (test-only; never use in production).
- Discovery-document parsing test cases (well-formed, malformed, forward-compatible unknown fields).
- Error-response shapes for representative failure modes.

Submitters of independent implementations are encouraged to contribute test vectors via the proposals process.

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

### D.6 Service-bound accounts

Portable accounts only in v0.1. A `did:web` variant for service-bound accounts may be considered in future versions if billing or legal use cases warrant it. The `service_did` field in the discovery document is itself encouraged to use `did:web`, which is a useful precedent.

### D.7 Two-step verify as a normative requirement

The two-step verify (Section 7.1) is the protocol's central security primitive and is therefore a MUST, not a SHOULD. Implementations that allow agent-key-alone ownership binding are not conformant. The intent is to make a stolen-key-redirects-email attack impossible at the protocol level rather than relying on implementer diligence.

---

*End of AFAuth Protocol v0.1 working draft.*
