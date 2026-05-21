// AFAuth TypeScript SDK v0.1 — API sketch.
//
// This file is a design artefact, NOT a working type definition. It documents
// the public surface that the SDK exposes across four packages at v0.1.
// Types are intentionally minimal: exhaustive overloads, brand types, and
// JSDoc citations to the spec come later, alongside the implementation.
//
// Reading order: core → agent → server → worker. Each section is one npm
// package, published independently under the `@afauth` scope from
// AFAuthHQ/typescript-sdk's pnpm workspace.
//
// SPDX-License-Identifier: MIT

// ============================================================
// @afauth/core
// ============================================================
declare module '@afauth/core' {
  // ---------- Identifiers (§3) ----------

  /** A W3C DID. v0.1 supports `did:key:...` only; `did:web:...` recognised in types. */
  export type Did = string;

  /** Raw 32-byte Ed25519 public key. */
  export type Ed25519PublicKey = Uint8Array;

  /** Raw 32-byte Ed25519 seed (private key material). */
  export type Ed25519PrivateKey = Uint8Array;

  // ---------- did:key codec (§3.1.1) ----------

  /** Encode a 32-byte Ed25519 public key as `did:key:z6Mk...`. */
  export function encodeDidKey(publicKey: Ed25519PublicKey): Did;

  /** Decode a `did:key:z...` to its 32-byte Ed25519 public key. Throws on non-canonical input. */
  export function decodeDidKey(did: Did): Ed25519PublicKey;

  // ---------- Recipient registry (§7.7) ----------

  export type Recipient =
    | { type: 'email'; value: string }                         // §7.7.1 — NFKC + lowercased
    | { type: 'phone'; value: string }                         // §7.7.2 — E.164, no extensions
    | { type: 'oidc';  issuer: string; subject: string }       // §7.7.3 — issuer opaque
    | { type: 'did';   value: Did };                           // §7.7.4 — canonical form

  // ---------- Signature parameters (§5.2) ----------

  export interface SignatureParams {
    /** Unix seconds. Signature creation time. */
    created: number;
    /** Unix seconds. Signature expiry — `expires - created` SHOULD be ≤ 300. */
    expires: number;
    /** ≥128 bits of entropy, hex or base64url. */
    nonce: string;
    /** The signer's DID. Must match the verification key the verifier resolves. */
    keyid: Did;
    /** Only `'ed25519'` in v0.1. */
    alg: 'ed25519';
  }

  export type CoveredComponent = '@method' | '@target-uri' | 'content-digest';

  // ---------- Canonicalisation (§5.2) ----------

  export interface CanonicalRequest {
    method: string;
    /** Absolute URL. */
    targetUri: string;
    /** `'sha-256=:<base64>:'` or undefined for no-body requests. */
    contentDigest?: string;
  }

  /** Builds the RFC 9421 canonical signature input — byte-exact, no trailing newline. */
  export function buildCanonicalInput(
    req: CanonicalRequest,
    params: SignatureParams,
    covered: readonly CoveredComponent[],
  ): string;

  /** Computes `'sha-256=:<base64>:'` per RFC 9530 §2. */
  export function sha256ContentDigest(body: string | Uint8Array): string;

  // ---------- Error envelope (§11) ----------

  export type AFAuthErrorCode =
    | 'invalid_signature' | 'expired_signature' | 'replayed_nonce'
    | 'unknown_account' | 'revoked_key' | 'invalid_attestation'
    | 'attestation_required' | 'invitation_expired' | 'invitation_not_found'
    | 'already_claimed' | 'not_claimed' | 'owner_authentication_required'
    | 'owner_binding_blocked' | 'account_expired' | 'rate_limit_exceeded'
    | 'malformed_request' | 'unsupported_recipient_type';

  export class AFAuthError extends Error {
    readonly code: AFAuthErrorCode;
    /** HTTP status code per §11.2. */
    readonly status: number;
    readonly details?: unknown;
    /** Serialises to a §11.1 error envelope Response. */
    toResponse(): Response;
  }
}

// ============================================================
// @afauth/agent
// ============================================================
declare module '@afauth/agent' {
  import type {
    Did, Recipient, Ed25519PublicKey, Ed25519PrivateKey, CoveredComponent,
  } from '@afauth/core';

  /** A complete request ready to `fetch()` — headers carry the AFAuth signature. */
  export interface SignedRequest {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: string | null;
  }

  export interface SignOptions {
    /** Default: 60. Total signature lifetime (`expires - created`). */
    expiresInSeconds?: number;
    /** Default: 16 random bytes as hex. */
    nonce?: string;
    /** Default: `['@method','@target-uri']` for GET, plus `'content-digest'` when body is present. */
    coveredComponents?: readonly CoveredComponent[];
  }

  export class Agent {
    readonly did: Did;
    readonly publicKey: Ed25519PublicKey;

    /** Fresh random keypair. */
    static generate(): Promise<Agent>;
    /** Restore from a 32-byte private key. */
    static fromPrivateKey(privateKey: Ed25519PrivateKey): Promise<Agent>;

    /**
     * Lower-level escape hatch: sign any AFAuth request. Defaults match
     * the spec, so callers normally pass no `opts`:
     *   - coveredComponents:  ['@method','@target-uri'] when body is absent,
     *                         plus 'content-digest' when body is present.
     *   - expiresInSeconds:   60
     *   - nonce:              16 random bytes, hex
     *
     * Override only for testing or to support v0.2+ endpoints not yet
     * covered by a builder. The protocol-aware builders below are the
     * primary path. See `implementation/adr/0004-sdk-api-shape.md`.
     */
    signRequest(
      req: { method: string; url: string; body?: string | null },
      opts?: SignOptions,
    ): Promise<SignedRequest>;

    // ----- High-level builders for protocol endpoints (§5.4 example, §7.2, §7.4, §8.1) -----

    buildOwnerInvitation(opts: {
      baseUrl: string;
      recipient: Recipient;
      redirectUrl?: string;
    }): Promise<SignedRequest>;

    buildKeyRotation(opts: {
      baseUrl: string;
      newDid: Did;
    }): Promise<SignedRequest>;

    buildAccountIntrospection(opts: {
      baseUrl: string;
    }): Promise<SignedRequest>;
  }

  // ---------- Discovery (§4) ----------

  export interface DiscoveryDocument {
    afauth_version: '0.1';
    service_did: Did;
    endpoints: {
      accounts: string;
      owner_invitation: string;
      claim_page: string;
      claim_completion: string;
      key_rotation?: string;
    };
    signature_algorithms: readonly 'ed25519'[];
    features?: readonly ('attestation' | 'key_rotation')[];
    recipient_types?: readonly ('email' | 'phone' | 'oidc' | 'did')[];
    limits?: {
      unclaimed_ttl_seconds?: number;
      unclaimed_rate_limit_per_hour?: number;
    };
    billing?: {
      unclaimed_mode?: string;
      accepted_attestors?: readonly string[];
    };
  }

  /** Unsigned GET of `/.well-known/afauth`. Validates `afauth_version === '0.1'`. */
  export function fetchDiscovery(baseUrl: string): Promise<DiscoveryDocument>;
}

// ============================================================
// @afauth/server
// ============================================================
declare module '@afauth/server' {
  import type { Did, Recipient, AFAuthError } from '@afauth/core';
  import type { DiscoveryDocument } from '@afauth/agent';

  // ---------- Nonce store (§5.6) ----------

  export interface NonceStore {
    /**
     * Inserts (keyid, nonce). Returns `true` if it was new, `false` if a replay.
     * Implementations MUST enforce a TTL ≥ `(expires - created) + clockSkew`.
     */
    seen(keyid: Did, nonce: string, ttlSeconds: number): Promise<boolean>;
  }

  /** Single-process Map-backed nonce store. Suitable for tests. */
  export class MemoryNonceStore implements NonceStore {
    seen(keyid: Did, nonce: string, ttlSeconds: number): Promise<boolean>;
  }

  // ---------- Account store (§6) ----------

  export type AccountState = 'UNCLAIMED' | 'INVITED' | 'CLAIMED' | 'EXPIRED';

  export interface Account {
    did: Did;
    state: AccountState;
    pendingRecipient?: Recipient;
    owner?: { identity: Recipient; userId: string; claimedAt: string };
    revoked?: boolean;
  }

  /**
   * Storage contract for AFAuth accounts. Mutations are exposed as named
   * methods rather than a generic upsert — each carries the atomicity
   * contract required by the spec section it implements. Adding a new
   * mutation is intentionally a deliberate interface change. See
   * `implementation/adr/0004-sdk-api-shape.md`.
   */
  export interface AccountStore {
    get(did: Did): Promise<Account | null>;

    /**
     * Read-only lookup by pending invitation token. Returns the account
     * iff the token is currently associated with a pending invitation
     * that has not yet expired. Returns `null` for missing, expired,
     * or already-consumed tokens.
     *
     * Used by `Server.handleClaimCompletion` to inspect
     * `pendingRecipient` and apply the §7.7 match relation before
     * calling the atomic `completeClaimByToken`. The atomicity
     * guarantee of `completeClaimByToken` is preserved: if the token
     * is consumed between this read and the commit, the commit
     * returns `null` and the handler reports `invitation_expired`.
     */
    findByPendingToken(token: string): Promise<Account | null>;

    /** Implicit signup (§6.3). Idempotent; returning an existing account is fine. */
    createUnclaimed(did: Did): Promise<Account>;

    /**
     * §7.3 atomic invitation: invalidates any prior pending invitation,
     * installs new pending_recipient + token + TTL. Implementation MUST
     * enforce single-invitation-at-a-time at the storage layer (unique
     * constraint, conditional put, or serialised update path).
     */
    setPendingInvitation(
      did: Did, recipient: Recipient, token: string, expiresAt: string,
    ): Promise<Account>;

    /**
     * §7.4 atomic claim: finds by token, verifies the token is unconsumed
     * and unexpired, transitions to CLAIMED, persists owner, clears pending.
     * Returns null if the token was missing, expired, or already consumed.
     */
    completeClaimByToken(
      token: string, owner: NonNullable<Account['owner']>,
    ): Promise<Account | null>;

    /** §8.1 / §8.2 atomic key rotation. */
    rotateKey(oldDid: Did, newDid: Did, rotatedAt: string): Promise<Account>;

    /** §8.4 atomic owner-initiated revocation. */
    revoke(did: Did, revokedAt: string): Promise<Account>;
  }

  // ---------- Recipient handlers (§7.7) ----------

  export interface RecipientHandler<R extends Recipient = Recipient> {
    /** Begin the verification ceremony — typically send an email, SMS, redirect, etc. */
    initiate(opts: {
      recipient: R;
      claimToken: string;
      claimPageUrl: string;
      redirectUrl?: string;
    }): Promise<void>;
    /** Apply the §7.7 match relation between the pending and authenticated recipient. */
    matches(opts: { pending: R; authenticated: R }): boolean;
  }

  // ---------- Revocation list (§8.3) ----------

  export interface RevocationList {
    /** Returns true iff `did` has been revoked (via rotation or §8.4). */
    isRevoked(did: Did): Promise<boolean>;
    /** Atomically mark `did` as revoked with the given timestamp. */
    add(did: Did, revokedAt: string): Promise<void>;
  }

  /** In-memory `RevocationList`. Suitable for tests and small examples. */
  export class MemoryRevocationList implements RevocationList {
    isRevoked(did: Did): Promise<boolean>;
    add(did: Did, revokedAt: string): Promise<void>;
  }

  // ---------- Verifier (§5.5) ----------

  export interface VerifierOptions {
    nonceStore: NonceStore;
    serviceDid: Did;
    /** Default: 5. */
    clockSkewSeconds?: number;
    /** Default: 300. Max allowed `expires - created`. */
    maxSignatureLifetimeSeconds?: number;
    /**
     * Optional. When supplied, the Verifier rejects requests signed
     * by a revoked DID with `401 revoked_key`. When omitted, the
     * Verifier skips the revocation check — useful for unit tests
     * that don't care about §8.3.
     */
    revocationList?: RevocationList;
  }

  export interface VerifiedRequest {
    agentDid: Did;
    method: string;
    url: string;
    body: string | null;
  }

  /**
   * Standalone request verifier. Useful as an edge plugin (Appendix E)
   * or as the front half of a `Server`.
   */
  export class Verifier {
    constructor(opts: VerifierOptions);
    /** Throws `AFAuthError` on any §5.5/§5.6 failure. Does not enforce §7.5. */
    verify(req: {
      method: string;
      url: string;
      headers: Headers;
      body: string | null;
    }): Promise<VerifiedRequest>;
  }

  // ---------- Server (full endpoint handlers) ----------

  export interface ServerOptions extends VerifierOptions {
    accounts: AccountStore;
    recipients: Partial<Record<'email' | 'phone' | 'oidc' | 'did', RecipientHandler>>;
    /** Either a static discovery doc or a builder that resolves at request time. */
    discovery: DiscoveryDocument | (() => Promise<DiscoveryDocument>);
    /** Used to compose `endpoints.claim_completion` URLs. */
    baseUrl: string;
  }

  /**
   * Owner-session shape passed into `handleClaimCompletion`. The application
   * supplies this — typically extracted from a cookie + IdP-issued session.
   */
  export interface OwnerSession {
    authenticated: Recipient;
    userId: string;
  }

  export class Server {
    constructor(opts: ServerOptions);

    handleDiscovery(req: Request): Promise<Response>;
    handleOwnerInvitation(req: Request): Promise<Response>;
    handleClaimCompletion(req: Request, session: OwnerSession): Promise<Response>;
    /**
     * Pre-claim key rotation (§8.1). Post-claim rotation (§8.2)
     * requires owner confirmation and is out of v0.1 scope; calls on
     * a CLAIMED account return `403 owner_authentication_required`.
     */
    handleKeyRotation(req: Request): Promise<Response>;
    handleAccountIntrospection(req: Request): Promise<Response>;

    /**
     * §8.4 owner-initiated revocation. Service calls this from its
     * own owner-authenticated dashboard route (not from a signed
     * AFAuth endpoint). Marks the account revoked and adds the DID
     * to the configured `RevocationList`.
     */
    revoke(did: Did): Promise<void>;
  }
}

// ============================================================
// @afauth/worker
// ============================================================
declare module '@afauth/worker' {
  import type { ServerOptions, NonceStore, OwnerSession, RevocationList } from '@afauth/server';

  export interface WorkerOptions extends ServerOptions {
    /**
     * Required. Bridges the Worker's uniform routing to the §7.4
     * claim-completion asymmetry — only that endpoint depends on a
     * human-authenticated session, all others ride agent signatures.
     * Return `null` to reject with `401 owner_authentication_required`.
     * See `implementation/adr/0004-sdk-api-shape.md`.
     */
    extractOwnerSession: (req: Request) => Promise<OwnerSession | null>;
  }

  /** Cloudflare Worker handler. Routes the five AFAuth endpoints; 404 otherwise. */
  export function createWorker(opts: WorkerOptions): ExportedHandler;

  /** Cloudflare KV–backed nonce store; uses KV TTL for §5.6 expiry. */
  export class KvNonceStore implements NonceStore {
    constructor(namespace: KVNamespace);
    seen(keyid: string, nonce: string, ttlSeconds: number): Promise<boolean>;
  }

  /**
   * Cloudflare KV–backed revocation list (§8.3). Durable: revoked
   * entries persist without TTL by default.
   */
  export class KvRevocationList implements RevocationList {
    constructor(namespace: KVNamespace);
    isRevoked(did: string): Promise<boolean>;
    add(did: string, revokedAt: string): Promise<void>;
  }
}
