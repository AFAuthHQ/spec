/**
 * AFAuth reference server for the e2e harness.
 *
 * Thin Hono wrapper around `@afauthhq/server`. Mounts the v0.1
 * endpoint set against in-memory stores. This is a fixture for the
 * stack-up harness — NOT a production deployment shape.
 *
 * Configuration via env:
 *   PORT                       listen port (default 3000)
 *   PUBLIC_BASE_URL            base URL the discovery doc advertises
 *   SERVICE_DID                service DID (default did:web:localhost%3A4003)
 *   ATTESTOR_TRUST_JWKS_URL    if set, configure the Server to accept
 *                              `afauth-trust` attestations against the
 *                              given JWKS endpoint. Used by the e2e
 *                              attestation scenario. May be http:// —
 *                              this is a test fixture, not production.
 *   ATTESTOR_TRUST_ISS         override issuer (default `afauth-trust`).
 *   ATTESTED_ONLY              if "1", advertise
 *                              `billing.unclaimed_mode = "attested_only"`
 *                              so signup without attestation fails.
 */

import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { AFAuthError, type Recipient } from "@afauthhq/core";
import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  Server,
  type Attestor,
  type AttestationClaims,
  type DiscoveryDocument,
  type OwnerSession,
  type RecipientHandler,
  type VerifyOptions,
} from "@afauthhq/server";
import { createRemoteJWKSet, jwtVerify } from "jose";

/**
 * Run a Server handler and serialise AFAuthError throws as §11.1
 * error envelopes. Without this wrapper Hono returns 500 on the
 * happy AFAuthError-throw paths (invalid_signature, expired,
 * replayed_nonce, etc.), which is wrong per the spec.
 */
async function wrap(fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof AFAuthError) return err.toResponse();
    throw err;
  }
}

const PORT = Number(process.env["PORT"] ?? "3000");
const PUBLIC_BASE_URL =
  process.env["PUBLIC_BASE_URL"] ?? `http://localhost:${PORT}`;
const SERVICE_DID = process.env["SERVICE_DID"] ?? "did:web:localhost%3A4003";

const ATTESTOR_TRUST_JWKS_URL = process.env["ATTESTOR_TRUST_JWKS_URL"];
const ATTESTOR_TRUST_ISS = process.env["ATTESTOR_TRUST_ISS"] ?? "afauth-trust";
const ATTESTED_ONLY = process.env["ATTESTED_ONLY"] === "1";

// E2E_CLAIM gates the in-memory invitation capture + claim
// completion endpoints. When set:
//   - the email RecipientHandler captures the magic-link details
//     instead of logging them, so the harness can fish them out
//     via GET /e2e/last-invitation
//   - POST /e2e/claim accepts {token, email} and drives the
//     SDK's handleClaimCompletion with a synthetic OwnerSession,
//     so the scenario can flip an INVITED account to CLAIMED
//     without a browser
// Default off; setting it in production would let any caller
// claim any pending invitation.
const E2E_CLAIM = process.env["E2E_CLAIM"] === "1";

interface CapturedInvitation {
  recipient: Recipient;
  claim_token: string;
  claim_page_url: string;
  redirect_url?: string;
  captured_at: string;
}
const capturedInvitations: CapturedInvitation[] = [];

const captureEmailHandler: RecipientHandler = {
  async initiate({ recipient, claimToken, claimPageUrl, redirectUrl }) {
    if (recipient.type !== "email") {
      throw new AFAuthError(
        "unsupported_recipient_type",
        400,
        `captureEmailHandler received non-email recipient: ${recipient.type}`,
      );
    }
    capturedInvitations.push({
      recipient,
      claim_token: claimToken,
      claim_page_url: claimPageUrl,
      redirect_url: redirectUrl,
      captured_at: new Date().toISOString(),
    });
  },
  matches: consoleEmailHandler.matches,
};

/**
 * Minimal `Attestor` implementation that bypasses the SDK's
 * JwksAttestor https-only constructor check, so the harness can
 * point at `http://trust:3000/.well-known/jwks.json` over docker's
 * internal network. Production deployments should always use the
 * SDK's `trustAttestor()`, which enforces https + the AFAP-pinned
 * URL.
 */
class LooseJwksAttestor implements Attestor {
  readonly iss: string;
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  constructor(iss: string, jwksUrl: string) {
    this.iss = iss;
    this.jwks = createRemoteJWKSet(new URL(jwksUrl));
  }
  async verify(
    jwt: string,
    agentDid: string,
    opts: VerifyOptions = {},
  ): Promise<AttestationClaims> {
    let payload: Record<string, unknown>;
    try {
      const result = await jwtVerify(jwt, this.jwks, {
        algorithms: ["EdDSA"],
        issuer: this.iss,
        ...(opts.audience ? { audience: opts.audience } : {}),
      });
      payload = result.payload as Record<string, unknown>;
    } catch (err) {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        `LooseJwksAttestor: ${(err as Error).message}`,
      );
    }
    // Mirror the SDK's validateClaims() in shape, just enough for
    // the Server to be satisfied. See SDK index.ts:validateClaims
    // for the production-grade version.
    if (payload.iss !== this.iss) {
      throw new AFAuthError("invalid_attestation", 401, `iss mismatch`);
    }
    if (payload.sub !== agentDid) {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        `sub mismatch: token sub=${String(payload.sub)} vs agent ${agentDid}`,
      );
    }
    if (typeof payload.exp !== "number") {
      throw new AFAuthError("invalid_attestation", 401, "missing exp claim");
    }
    return payload as AttestationClaims;
  }
}

const attestor = ATTESTOR_TRUST_JWKS_URL
  ? new LooseJwksAttestor(ATTESTOR_TRUST_ISS, ATTESTOR_TRUST_JWKS_URL)
  : undefined;

// `claim_page` MUST be a URL the human visits; the spec (§4.4)
// allows endpoints to be paths *or* absolute URLs, but several
// downstream consumers (e.g. registry.afauth.org's
// DiscoveryDocSchema) require a URL here. Emitting an absolute URL
// keeps the reference fixture compatible with all of them.
const discovery: DiscoveryDocument = {
  afauth_version: "0.1",
  service_did: SERVICE_DID,
  endpoints: {
    accounts: "/afauth/v1/accounts",
    owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
    claim_page: `${PUBLIC_BASE_URL.replace(/\/$/, "")}/claim`,
    claim_completion: "/afauth/v1/claim",
    key_rotation: "/afauth/v1/accounts/me/keys/rotate",
  },
  signature_algorithms: ["ed25519"],
  recipient_types: ["email"],
  ...(ATTESTED_ONLY
    ? {
        billing: {
          unclaimed_mode: "attested_only" as const,
          accepted_attestors: [ATTESTOR_TRUST_ISS],
        },
      }
    : {}),
};

const server = new Server({
  nonceStore: new MemoryNonceStore(),
  revocationList: new MemoryRevocationList(),
  serviceDid: SERVICE_DID,
  accounts: new MemoryAccountStore(),
  recipients: { email: E2E_CLAIM ? captureEmailHandler : consoleEmailHandler },
  discovery,
  baseUrl: PUBLIC_BASE_URL,
  ...(attestor ? { attestor } : {}),
});

const app = new Hono();

app.get("/healthz", (c) => c.json({ ok: true }));

app.get("/.well-known/afauth", async (c) =>
  wrap(() => server.handleDiscovery(c.req.raw)),
);

app.get("/afauth/v1/accounts/me", async (c) =>
  wrap(() => server.handleAccountIntrospection(c.req.raw)),
);

app.post("/afauth/v1/accounts/me/owner-invitation", async (c) =>
  wrap(() => server.handleOwnerInvitation(c.req.raw)),
);

app.post("/afauth/v1/accounts/me/keys/rotate", async (c) =>
  wrap(() => server.handleKeyRotation(c.req.raw)),
);

// Claim page is normally a real HTML page. For the harness it returns
// a stub — the e2e CLI flow doesn't drive claim today.
app.get("/claim", (c) =>
  c.text("e2e reference server — claim page stub", 200),
);

// ----- E2E_CLAIM-gated invitation / claim helpers -----
//
// These endpoints exist ONLY to let the harness drive scenario 9
// (owner invitation + claim) without a Playwright browser. They
// expose pending invitations and complete claims with a synthetic
// OwnerSession. 404 by default. MUST NOT be enabled in production.

app.get("/e2e/last-invitation", (c) => {
  if (!E2E_CLAIM) {
    return c.json({ error: { code: "not_found", message: "Not found" } }, 404);
  }
  if (capturedInvitations.length === 0) {
    return c.json(
      { error: { code: "not_found", message: "no invitations captured" } },
      404,
    );
  }
  return c.json(capturedInvitations[capturedInvitations.length - 1]);
});

app.post("/e2e/claim", async (c) => {
  if (!E2E_CLAIM) {
    return c.json({ error: { code: "not_found", message: "Not found" } }, 404);
  }
  const body = await c.req.json().catch(() => ({}));
  const token = typeof body?.token === "string" ? body.token : null;
  const email = typeof body?.email === "string" ? body.email : null;
  if (!token || !email) {
    return c.json(
      {
        error: {
          code: "malformed_request",
          message: "token and email required",
        },
      },
      400,
    );
  }
  // Build a synthetic OwnerSession proving the human "authenticated"
  // by email. The real ceremony would route through a magic-link
  // + cookie session at the /claim browser page; we shortcut to the
  // same input the SDK requires.
  const session: OwnerSession = {
    authenticated: { type: "email", value: email },
    userId: `e2e-user:${email.toLowerCase()}`,
    authenticatedAt: new Date().toISOString(),
  };
  const claimUrl = `${PUBLIC_BASE_URL.replace(/\/$/, "")}/afauth/v1/claim/${token}`;
  const fakeReq = new Request(claimUrl, { method: "POST" });
  return wrap(() => server.handleClaimCompletion(fakeReq, session));
});

serve({ fetch: app.fetch, port: PORT }, (info) => {
  // eslint-disable-next-line no-console
  console.log(
    `reference-server listening on :${info.port} (service_did=${SERVICE_DID}, attested_only=${ATTESTED_ONLY}, attestor=${attestor ? "configured" : "off"})`,
  );
});
