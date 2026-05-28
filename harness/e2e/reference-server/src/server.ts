/**
 * AFAuth reference server for the e2e harness.
 *
 * Thin Hono wrapper around `@afauthhq/server`. Mounts the v0.1
 * endpoint set against in-memory stores. This is a fixture for the
 * stack-up harness — NOT a production deployment shape.
 *
 * Configuration via env:
 *   PORT             listen port (default 3000)
 *   PUBLIC_BASE_URL  base URL the discovery doc advertises
 *   SERVICE_DID      service DID (default did:web:localhost%3A4003)
 */

import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { AFAuthError } from "@afauthhq/core";
import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  Server,
  type DiscoveryDocument,
} from "@afauthhq/server";

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

const discovery: DiscoveryDocument = {
  afauth_version: "0.1",
  service_did: SERVICE_DID,
  endpoints: {
    accounts: "/afauth/v1/accounts",
    owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
    claim_page: "/claim",
    claim_completion: "/afauth/v1/claim",
    key_rotation: "/afauth/v1/accounts/me/keys/rotate",
  },
  signature_algorithms: ["ed25519"],
  recipient_types: ["email"],
};

const server = new Server({
  nonceStore: new MemoryNonceStore(),
  revocationList: new MemoryRevocationList(),
  serviceDid: SERVICE_DID,
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  discovery,
  baseUrl: PUBLIC_BASE_URL,
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

serve({ fetch: app.fetch, port: PORT }, (info) => {
  // eslint-disable-next-line no-console
  console.log(
    `reference-server listening on :${info.port} (service_did=${SERVICE_DID})`,
  );
});
