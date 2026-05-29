#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// AFAuth e2e harness — scenario runner.
//
// Drives implementations under test against the dependency-side stack
// brought up by ./scripts/up.sh. Each scenario is a small async
// function in SCENARIOS below; pass the name with --scenario, or omit
// to run all.
//
// Usage:
//
//   node run.js                              # run all scenarios
//   node run.js --scenario init-signup       # run one
//   node run.js --list                       # list scenarios
//
// Environment:
//
//   AFAUTH_CLI_BIN        path to a built `afauth` binary (required
//                         for CLI scenarios)
//   AFAUTH_TRUST_BASE            URL of the trust service                (default: http://localhost:4001)
//   AFAUTH_REGISTRY_BASE         URL of the registry service             (default: http://localhost:4002)
//   AFAUTH_SERVER_BASE           URL of the reference server             (default: http://localhost:4003)
//   AFAUTH_SERVER_BASE_B         URL of the second reference server      (default: http://localhost:4004)
//   AFAUTH_SERVER_BASE_ATTESTED  URL of the attested-only reference srv  (default: http://localhost:4005)
//
// Exits non-zero on any failure.

'use strict';

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const DEFAULTS = {
  trustBase: process.env.AFAUTH_TRUST_BASE || 'http://localhost:4001',
  registryBase: process.env.AFAUTH_REGISTRY_BASE || 'http://localhost:4002',
  serverBase: process.env.AFAUTH_SERVER_BASE || 'http://localhost:4003',
  serverBaseB: process.env.AFAUTH_SERVER_BASE_B || 'http://localhost:4004',
  serverBaseAttested: process.env.AFAUTH_SERVER_BASE_ATTESTED || 'http://localhost:4005',
  cliBin: process.env.AFAUTH_CLI_BIN || '',
};

// ---------- helpers ----------

function runCli(opts, args) {
  return new Promise((resolve, reject) => {
    if (!opts.cliBin) {
      reject(new Error('AFAUTH_CLI_BIN is not set'));
      return;
    }
    const env = { ...process.env, AFAUTH_HOME: opts.tmpDir };
    const child = spawn(opts.cliBin, args, { env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

/**
 * Like runCli, but invokes onLine(line) for every newline-terminated
 * stdout line as it arrives. Use for interactive scenarios where the
 * harness needs to react to CLI output before the process exits.
 */
function runCliStreaming(opts, args, onLine) {
  return new Promise((resolve, reject) => {
    if (!opts.cliBin) {
      reject(new Error('AFAUTH_CLI_BIN is not set'));
      return;
    }
    const env = { ...process.env, AFAUTH_HOME: opts.tmpDir };
    const child = spawn(opts.cliBin, args, { env });
    let stdout = '';
    let stderr = '';
    let buf = '';
    child.stdout.on('data', (d) => {
      const s = d.toString();
      stdout += s;
      buf += s;
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        try {
          onLine(line);
        } catch (e) {
          child.kill();
          reject(e);
          return;
        }
      }
    });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

async function preflight(opts) {
  // Refuse to start scenarios if the stack isn't reachable. Saves
  // confusing "connection refused" errors deep inside a scenario.
  const urls = [
    ['reference-server', opts.serverBase + '/healthz'],
    ['reference-server-b', opts.serverBaseB + '/healthz'],
    ['reference-server-attested', opts.serverBaseAttested + '/healthz'],
    ['trust', opts.trustBase + '/healthz'],
    ['registry', opts.registryBase + '/healthz'],
  ];
  for (const [name, url] of urls) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`status ${res.status}`);
    } catch (e) {
      throw new Error(`preflight: ${name} not reachable at ${url}: ${e.message}`);
    }
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(`assert: ${msg}`);
}

/**
 * Decode the JSON payload of a JWT without verifying the signature.
 * Used to extract `req_id` from the link URL the CLI prints during
 * `afauth trust link`. Signature verification is the trust service's
 * job; the harness only needs the request id.
 */
function decodeJwtPayload(jwt) {
  const parts = jwt.split('.');
  if (parts.length < 2) throw new Error('jwt: expected 3 segments');
  const padded = parts[1] + '='.repeat((4 - (parts[1].length % 4)) % 4);
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}

// ---------- inline signer (replay / expired scenarios) ----------
//
// Self-contained RFC 9421 signer just enough to craft a few crafted
// probes. Avoids pulling in `@afauthhq/agent` as an npm dep —
// keeping the harness zero-deps means CI's `up.sh && node run.js`
// stays a two-command setup.
//
// Limitations: handles only `@method` + `@target-uri` covered
// components (no body / content-digest). Good enough for the GET
// /accounts/me probe surface; not a general-purpose signer.

// PKCS#8 prefix for an Ed25519 private key carrying a 32-byte raw seed.
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function loadAgentFromKeyJson(keyJsonPath) {
  const json = JSON.parse(fs.readFileSync(keyJsonPath, 'utf8'));
  const seed = Buffer.from(json.private_key_seed_hex, 'hex');
  if (seed.length !== 32) {
    throw new Error(`expected 32-byte Ed25519 seed, got ${seed.length}`);
  }
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  const privateKey = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return { did: json.did_key, privateKey };
}

function buildCanonicalSignInput({ method, targetUri, params, covered }) {
  const lines = [];
  for (const c of covered) {
    if (c === '@method') lines.push(`"@method": ${method}`);
    else if (c === '@target-uri') lines.push(`"@target-uri": ${targetUri}`);
    else throw new Error(`inline signer: unsupported covered component ${c}`);
  }
  const list = covered.map((c) => `"${c}"`).join(' ');
  const paramStr =
    `created=${params.created};` +
    `expires=${params.expires};` +
    `nonce="${params.nonce}";` +
    `keyid="${params.keyid}";` +
    `alg="${params.alg}"`;
  lines.push(`"@signature-params": (${list});${paramStr}`);
  return lines.join('\n');
}

function signGet(agent, url, opts = {}) {
  const created = opts.created ?? Math.floor(Date.now() / 1000);
  const expires = opts.expires ?? created + 60;
  const nonce = opts.nonce ?? crypto.randomBytes(16).toString('hex');
  const covered = ['@method', '@target-uri'];
  const params = { created, expires, nonce, keyid: agent.did, alg: 'ed25519' };
  const canonical = buildCanonicalSignInput({
    method: 'GET',
    targetUri: url,
    params,
    covered,
  });
  const sig = crypto.sign(null, Buffer.from(canonical, 'utf8'), agent.privateKey);
  const list = covered.map((c) => `"${c}"`).join(' ');
  return {
    'signature-input':
      `sig1=(${list});created=${created};expires=${expires};` +
      `nonce="${nonce}";keyid="${agent.did}";alg="ed25519"`,
    signature: `sig1=:${sig.toString('base64')}:`,
  };
}

/**
 * Assert a fetch Response carries a §11.1 error envelope:
 *   { "error": { "code": "...", "message": "..." } }
 * and the expected status code. Used by the negatives bundle.
 */
async function assertErrorEnvelope(res, expectedStatus, expectedCode) {
  assert(
    res.status === expectedStatus,
    `expected status ${expectedStatus}, got ${res.status}`,
  );
  let body;
  try {
    body = await res.json();
  } catch {
    throw new Error('response body was not JSON');
  }
  assert(body && typeof body === 'object', 'body is not an object');
  assert(body.error && typeof body.error === 'object', 'missing error object');
  assert(
    body.error.code === expectedCode,
    `expected code=${expectedCode}, got code=${body.error.code}`,
  );
  assert(
    typeof body.error.message === 'string' && body.error.message.length > 0,
    'missing or empty error.message',
  );
}

// ---------- scenarios ----------

/**
 * Scenario 1: `afauth init → afauth signup`.
 *
 * Validates the full stack-up:
 *   - the CLI builds, runs, and writes a local key
 *   - the CLI fetches the reference server's discovery doc
 *   - the CLI signs GET /accounts/me with its agent key
 *   - the reference server (real @afauthhq/server) verifies the
 *     signature, creates an UNCLAIMED account, returns introspection
 *   - the CLI persists the ledger entry locally
 *
 * Failure here means the harness pattern itself is broken — every
 * other scenario depends on this working.
 */
async function scenarioInitSignup(opts) {
  // 1. afauth init — fresh agent key under our scoped AFAUTH_HOME.
  const init = await runCli(opts, ['init']);
  assert(init.code === 0, `init exit ${init.code}: ${init.stderr}`);
  assert(/did:key:z/.test(init.stdout), `init stdout missing did:key: ${init.stdout}`);
  assert(
    fs.existsSync(path.join(opts.tmpDir, 'key.json')),
    'key.json not written to AFAUTH_HOME',
  );

  // 2. afauth signup <reference-server> — implicit signup via
  //    GET /accounts/me. The CLI signs the request; the server
  //    verifies and creates an UNCLAIMED account row.
  const signup = await runCli(opts, ['signup', opts.serverBase]);
  assert(signup.code === 0, `signup exit ${signup.code}: ${signup.stderr}`);
  assert(
    signup.stdout.includes('signed up to ' + opts.serverBase),
    `signup stdout missing confirmation: ${signup.stdout}`,
  );
  assert(
    signup.stdout.includes('(UNCLAIMED)'),
    `signup stdout missing UNCLAIMED state: ${signup.stdout}`,
  );

  // 3. ledger persisted.
  assert(
    fs.existsSync(path.join(opts.tmpDir, 'accounts.json')),
    'accounts.json not written to AFAUTH_HOME',
  );

  // 4. afauth accounts list --json — confirm the entry round-trips.
  const list = await runCli(opts, ['accounts', 'list', '--json']);
  assert(list.code === 0, `accounts list exit ${list.code}: ${list.stderr}`);
  const entries = JSON.parse(list.stdout);
  assert(Array.isArray(entries) && entries.length === 1, `expected 1 entry, got ${entries.length}`);
  assert(
    entries[0].state === 'UNCLAIMED',
    `expected state=UNCLAIMED, got ${entries[0].state}`,
  );
}

/**
 * Scenario 2: `afauth keys rotate` (§8.1 pre-claim key rotation).
 *
 * Validates:
 *   - the CLI generates a new keypair locally
 *   - the CLI signs the rotation request with the OLD key (§8.1)
 *   - the reference server accepts the rotation and updates the
 *     account's bound DID
 *   - the local ledger is rewritten to point at the new DID
 *
 * Catches: silent rotation failures where the CLI swaps the key
 * locally but the server-side rejects (or vice versa). Unit tests
 * mock the wire; only e2e exercises the actual signed-with-old-key
 * → verified-by-server round-trip.
 */
async function scenarioPreClaimKeyRotate(opts) {
  // 1-2. Setup: init + signup (same as scenario 1).
  let r = await runCli(opts, ['init']);
  assert(r.code === 0, `init: ${r.stderr}`);
  r = await runCli(opts, ['signup', opts.serverBase]);
  assert(r.code === 0, `signup: ${r.stderr}`);

  // 3. Capture the original DID.
  const ledger0 = JSON.parse(
    fs.readFileSync(path.join(opts.tmpDir, 'accounts.json'), 'utf8'),
  );
  const entries0 = Object.values(ledger0.accounts || {});
  assert(entries0.length === 1, `expected 1 ledger entry, got ${entries0.length}`);
  const oldDID = entries0[0].agent_did;
  assert(/^did:key:z/.test(oldDID), `expected did:key, got ${oldDID}`);

  // 4. Rotate.
  r = await runCli(opts, ['keys', 'rotate', '--service', opts.serverBase]);
  assert(r.code === 0, `keys rotate exit ${r.code}: ${r.stderr}`);
  assert(
    r.stdout.includes('rotated ' + opts.serverBase),
    `rotate stdout missing confirmation: ${r.stdout}`,
  );
  assert(
    r.stdout.includes('old: ' + oldDID),
    `rotate stdout missing old DID: ${r.stdout}`,
  );

  // 5. Ledger now points at the new DID.
  const ledger1 = JSON.parse(
    fs.readFileSync(path.join(opts.tmpDir, 'accounts.json'), 'utf8'),
  );
  const entries1 = Object.values(ledger1.accounts || {});
  const newDID = entries1[0].agent_did;
  assert(newDID !== oldDID, 'ledger still has old DID after rotate');
  assert(/^did:key:z/.test(newDID), `expected new did:key, got ${newDID}`);

  // 6. `accounts list --json` agrees.
  r = await runCli(opts, ['accounts', 'list', '--json']);
  assert(r.code === 0, `list: ${r.stderr}`);
  const listed = JSON.parse(r.stdout);
  assert(
    listed[0].agent_did === newDID,
    `list shows ${listed[0].agent_did}, expected ${newDID}`,
  );
}

/**
 * Scenario 3: `afauth trust link` against a real trust attestor
 * (AFAP-0006 §10).
 *
 * Validates the full link round-trip:
 *   - CLI hits /v1/link/start → trust returns link URL + req_id
 *   - the harness (acting as the browser human) auto-confirms via
 *     the gated /v1/link/confirm-e2e endpoint
 *   - CLI's polling picks up the confirmed state and pops the
 *     binding token from Redis
 *   - the CLI persists trust state to ~/.afauth/trust.json
 *
 * Catches: drift between the agent-side signing of /v1/link/poll
 * and the trust-side verification — entirely a wire concern, not
 * something unit tests reach. This scenario depends on
 * TRUST_E2E_AUTOCONFIRM=1 being set in the docker-compose stack.
 */
async function scenarioTrustLink(opts) {
  // 1. Fresh agent.
  let r = await runCli(opts, ['init']);
  assert(r.code === 0, `init: ${r.stderr}`);

  // 2. Start `afauth trust link` in the background. The CLI will
  //    print the link URL, then poll. We extract req_id from the
  //    JWT in the link URL, post the auto-confirm, and the CLI's
  //    next poll will succeed.
  let confirmed = false;
  const linkResult = await runCliStreaming(
    opts,
    [
      'trust', 'link',
      '--base', opts.trustBase,
      '--no-loopback',
      '--no-browser',
      '--timeout', '30',
      '--poll', '1',
    ],
    async (line) => {
      // The CLI prints "  http://.../link?req=<jwt>" on its own line.
      const m = line.match(/(https?:\/\/[^\s]+\/link\?req=([^\s&]+))/);
      if (!m || confirmed) return;
      confirmed = true;
      const reqJwt = decodeURIComponent(m[2]);
      const payload = decodeJwtPayload(reqJwt);
      const reqId = payload.req_id;
      assert(typeof reqId === 'string', `req_id missing from link JWT payload`);

      // Auto-confirm as a synthetic human. Mirrors what the browser
      // does after the human clicks "Confirm" on /link.
      const res = await fetch(opts.trustBase + '/v1/link/confirm-e2e', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          req_id: reqId,
          email: 'e2e-human@example.com',
        }),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(
          `auto-confirm failed: status ${res.status}: ${body}`,
        );
      }
    },
  );

  assert(linkResult.code === 0, `trust link exit ${linkResult.code}: ${linkResult.stderr}`);
  assert(confirmed, 'harness never detected the link URL in CLI stdout');
  assert(
    linkResult.stdout.includes('linked ✓'),
    `trust link stdout missing "linked ✓": ${linkResult.stdout}`,
  );
  assert(
    fs.existsSync(path.join(opts.tmpDir, 'trust.json')),
    'trust.json not written to AFAUTH_HOME',
  );

  // 3. trust.json has the expected shape.
  const trustState = JSON.parse(
    fs.readFileSync(path.join(opts.tmpDir, 'trust.json'), 'utf8'),
  );
  assert(
    /^[0-9a-f-]{36}$/.test(trustState.binding_id),
    `unexpected binding_id: ${trustState.binding_id}`,
  );
  assert(
    typeof trustState.binding_token === 'string' && trustState.binding_token.length > 0,
    'binding_token missing',
  );
}

/**
 * Scenario 4: §11.1 error envelope conformance probes.
 *
 * The reference server is the consumer of the @afauthhq/server SDK;
 * a regression here means anyone wiring the SDK into Hono / Express
 * silently leaks 500s instead of conformant 401 envelopes. We
 * already caught this once (the wrap() helper); this scenario stops
 * it from coming back.
 *
 * Only checks paths that don't require valid signing (signing-with-
 * adjusted-timestamp / replayed-nonce probes need a custom signer
 * which is tracked as follow-on).
 */
async function scenarioNegatives(opts) {
  // 1. Unsigned GET /accounts/me → 401 invalid_signature.
  let res = await fetch(opts.serverBase + '/afauth/v1/accounts/me');
  await assertErrorEnvelope(res, 401, 'invalid_signature');

  // 2. Unsigned POST /accounts/me/keys/rotate → 401 invalid_signature.
  res = await fetch(opts.serverBase + '/afauth/v1/accounts/me/keys/rotate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ new_account_did: 'did:key:zAAA' }),
  });
  await assertErrorEnvelope(res, 401, 'invalid_signature');

  // 3. Unsigned POST /accounts/me/owner-invitation → 401.
  res = await fetch(opts.serverBase + '/afauth/v1/accounts/me/owner-invitation', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ recipient_type: 'email', recipient_value: 'a@b.co' }),
  });
  await assertErrorEnvelope(res, 401, 'invalid_signature');

  // 4. GET /.well-known/afauth → 200 with valid DiscoveryDocument.
  res = await fetch(opts.serverBase + '/.well-known/afauth');
  assert(res.status === 200, `discovery: expected 200, got ${res.status}`);
  const doc = await res.json();
  assert(doc.afauth_version === '0.1', `discovery: bad afauth_version: ${doc.afauth_version}`);
  assert(
    typeof doc.service_did === 'string' && doc.service_did.length > 0,
    'discovery: service_did missing',
  );
  assert(
    Array.isArray(doc.signature_algorithms) && doc.signature_algorithms.includes('ed25519'),
    'discovery: signature_algorithms missing ed25519',
  );
}

/**
 * Scenario 5: registry round-trip (AFAP-0003).
 *
 * Validates the service-directory promise:
 *   - a service publishes a discovery doc at a well-known URL
 *   - the registry stores (service_did, discovery_url, doc) and
 *     returns it on lookup-by-DID and on the list endpoint
 *   - an agent that has the service_did can resolve back to the
 *     discovery URL without already knowing it
 *
 * We bypass the production challenge/proof ceremony via the
 * gated REGISTRY_E2E_DIRECT_INSERT endpoint — the SSRF protection
 * in registry's fetchText (https-only, public-host-only) blocks
 * docker-internal URLs, and the ceremony isn't what we're testing
 * here. The wire shape is: harness fetches the live discovery
 * doc, hands it to registry, then reads it back.
 *
 * Catches: schema drift between the reference server's discovery
 * doc and the registry's DiscoveryDocSchema (we already caught
 * one — the `claim_page` URL requirement). Future catches: DID
 * normalisation regressions, list/search filtering breakage.
 */
async function scenarioRegistryRoundTrip(opts) {
  // 1. Fetch the live discovery doc from the reference server.
  let res = await fetch(opts.serverBase + '/.well-known/afauth');
  assert(res.ok, `discovery fetch failed: ${res.status}`);
  const doc = await res.json();
  const serviceDid = doc.service_did;
  assert(
    typeof serviceDid === 'string' && serviceDid.startsWith('did:'),
    `discovery doc missing service_did: ${JSON.stringify(doc).slice(0, 200)}`,
  );

  // 2. Seed the listing into the registry.
  const submission = {
    service_did: serviceDid,
    discovery_url: opts.serverBase + '/.well-known/afauth',
    discovery_doc: doc,
    title: 'E2E reference service',
    description: 'Inserted by spec/harness/e2e/run.js — registry-roundtrip.',
    tags: ['e2e', 'reference'],
  };
  res = await fetch(opts.registryBase + '/admin/e2e/listings', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(submission),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`seed failed: ${res.status}: ${body.slice(0, 300)}`);
  }
  const inserted = await res.json();
  assert(inserted.service_did === serviceDid, `inserted DID mismatch: ${inserted.service_did}`);

  // 3. Look up by DID — round-trip.
  res = await fetch(
    opts.registryBase + '/v1/listings/' + encodeURIComponent(serviceDid),
  );
  assert(res.status === 200, `lookup-by-DID expected 200, got ${res.status}`);
  const lookup = await res.json();
  assert(lookup.service_did === serviceDid, `lookup DID mismatch: ${lookup.service_did}`);
  assert(
    lookup.discovery_url === submission.discovery_url,
    `lookup discovery_url mismatch: ${lookup.discovery_url}`,
  );
  assert(lookup.title === submission.title, `lookup title mismatch: ${lookup.title}`);

  // 4. List with a tag filter, confirm the seeded entry surfaces.
  res = await fetch(opts.registryBase + '/v1/listings?tag=e2e&limit=50');
  assert(res.status === 200, `list expected 200, got ${res.status}`);
  const list = await res.json();
  assert(Array.isArray(list.listings), `list.listings is not an array`);
  const found = list.listings.find((l) => l.service_did === serviceDid);
  assert(found, `seeded listing not present in tag=e2e list`);
}

/**
 * Scenario 6: cross-service portability (§D.1).
 *
 * Validates the headline promise of the protocol: an agent's
 * did:key is portable across services. Same agent key, two
 * services, two independent UNCLAIMED accounts. Neither service
 * has knowledge of the other; the only thing tying the rows
 * together is the agent's DID.
 *
 * Catches: any regression that introduces hidden cross-service
 * coupling (e.g. an SDK change that fetches a "primary" service
 * before signing up). Two ref-server containers (different
 * SERVICE_DIDs) make the test honest — there's no way for them
 * to coordinate.
 */
async function scenarioCrossServicePortability(opts) {
  // 1. Fresh agent.
  let r = await runCli(opts, ['init']);
  assert(r.code === 0, `init: ${r.stderr}`);
  const keyJson = JSON.parse(
    fs.readFileSync(path.join(opts.tmpDir, 'key.json'), 'utf8'),
  );
  // Sanity-check the agent did is fixed across the scenario.
  const agentDid = keyJson.did_key;
  assert(/^did:key:z/.test(agentDid), `expected did:key, got ${agentDid}`);

  // 2. Sign up on server A.
  r = await runCli(opts, ['signup', opts.serverBase]);
  assert(r.code === 0, `signup A: ${r.stderr}`);

  // 3. Sign up on server B (different SERVICE_DID, different stack).
  r = await runCli(opts, ['signup', opts.serverBaseB]);
  assert(r.code === 0, `signup B: ${r.stderr}`);

  // 4. Ledger has two independent entries, both keyed by the same
  //    agent DID.
  const ledger = JSON.parse(
    fs.readFileSync(path.join(opts.tmpDir, 'accounts.json'), 'utf8'),
  );
  const entries = Object.values(ledger.accounts || {});
  assert(entries.length === 2, `expected 2 ledger entries, got ${entries.length}`);

  const byService = new Map(entries.map((e) => [e.service_url, e]));
  const a = byService.get(opts.serverBase);
  const b = byService.get(opts.serverBaseB);
  assert(a, `ledger missing entry for ${opts.serverBase}`);
  assert(b, `ledger missing entry for ${opts.serverBaseB}`);
  assert(a.state === 'UNCLAIMED', `A state expected UNCLAIMED, got ${a.state}`);
  assert(b.state === 'UNCLAIMED', `B state expected UNCLAIMED, got ${b.state}`);
  assert(
    a.agent_did === b.agent_did,
    `agent DIDs diverged: A=${a.agent_did} vs B=${b.agent_did}`,
  );
  assert(a.agent_did === agentDid, `A agent_did != key.json did`);
}

/**
 * Scenario 7: replay protection + expired-signature probes (§5.6).
 *
 * Uses the inline signer to craft signed GETs that fail in
 * specific ways:
 *   - well-formed signature with expires < now → 401 expired_signature
 *   - well-formed signature with nonce reused → 401 replayed_nonce
 *
 * The vector-level conformance harness (`spec/harness/run.js`)
 * already checks the canonical-input format of these errors; this
 * scenario verifies the live HTTP behaviour all the way to the
 * envelope. Catches regressions where the SDK accepts a stale
 * `expires` or fails to record a nonce in the NonceStore.
 */
async function scenarioReplayExpired(opts) {
  // 1. Setup agent + signup, so a valid account exists for the
  //    crafted probes to target.
  let r = await runCli(opts, ['init']);
  assert(r.code === 0, `init: ${r.stderr}`);
  r = await runCli(opts, ['signup', opts.serverBase]);
  assert(r.code === 0, `signup: ${r.stderr}`);

  const agent = loadAgentFromKeyJson(path.join(opts.tmpDir, 'key.json'));
  const targetUri = opts.serverBase + '/afauth/v1/accounts/me';

  // 2. Baseline: a fresh signed request succeeds.
  let headers = signGet(agent, targetUri);
  let res = await fetch(targetUri, { method: 'GET', headers });
  assert(res.status === 200, `baseline expected 200, got ${res.status}`);

  // 3. Expired-signature probe: created/expires are well in the past.
  const past = Math.floor(Date.now() / 1000) - 600;
  headers = signGet(agent, targetUri, { created: past, expires: past + 60 });
  res = await fetch(targetUri, { method: 'GET', headers });
  await assertErrorEnvelope(res, 401, 'expired_signature');

  // 4. Replay probe: two signed requests with the same nonce. The
  //    first succeeds, the second is rejected.
  const sharedNonce = crypto.randomBytes(16).toString('hex');
  const h1 = signGet(agent, targetUri, { nonce: sharedNonce });
  res = await fetch(targetUri, { method: 'GET', headers: h1 });
  assert(res.status === 200, `replay first call expected 200, got ${res.status}`);
  // Re-sign with the same nonce but fresh timestamp — must still trip
  // the NonceStore even though the canonical input differs.
  const h2 = signGet(agent, targetUri, { nonce: sharedNonce });
  res = await fetch(targetUri, { method: 'GET', headers: h2 });
  await assertErrorEnvelope(res, 401, 'replayed_nonce');
}

/**
 * Scenario 8: trust attestation presented to a service (§10).
 *
 * Validates the full AFAP-0006 round-trip:
 *   - agent links with the trust attestor (gated auto-confirm)
 *   - agent calls `afauth trust token <service-did>` → mints an
 *     `afauth-trust` JWT scoped to the reference server
 *   - agent calls `afauth signup --attest <jwt>` → CLI presents
 *     the JWT in `AFAuth-Attestation`
 *   - reference server fetches trust's JWKS over the docker
 *     network, verifies the JWT (iss=afauth-trust, sub=agent did,
 *     aud=service did, EdDSA), accepts the signup
 *
 * Catches: drift across the full pipeline — trust signing keys,
 * JWKS shape, CLI Attestation header construction, SDK verifier.
 * No mock fits in this picture.
 */
async function scenarioTrustAttestation(opts) {
  // 1. Fresh agent + link with trust (re-uses the auto-confirm
  //    mechanism from the trust-link scenario).
  let r = await runCli(opts, ['init']);
  assert(r.code === 0, `init: ${r.stderr}`);

  let confirmed = false;
  const link = await runCliStreaming(
    opts,
    [
      'trust', 'link',
      '--base', opts.trustBase,
      '--no-loopback',
      '--no-browser',
      '--timeout', '30',
      '--poll', '1',
    ],
    async (line) => {
      const m = line.match(/(https?:\/\/[^\s]+\/link\?req=([^\s&]+))/);
      if (!m || confirmed) return;
      confirmed = true;
      const reqJwt = decodeURIComponent(m[2]);
      const reqId = decodeJwtPayload(reqJwt).req_id;
      const res = await fetch(opts.trustBase + '/v1/link/confirm-e2e', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          req_id: reqId,
          email: 'e2e-human@example.com',
        }),
      });
      if (!res.ok) throw new Error(`auto-confirm failed: ${res.status}`);
    },
  );
  assert(link.code === 0, `trust link: ${link.stderr}`);

  // 2. Mint an attestation JWT scoped to the reference server's
  //    SERVICE_DID. The ref-server announces this as
  //    did:web:localhost%3A4003 in its discovery doc.
  const serviceDiscovery = await (await fetch(opts.serverBase + '/.well-known/afauth')).json();
  const serviceDid = serviceDiscovery.service_did;
  assert(/^did:web:/.test(serviceDid), `expected did:web:, got ${serviceDid}`);

  r = await runCli(opts, ['trust', 'token', serviceDid]);
  assert(r.code === 0, `trust token: ${r.stderr}`);
  const jwt = r.stdout.trim();
  assert(/^ey/.test(jwt), `expected JWT, got: ${jwt.slice(0, 40)}`);

  // 3. Sign up against the reference server, presenting the JWT.
  r = await runCli(opts, ['signup', '--attest', jwt, opts.serverBase]);
  assert(r.code === 0, `signup --attest exit ${r.code}: ${r.stderr}`);
  assert(
    r.stdout.includes('signed up to ' + opts.serverBase),
    `signup stdout missing confirmation: ${r.stdout}`,
  );

  // 4. Ledger persisted with UNCLAIMED state — proves the server
  //    accepted the attested signup.
  const ledger = JSON.parse(
    fs.readFileSync(path.join(opts.tmpDir, 'accounts.json'), 'utf8'),
  );
  const entries = Object.values(ledger.accounts || {});
  assert(entries.length === 1, `expected 1 ledger entry, got ${entries.length}`);
  assert(entries[0].state === 'UNCLAIMED', `expected UNCLAIMED, got ${entries[0].state}`);
}

/**
 * Scenario 9: attested_only rejection (§9.2).
 *
 * Counterpart to scenario 8: that one proves the accept path
 * (valid attestation lets signup through). This one proves the
 * reject path on a service that REQUIRES attestation, at BOTH
 * layers of defence:
 *
 *   (a) CLI client-side guard — `afauth signup <attested-server>`
 *       with no trust link short-circuits with a helpful error
 *       before hitting the wire. Avoids a wasted round-trip.
 *
 *   (b) Server-side §9.2 enforcement — a raw signed GET /accounts/me
 *       with no `AFAuth-Attestation` header is rejected by the
 *       server with 401 + error code `attestation_required`. This
 *       is the part the spec mandates; the CLI guard is just UX.
 *
 * No ledger row gets written in either case.
 *
 * Catches: regressions in the SDK's §9.2 enforcement order (must
 * reject BEFORE creating the account row), discovery-doc shape
 * drift on the `billing` block, and CLI fail-fast wiring for
 * attested_only services.
 */
async function scenarioAttestedOnlyReject(opts) {
  // 1. Discovery doc must actually advertise attested_only — without
  //    this the rest of the scenario doesn't prove anything.
  const disc = await (await fetch(opts.serverBaseAttested + '/.well-known/afauth')).json();
  assert(
    disc.billing && disc.billing.unclaimed_mode === 'attested_only',
    `discovery: expected unclaimed_mode=attested_only, got ${JSON.stringify(disc.billing)}`,
  );
  assert(
    Array.isArray(disc.billing.accepted_attestors) &&
      disc.billing.accepted_attestors.includes('afauth-trust'),
    `discovery: accepted_attestors missing afauth-trust: ${JSON.stringify(disc.billing.accepted_attestors)}`,
  );

  // 2. afauth init — fresh key. No trust link, no attestation token.
  let r = await runCli(opts, ['init']);
  assert(r.code === 0, `init: ${r.stderr}`);

  // 3. CLI guard: `afauth signup` against an attested_only service
  //    with no trust link MUST fail fast, before hitting the server.
  r = await runCli(opts, ['signup', opts.serverBaseAttested]);
  assert(
    r.code !== 0,
    `signup against attested-only server should have failed, exit=0 stdout=${r.stdout}`,
  );
  assert(
    /trust attestation/i.test(r.stderr) && /afauth trust link/.test(r.stderr),
    `stderr should surface the missing-trust-link guard, got: ${r.stderr}`,
  );

  // 4. Server-side enforcement (the spec part). Craft a raw signed
  //    GET /accounts/me with NO AFAuth-Attestation header and send
  //    it directly. §9.2 says the server MUST 401 with
  //    `attestation_required` and MUST NOT create the account row.
  const agent = loadAgentFromKeyJson(path.join(opts.tmpDir, 'key.json'));
  const targetUri = opts.serverBaseAttested + '/afauth/v1/accounts/me';
  const headers = signGet(agent, targetUri);
  const res = await fetch(targetUri, { method: 'GET', headers });
  await assertErrorEnvelope(res, 401, 'attestation_required');

  // 5. No ledger row was written — §9.2 requires the rejection to
  //    happen before any state transition. The CLI guard didn't get
  //    far enough to write either, but check anyway.
  const ledgerPath = path.join(opts.tmpDir, 'accounts.json');
  if (fs.existsSync(ledgerPath)) {
    const ledger = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
    const entries = Object.values(ledger.accounts || {});
    assert(
      entries.length === 0,
      `expected 0 ledger entries after rejected signup, got ${entries.length}`,
    );
  }
}

/**
 * Scenario 10: owner invitation + claim (§7).
 *
 * The heart of the spec: an UNCLAIMED account becomes CLAIMED
 * after a human completes the two-step verify ceremony.
 *
 *   - CLI: `afauth invite alice@example.com` against the ref server
 *     → server creates pending invitation, the e2e email handler
 *     captures the magic-link details into memory
 *   - harness: GET /e2e/last-invitation → claim token + URL
 *   - harness: POST /e2e/claim with {token, email}; the ref server
 *     synthesises an OwnerSession for that email and calls the
 *     SDK's handleClaimCompletion, transitioning the account
 *   - CLI: `accounts show --refresh` → state is now CLAIMED, owner
 *     identity is the synthetic human
 *
 * Catches: drift between SDK's invitation token generation /
 * recipient handler contract / claim completion / owner-binding
 * persistence. No mock fits in this loop.
 */
async function scenarioOwnerInvitationClaim(opts) {
  const ownerEmail = `e2e-owner-${Date.now()}@example.com`;

  // 1-2. Setup: init + signup.
  let r = await runCli(opts, ['init']);
  assert(r.code === 0, `init: ${r.stderr}`);
  r = await runCli(opts, ['signup', opts.serverBase]);
  assert(r.code === 0, `signup: ${r.stderr}`);

  // 3. afauth invite — agent kicks off the owner-binding ceremony.
  r = await runCli(opts, ['invite', ownerEmail, '--service', opts.serverBase]);
  assert(r.code === 0, `invite exit ${r.code}: ${r.stderr}`);
  assert(
    /invitation .* \(state=INVITED/.test(r.stdout),
    `invite stdout missing INVITED state: ${r.stdout}`,
  );

  // 4. The reference server captured the magic-link details.
  let res = await fetch(opts.serverBase + '/e2e/last-invitation');
  assert(res.ok, `last-invitation fetch failed: ${res.status}`);
  const captured = await res.json();
  assert(
    captured.recipient && captured.recipient.value === ownerEmail,
    `captured invitation recipient mismatch: ${JSON.stringify(captured.recipient)}`,
  );
  assert(
    typeof captured.claim_token === 'string' && captured.claim_token.length > 0,
    'captured invitation missing claim_token',
  );

  // 5. Drive claim completion. The /e2e/claim endpoint synthesises
  //    an OwnerSession from the email and calls the SDK's
  //    handleClaimCompletion.
  res = await fetch(opts.serverBase + '/e2e/claim', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: captured.claim_token, email: ownerEmail }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`e2e claim failed: ${res.status}: ${body.slice(0, 200)}`);
  }
  const claimResp = await res.json();
  assert(
    claimResp.state === 'CLAIMED',
    `claim response state expected CLAIMED, got ${claimResp.state}`,
  );

  // 6. The CLI confirms the new state via accounts show --refresh.
  //    `accounts show` already emits JSON unconditionally.
  r = await runCli(opts, [
    'accounts', 'show', opts.serverBase, '--refresh',
  ]);
  assert(r.code === 0, `accounts show --refresh exit ${r.code}: ${r.stderr}`);
  const entry = JSON.parse(r.stdout);
  assert(
    entry.state === 'CLAIMED',
    `accounts show state expected CLAIMED, got ${entry.state}`,
  );
}

const SCENARIOS = {
  'init-signup': scenarioInitSignup,
  'pre-claim-key-rotate': scenarioPreClaimKeyRotate,
  'trust-link': scenarioTrustLink,
  'negatives': scenarioNegatives,
  'registry-roundtrip': scenarioRegistryRoundTrip,
  'cross-service-portability': scenarioCrossServicePortability,
  'replay-expired': scenarioReplayExpired,
  'trust-attestation': scenarioTrustAttestation,
  'attested-only-reject': scenarioAttestedOnlyReject,
  'owner-invitation-claim': scenarioOwnerInvitationClaim,
};

// ---------- runner ----------

function makeOpts() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'afauth-e2e-'));
  return { ...DEFAULTS, tmpDir };
}

function cleanupOpts(opts) {
  try { fs.rmSync(opts.tmpDir, { recursive: true, force: true }); } catch { /* noop */ }
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--list')) {
    for (const name of Object.keys(SCENARIOS)) console.log(name);
    return;
  }

  const idx = args.indexOf('--scenario');
  const selected = idx >= 0 && args[idx + 1] ? [args[idx + 1]] : Object.keys(SCENARIOS);
  const unknown = selected.filter((n) => !(n in SCENARIOS));
  if (unknown.length) {
    console.error(`unknown scenario(s): ${unknown.join(', ')}`);
    console.error(`available: ${Object.keys(SCENARIOS).join(', ')}`);
    process.exit(2);
  }

  try {
    // Preflight against shared opts so we don't bother making a tmp
    // dir if the stack is down.
    await preflight(DEFAULTS);
  } catch (e) {
    console.error(`PRE   ${e.message}`);
    console.error('hint: run ./scripts/up.sh first');
    process.exit(1);
  }

  let pass = 0;
  let fail = 0;
  for (const name of selected) {
    // Each scenario gets its own AFAUTH_HOME so state doesn't bleed.
    const opts = makeOpts();
    try {
      await SCENARIOS[name](opts);
      console.log(`PASS  ${name}`);
      pass++;
    } catch (e) {
      console.log(`FAIL  ${name}`);
      console.log(`      ${e.message}`);
      if (e.stack) console.log(e.stack.split('\n').slice(1, 4).map((l) => '      ' + l.trim()).join('\n'));
      fail++;
    } finally {
      cleanupOpts(opts);
    }
  }

  console.log('');
  console.log(`${pass} passed, ${fail} failed (of ${pass + fail})`);
  process.exit(fail > 0 ? 1 : 0);
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

module.exports = { SCENARIOS, runCli, runCliStreaming, preflight, decodeJwtPayload };
