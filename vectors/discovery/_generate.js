#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Generator for AFAuth §C.3 discovery-document parsing vectors.
// Each fixture carries a candidate document and the expected parse
// outcome (accept or reject). Reasons on reject vectors are
// informational — implementations may produce different error
// messages.
//
// Run from this directory:  node _generate.js

'use strict';

const fs = require('fs');
const path = require('path');

const BASE = {
  afauth_version: '0.1',
  service_did: 'did:web:api.example.com',
  endpoints: {
    accounts: '/afauth/v1/accounts',
    owner_invitation: '/afauth/v1/accounts/me/owner-invitation',
    claim_page: 'https://claim.example.com',
    claim_completion: '/afauth/v1/claim',
  },
  signature_algorithms: ['ed25519'],
};

const VECTORS = [
  // ---------- Well-formed (accept) ----------
  {
    name: 'well-formed-minimal',
    description:
      'Minimal v0.1 document — only the §4.3 required fields. Implementations MUST accept.',
    document: { ...BASE },
    expected: { type: 'accept' },
  },
  {
    name: 'well-formed-with-features',
    description: 'Adds the optional `features` field (§4.4).',
    document: { ...BASE, features: ['key_rotation'] },
    expected: { type: 'accept' },
  },
  {
    name: 'well-formed-with-recipient-types',
    description: 'Adds the optional `recipient_types` field (§4.4).',
    document: { ...BASE, recipient_types: ['email', 'oidc'] },
    expected: { type: 'accept' },
  },
  {
    name: 'well-formed-with-limits',
    description: 'Adds the optional `limits` field (§4.4).',
    document: {
      ...BASE,
      limits: { unclaimed_ttl_seconds: 2592000, unclaimed_rate_limit_per_hour: 100 },
    },
    expected: { type: 'accept' },
  },
  {
    name: 'well-formed-with-billing',
    description: 'Adds the optional `billing` declaration (§4.4 / §9).',
    document: {
      ...BASE,
      billing: { unclaimed_mode: 'free', accepted_attestors: ['stripe-projects'] },
    },
    expected: { type: 'accept' },
  },
  {
    name: 'well-formed-complete',
    description: 'All optional fields populated, plus the key_rotation endpoint.',
    document: {
      ...BASE,
      endpoints: { ...BASE.endpoints, key_rotation: '/afauth/v1/accounts/me/keys/rotate' },
      features: ['key_rotation', 'attestation'],
      recipient_types: ['email', 'phone', 'oidc', 'did'],
      limits: { unclaimed_ttl_seconds: 2592000, unclaimed_rate_limit_per_hour: 100 },
      billing: { unclaimed_mode: 'free', accepted_attestors: ['stripe-projects'] },
    },
    expected: { type: 'accept' },
  },

  // ---------- Forward-compatible (accept; §4.2) ----------
  {
    name: 'forward-compat-unknown-top-level-field',
    description:
      'Adds an unknown top-level field. §4.2 MUST treat as opaque and accept.',
    document: { ...BASE, future_field: { x: 1 } },
    expected: { type: 'accept' },
  },
  {
    name: 'forward-compat-unknown-endpoint-key',
    description:
      'Adds an unknown key inside endpoints. §4.2 forward-compatibility applies; accept.',
    document: {
      ...BASE,
      endpoints: { ...BASE.endpoints, future_endpoint: '/afauth/v1/future' },
    },
    expected: { type: 'accept' },
  },

  // ---------- Malformed (reject) ----------
  {
    name: 'reject-wrong-version',
    description: 'afauth_version is not "0.1". Implementations MUST reject.',
    document: { ...BASE, afauth_version: '0.2' },
    expected: { type: 'reject', reason: 'afauth_version is not "0.1"' },
  },
  {
    name: 'reject-missing-service-did',
    description: '§4.3 service_did is required.',
    document: (() => { const d = { ...BASE }; delete d.service_did; return d; })(),
    expected: { type: 'reject', reason: 'missing required field service_did' },
  },
  {
    name: 'reject-missing-endpoints',
    description: '§4.3 endpoints object is required.',
    document: (() => { const d = { ...BASE }; delete d.endpoints; return d; })(),
    expected: { type: 'reject', reason: 'missing required field endpoints' },
  },
  {
    name: 'reject-missing-endpoints-accounts',
    description: '§4.3 endpoints.accounts is required.',
    document: { ...BASE, endpoints: (() => { const e = { ...BASE.endpoints }; delete e.accounts; return e; })() },
    expected: { type: 'reject', reason: 'missing required endpoints.accounts' },
  },
  {
    name: 'reject-missing-endpoints-owner-invitation',
    description: '§4.3 endpoints.owner_invitation is required.',
    document: { ...BASE, endpoints: (() => { const e = { ...BASE.endpoints }; delete e.owner_invitation; return e; })() },
    expected: { type: 'reject', reason: 'missing required endpoints.owner_invitation' },
  },
  {
    name: 'reject-missing-endpoints-claim-page',
    description: '§4.3 endpoints.claim_page is required.',
    document: { ...BASE, endpoints: (() => { const e = { ...BASE.endpoints }; delete e.claim_page; return e; })() },
    expected: { type: 'reject', reason: 'missing required endpoints.claim_page' },
  },
  {
    name: 'reject-missing-endpoints-claim-completion',
    description: '§4.3 endpoints.claim_completion is required.',
    document: { ...BASE, endpoints: (() => { const e = { ...BASE.endpoints }; delete e.claim_completion; return e; })() },
    expected: { type: 'reject', reason: 'missing required endpoints.claim_completion' },
  },
  {
    name: 'reject-missing-signature-algorithms',
    description: '§4.3 signature_algorithms is required.',
    document: (() => { const d = { ...BASE }; delete d.signature_algorithms; return d; })(),
    expected: { type: 'reject', reason: 'missing required field signature_algorithms' },
  },
  {
    name: 'reject-signature-algorithms-not-array',
    description: 'signature_algorithms must be an array.',
    document: { ...BASE, signature_algorithms: 'ed25519' },
    expected: { type: 'reject', reason: 'signature_algorithms must be an array' },
  },
  {
    name: 'reject-missing-ed25519-from-algorithms',
    description:
      '§4.5: services MUST include ed25519 to be v0.1-conformant; agents MUST honour signature_algorithms.',
    document: { ...BASE, signature_algorithms: ['rsa-sha256'] },
    expected: { type: 'reject', reason: 'service does not advertise ed25519' },
  },
];

const OUT = __dirname;
for (const v of VECTORS) {
  const out = {
    name: v.name,
    description: v.description,
    section: 'C.3',
    document: v.document,
    expected: v.expected,
  };
  fs.writeFileSync(path.join(OUT, `${v.name}.json`), JSON.stringify(out, null, 2) + '\n');
}
console.log(`${VECTORS.length} discovery vectors written.`);
