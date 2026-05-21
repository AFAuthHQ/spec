// SPDX-License-Identifier: Apache-2.0
//
// Test-vector generator for AFAuth §C.1 (canonical signature input) and §C.2
// (reference signatures). Reads the keypair from ../keypair.json, builds the
// canonical input per RFC 9421 §2.5 for each fixture defined below, signs with
// Ed25519, and writes one JSON file per vector into this directory.
//
// Vectors are deterministic: same inputs → same outputs. Re-run after spec
// changes to regenerate. Reviewers should run this script and confirm the
// committed JSON files match the regenerated output.
//
// Usage: node _generate.js

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYPAIR = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'keypair.json'), 'utf8'));
const SEED = Buffer.from(KEYPAIR.private_key_raw_hex, 'hex');

// Reconstitute the private key from the raw 32-byte seed.
const PRIV = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEED]),
  format: 'der',
  type: 'pkcs8',
});

const KEYID = KEYPAIR.did_key;
const ALG = 'ed25519';

// Fixtures: each defines a single request. The generator computes everything
// else (content-digest, canonical input, signature).
const FIXTURES = [
  {
    name: 'get-account-introspection',
    description: 'GET account-introspection request, no body. Exercises a GET signature without content-digest.',
    method: 'GET',
    target_uri: 'https://api.example.com/afauth/v1/accounts/me',
    body: null,
    covered_components: ['@method', '@target-uri'],
    signature_params: {
      created: 1715000000,
      expires: 1715000060,
      nonce: '9f8b3a7c1d2e4f56',
    },
  },
  {
    name: 'post-owner-invitation-email',
    description: 'POST owner-invitation with email recipient body. Exercises a POST with content-digest and a typed recipient.',
    method: 'POST',
    target_uri: 'https://api.example.com/afauth/v1/accounts/me/owner-invitation',
    body: '{"recipient":{"type":"email","value":"alice@example.com"}}',
    covered_components: ['@method', '@target-uri', 'content-digest'],
    signature_params: {
      created: 1715000100,
      expires: 1715000160,
      nonce: '2a4b6c8d0e1f3a5b',
    },
  },
  {
    name: 'post-owner-invitation-phone',
    description: 'POST owner-invitation with phone recipient body. Exercises E.164 in the body.',
    method: 'POST',
    target_uri: 'https://api.example.com/afauth/v1/accounts/me/owner-invitation',
    body: '{"recipient":{"type":"phone","value":"+14155550173"}}',
    covered_components: ['@method', '@target-uri', 'content-digest'],
    signature_params: {
      created: 1715000200,
      expires: 1715000260,
      nonce: '4c6d8e0f2a3b5c7d',
    },
  },
  {
    name: 'post-owner-invitation-oidc',
    description: 'POST owner-invitation with oidc recipient body. Exercises the issuer+sub canonical shape.',
    method: 'POST',
    target_uri: 'https://api.example.com/afauth/v1/accounts/me/owner-invitation',
    body: '{"recipient":{"type":"oidc","value":{"issuer":"https://accounts.google.com","sub":"103948572345"}}}',
    covered_components: ['@method', '@target-uri', 'content-digest'],
    signature_params: {
      created: 1715000300,
      expires: 1715000360,
      nonce: '6e8f0a2b4c6d8e0f',
    },
  },
  {
    name: 'post-owner-invitation-did',
    description: 'POST owner-invitation with did recipient body. Exercises a DID as the recipient identifier.',
    method: 'POST',
    target_uri: 'https://api.example.com/afauth/v1/accounts/me/owner-invitation',
    body: '{"recipient":{"type":"did","value":"did:key:z6MkrJVnaZkeFzdQyMZu1cF5cgqU3MnVKDx7XfsKnvKzpC9k"}}',
    covered_components: ['@method', '@target-uri', 'content-digest'],
    signature_params: {
      created: 1715000400,
      expires: 1715000460,
      nonce: '8a0b2c4d6e8f0a2b',
    },
  },
  {
    name: 'post-key-rotation',
    description: 'POST key-rotation request with new_account_did body. Exercises §8.1 pre-claim rotation.',
    method: 'POST',
    target_uri: 'https://api.example.com/afauth/v1/accounts/me/keys/rotate',
    body: '{"new_account_did":"did:key:z6MkrJVnaZkeFzdQyMZu1cF5cgqU3MnVKDx7XfsKnvKzpC9k"}',
    covered_components: ['@method', '@target-uri', 'content-digest'],
    signature_params: {
      created: 1715000500,
      expires: 1715000560,
      nonce: '0c2d4e6f8a0b2c4d',
    },
  },
  {
    name: 'post-claim-completion',
    description: 'POST claim-completion request, signed by the agent. Exercises a service-recipient-side endpoint.',
    method: 'POST',
    target_uri: 'https://api.example.com/afauth/v1/claim/INV_01H1234567890',
    body: '{"token":"INV_01H1234567890"}',
    covered_components: ['@method', '@target-uri', 'content-digest'],
    signature_params: {
      created: 1715000600,
      expires: 1715000660,
      nonce: '2e4f6a8b0c2d4e6f',
    },
  },
  {
    name: 'get-discovery',
    description: 'GET on a discovery document URL. Demonstrates that AFAuth signatures are not used on /.well-known/afauth (this vector is for harness completeness — the agent does not sign this endpoint in normal use); included to confirm the canonical input for an unsigned-request shape would still validate if produced.',
    method: 'GET',
    target_uri: 'https://api.example.com/.well-known/afauth',
    body: null,
    covered_components: ['@method', '@target-uri'],
    signature_params: {
      created: 1715000700,
      expires: 1715000760,
      nonce: '4a6b8c0d2e4f6a8b',
    },
  },
];

function computeContentDigest(body) {
  if (body === null || body === undefined || body === '') return null;
  const hash = crypto.createHash('sha256').update(body, 'utf8').digest('base64');
  return `sha-256=:${hash}:`;
}

function buildSignatureInput(fixture, contentDigest) {
  const lines = [];
  for (const component of fixture.covered_components) {
    if (component === '@method') {
      lines.push(`"@method": ${fixture.method}`);
    } else if (component === '@target-uri') {
      lines.push(`"@target-uri": ${fixture.target_uri}`);
    } else if (component === 'content-digest') {
      lines.push(`"content-digest": ${contentDigest}`);
    } else {
      throw new Error(`Unknown covered component: ${component}`);
    }
  }
  const componentList = fixture.covered_components.map(c => `"${c}"`).join(' ');
  const params = fixture.signature_params;
  const paramStr =
    `created=${params.created};` +
    `expires=${params.expires};` +
    `nonce="${params.nonce}";` +
    `keyid="${KEYID}";` +
    `alg="${ALG}"`;
  lines.push(`"@signature-params": (${componentList});${paramStr}`);
  return lines.join('\n');
}

function generate(fixture) {
  const contentDigest = computeContentDigest(fixture.body);
  if (contentDigest === null && fixture.covered_components.includes('content-digest')) {
    throw new Error(`${fixture.name}: covered_components includes content-digest but body is empty`);
  }
  if (contentDigest !== null && !fixture.covered_components.includes('content-digest')) {
    throw new Error(`${fixture.name}: body is non-empty but covered_components excludes content-digest`);
  }

  const canonicalInput = buildSignatureInput(fixture, contentDigest);
  const signature = crypto.sign(null, Buffer.from(canonicalInput, 'utf8'), PRIV);
  const signatureHex = signature.toString('hex');

  return {
    name: fixture.name,
    description: fixture.description,
    section: 'C.1, C.2',
    request: {
      method: fixture.method,
      target_uri: fixture.target_uri,
      body: fixture.body,
    },
    content_digest: contentDigest,
    covered_components: fixture.covered_components,
    signature_params: {
      ...fixture.signature_params,
      keyid: KEYID,
      alg: ALG,
    },
    canonical_signature_input: canonicalInput,
    signature_hex: signatureHex,
    public_key_did: KEYID,
  };
}

let regenerated = 0;
let changed = 0;
for (const fixture of FIXTURES) {
  const vector = generate(fixture);
  const filename = path.join(__dirname, `${fixture.name}.json`);
  const newContent = JSON.stringify(vector, null, 2) + '\n';
  let oldContent = null;
  try {
    oldContent = fs.readFileSync(filename, 'utf8');
  } catch (_) {}
  if (oldContent !== newContent) {
    fs.writeFileSync(filename, newContent);
    changed++;
  }
  regenerated++;
}
console.log(`Generated ${regenerated} vector(s); ${changed} changed.`);
