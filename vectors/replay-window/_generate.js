#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Generator for AFAuth §C.6 replay-window test vectors. Each vector
// describes a signed request that a conformant Verifier MUST reject
// (or in the cross-keyid case, MUST accept) given a specified
// verifier "now" time. The signing path matches §C.1 / §C.2.
//
// Vector shape extends the §C.1/§C.2 vector with:
//   - `verifier_now_unix_seconds`: the value `now` the verifier
//     should use when evaluating this request.
//   - `expected_outcome`:
//        { "type": "reject", "code": "<§11.3 code>", "status": <int> }
//      or
//        { "type": "accept" }
//   - `extra_setup`: optional. Currently used only by the cross-keyid
//     vector to indicate that a different (keyid, nonce) was inserted
//     first.
//
// Run from this directory:  node _generate.js

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYPAIR = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'keypair.json'), 'utf8'));
const SEED = Buffer.from(KEYPAIR.private_key_raw_hex, 'hex');

const PRIV = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEED]),
  format: 'der',
  type: 'pkcs8',
});

const KEYID = KEYPAIR.did_key;
const ALG = 'ed25519';

// Each fixture's `verifier_now_unix_seconds` is chosen so the
// expected outcome holds with the v0.1 default clockSkewSeconds=5.
const FIXTURES = [
  {
    name: 'expired-signature',
    description:
      'Signature whose `expires` parameter is well in the past relative to the verifier\'s `now`. Verifier MUST reject with `expired_signature` (§5.6, §11.3).',
    method: 'GET',
    target_uri: 'https://api.example.com/afauth/v1/accounts/me',
    body: null,
    covered_components: ['@method', '@target-uri'],
    signature_params: {
      created: 1715000000,
      expires: 1715000060,
      nonce: 'a1b2c3d4e5f60718',
    },
    verifier_now_unix_seconds: 1715005000, // ~83 minutes after expires
    expected_outcome: { type: 'reject', code: 'expired_signature', status: 401 },
  },
  {
    name: 'future-dated-signature',
    description:
      'Signature whose `created` parameter is significantly in the future relative to the verifier\'s `now` (well beyond the configured clockSkew). Verifier MUST reject with `invalid_signature` (§5.6, §11.3).',
    method: 'GET',
    target_uri: 'https://api.example.com/afauth/v1/accounts/me',
    body: null,
    covered_components: ['@method', '@target-uri'],
    signature_params: {
      created: 1716000000,
      expires: 1716000060,
      nonce: 'b2c3d4e5f6071829',
    },
    verifier_now_unix_seconds: 1715000000, // 1,000,000 s before created — well beyond skew
    expected_outcome: { type: 'reject', code: 'invalid_signature', status: 401 },
  },
  {
    name: 'fresh-signature-accepted',
    description:
      'Signature whose `created` ≤ `verifier_now` ≤ `expires`. Verifier MUST accept. This is the positive control for the replay-window suite — implementations that reject this are wrong, not the vector. The same request submitted twice on the same nonce store MUST be rejected on the second submission with `replayed_nonce`; the replay property is exercised by re-running this vector through the same Verifier instance.',
    method: 'GET',
    target_uri: 'https://api.example.com/afauth/v1/accounts/me',
    body: null,
    covered_components: ['@method', '@target-uri'],
    signature_params: {
      created: 1715000000,
      expires: 1715000060,
      nonce: 'c3d4e5f607182930',
    },
    verifier_now_unix_seconds: 1715000030, // halfway through window
    expected_outcome: { type: 'accept' },
    replay_behaviour:
      'A second verification of this same vector through the same Verifier (same nonce store) MUST reject with `replayed_nonce` (status 401).',
  },
  {
    name: 'cross-keyid-nonce-reuse',
    description:
      'Two requests share the same `nonce` value but use distinct `keyid`s. Per §5.6, the nonce-uniqueness invariant is scoped to (keyid, nonce), so this MUST be accepted — re-using a nonce across DIDs is not a replay.',
    method: 'GET',
    target_uri: 'https://api.example.com/afauth/v1/accounts/me',
    body: null,
    covered_components: ['@method', '@target-uri'],
    signature_params: {
      created: 1715000000,
      expires: 1715000060,
      // Same nonce as `fresh-signature-accepted`; different (effective)
      // keyid — see extra_setup below.
      nonce: 'c3d4e5f607182930',
    },
    verifier_now_unix_seconds: 1715000030,
    expected_outcome: { type: 'accept' },
    extra_setup: {
      kind: 'prime_nonce_under_other_keyid',
      other_keyid: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoom5bxQbCDuJ3LZTW',
      note:
        'Before verifying this vector, the harness inserts (other_keyid, "c3d4e5f607182930") into the nonce store. The vector\'s own (keyid, nonce) is still fresh from the verifier\'s perspective and MUST be accepted.',
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
  const canonicalInput = buildSignatureInput(fixture, contentDigest);
  const signatureHex = crypto.sign(null, Buffer.from(canonicalInput, 'utf8'), PRIV).toString('hex');

  const vector = {
    name: fixture.name,
    description: fixture.description,
    section: 'C.6',
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
    verifier_now_unix_seconds: fixture.verifier_now_unix_seconds,
    expected_outcome: fixture.expected_outcome,
  };
  if (fixture.replay_behaviour) vector.replay_behaviour = fixture.replay_behaviour;
  if (fixture.extra_setup) vector.extra_setup = fixture.extra_setup;
  return vector;
}

let regenerated = 0;
let changed = 0;
for (const fixture of FIXTURES) {
  const vector = generate(fixture);
  const file = path.join(__dirname, `${fixture.name}.json`);
  const newContent = JSON.stringify(vector, null, 2) + '\n';
  let oldContent = null;
  try {
    oldContent = fs.readFileSync(file, 'utf8');
  } catch (_) {}
  if (oldContent !== newContent) {
    fs.writeFileSync(file, newContent);
    changed++;
  }
  regenerated++;
}
console.log(`Generated ${regenerated} replay-window vector(s); ${changed} changed.`);
