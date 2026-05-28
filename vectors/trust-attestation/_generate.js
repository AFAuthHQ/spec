// SPDX-License-Identifier: Apache-2.0
//
// Deterministic test-vector generator for AFAP-0006 §10 trust-attestation
// verification. Mints EdDSA-signed JWTs from a fixed seed and a fixed
// K_pseudonym so the same fixture inputs always produce the same JWT,
// kid, and sub_h values. Vector consumers reproduce verification offline
// against the embedded JWKS and the verification_inputs.
//
// Usage: node _generate.js

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------
// Fixed cryptographic material (TEST ONLY)
// ---------------------------------------------------------------------

const ATTESTOR_SEED_HEX =
  'a1b2c3d4e5f6071829374a5b6c7d8e9faabbccddeeff00112233445566778899';
const ATTESTOR_KID = 'tk-vectors-2024-05';
const K_PSEUDONYM = crypto
  .createHash('sha256')
  .update('afauth-trust-vectors-pseudonym-key-v1')
  .digest();

// Reconstitute the EdDSA private key from the raw 32-byte seed.
const ATTESTOR_PRIV = crypto.createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(ATTESTOR_SEED_HEX, 'hex'),
  ]),
  format: 'der',
  type: 'pkcs8',
});
const ATTESTOR_PUB = crypto.createPublicKey(ATTESTOR_PRIV);
const ATTESTOR_PUB_JWK = ATTESTOR_PUB.export({ format: 'jwk' });
ATTESTOR_PUB_JWK.kid = ATTESTOR_KID;
ATTESTOR_PUB_JWK.use = 'sig';
ATTESTOR_PUB_JWK.alg = 'EdDSA';

const JWKS = { keys: [ATTESTOR_PUB_JWK] };

// ---------------------------------------------------------------------
// Fixed claim material
// ---------------------------------------------------------------------

const AGENT_DID = 'did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr';
const SERVICE_DID = 'did:web:svc.example';
const HUMAN_ID = '00000000-0000-4000-8000-000000000001';
const IAT = 1715000000;
const EXP = IAT + 900;

// §10.4.3 — sub_h = base64url(HMAC-SHA256(K_pseudonym, principal_id ':' aud))
function deriveSubH(principalId, aud) {
  return crypto
    .createHmac('sha256', K_PSEUDONYM)
    .update(`${principalId}:${aud}`)
    .digest('base64url');
}

// ---------------------------------------------------------------------
// JWT minting (no external dep, so the generator stays portable)
// ---------------------------------------------------------------------

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function mintJwt(payload) {
  const header = { alg: 'EdDSA', typ: 'JWT', kid: ATTESTOR_KID };
  const encodedHeader = b64url(JSON.stringify(header));
  const encodedPayload = b64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const sig = crypto.sign(null, Buffer.from(signingInput), ATTESTOR_PRIV);
  return {
    jwt: `${signingInput}.${b64url(sig)}`,
    header,
    payload,
  };
}

// ---------------------------------------------------------------------
// Vector fixtures
// ---------------------------------------------------------------------

const FIXTURES = [
  {
    name: 'well-formed',
    description:
      'Canonical afauth-trust JWT: iss, aud, sub, iat, exp, verification, sub_h all present and well-formed. A conforming verifier MUST accept.',
    payload: {
      iss: 'afauth-trust',
      sub: AGENT_DID,
      aud: SERVICE_DID,
      iat: IAT,
      exp: EXP,
      verification: 'oauth',
      sub_h: deriveSubH(HUMAN_ID, SERVICE_DID),
    },
    expected: { accept: true, error_code: null },
  },
  {
    name: 'missing-sub-h',
    description:
      '§10.4.1 — verification present but sub_h absent. A conforming verifier MUST reject with invalid_attestation.',
    payload: {
      iss: 'afauth-trust',
      sub: AGENT_DID,
      aud: SERVICE_DID,
      iat: IAT,
      exp: EXP,
      verification: 'oauth',
    },
    expected: { accept: false, error_code: 'invalid_attestation' },
  },
  {
    name: 'malformed-sub-h-short',
    description:
      '§10.4.2 — sub_h shorter than 22 base64url chars. A conforming verifier MUST reject with invalid_attestation.',
    payload: {
      iss: 'afauth-trust',
      sub: AGENT_DID,
      aud: SERVICE_DID,
      iat: IAT,
      exp: EXP,
      verification: 'oauth',
      sub_h: 'tooShort',
    },
    expected: { accept: false, error_code: 'invalid_attestation' },
  },
  {
    name: 'malformed-sub-h-non-base64url',
    description:
      '§10.4.2 — sub_h contains base64-standard characters (+, /, =) not permitted by the base64url alphabet. A conforming verifier MUST reject with invalid_attestation.',
    payload: {
      iss: 'afauth-trust',
      sub: AGENT_DID,
      aud: SERVICE_DID,
      iat: IAT,
      exp: EXP,
      verification: 'oauth',
      sub_h: 'has+plus/and=padding-which-violates-base64url-shape',
    },
    expected: { accept: false, error_code: 'invalid_attestation' },
  },
  {
    name: 'runtime-only-no-binding',
    description:
      '§10.4.1 — attestor does not assert a human binding (no verification claim). sub_h is permitted to be absent. A conforming verifier MUST accept.',
    payload: {
      iss: 'afauth-trust',
      sub: AGENT_DID,
      aud: SERVICE_DID,
      iat: IAT,
      exp: EXP,
    },
    expected: { accept: true, error_code: null },
  },
];

// ---------------------------------------------------------------------
// Emit
// ---------------------------------------------------------------------

for (const f of FIXTURES) {
  const { jwt, header, payload } = mintJwt(f.payload);
  const vector = {
    name: f.name,
    description: f.description,
    section: '§10.4',
    jwt,
    header_decoded: header,
    payload_decoded: payload,
    jwks: JWKS,
    verification_inputs: {
      expected_aud: SERVICE_DID,
      expected_agent_did: AGENT_DID,
      now_unix: IAT + 10,
    },
    expected: f.expected,
  };
  const outPath = path.join(__dirname, `${f.name}.json`);
  fs.writeFileSync(outPath, JSON.stringify(vector, null, 2) + '\n');
  console.log(`wrote ${path.basename(outPath)}`);
}
