#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// AFAuth conformance harness — minimum viable.
//
// Loads every JSON vector under ../vectors/signatures/ and runs two checks:
//
//   1. Canonical-input check.   Re-build the canonical signature input from
//      the vector's request + covered_components + signature_params, and
//      assert byte-equality with the committed `canonical_signature_input`.
//
//   2. Signature verification.  Resolve the public key from the vector's
//      `keyid` (a did:key) and verify the committed `signature_hex` against
//      the canonical input. Asserts Ed25519 acceptance.
//
// Exits non-zero on any failure.
//
// Usage:
//
//   node harness/run.js                       # run all vectors (default)
//   node harness/run.js <vector-name>...      # run only the named vectors
//
// This harness verifies that the committed vectors are internally consistent.
// To validate a third-party implementation, import the helpers below from
// your own test runner — `buildCanonicalInput`, `verifySignature`, and
// `decodeDidKey` are the integration surface.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const VECTORS_DIR = path.join(__dirname, '..', 'vectors', 'signatures');

// ---------- did:key decoding ----------

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX = (() => {
  const m = new Map();
  for (let i = 0; i < BASE58_ALPHABET.length; i++) m.set(BASE58_ALPHABET[i], i);
  return m;
})();

function base58btcDecode(str) {
  let n = 0n;
  for (const ch of str) {
    const v = BASE58_INDEX.get(ch);
    if (v === undefined) throw new Error(`invalid base58 character: ${ch}`);
    n = n * 58n + BigInt(v);
  }
  // Recover leading zero bytes.
  let leadingZeros = 0;
  for (const ch of str) {
    if (ch === '1') leadingZeros++;
    else break;
  }
  const hex = n.toString(16);
  const padded = hex.length % 2 === 0 ? hex : '0' + hex;
  const bodyBytes = padded === '0' ? Buffer.alloc(0) : Buffer.from(padded, 'hex');
  return Buffer.concat([Buffer.alloc(leadingZeros), bodyBytes]);
}

function decodeDidKey(did) {
  if (!did.startsWith('did:key:z')) throw new Error(`not a did:key: ${did}`);
  const multibase = did.slice('did:key:'.length);
  if (multibase[0] !== 'z') throw new Error(`unsupported multibase prefix: ${multibase[0]}`);
  const decoded = base58btcDecode(multibase.slice(1));
  if (decoded.length < 2) throw new Error('did:key payload too short');
  // Multicodec varint. For ed25519-pub the varint is two bytes: 0xed 0x01.
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error(`unsupported multicodec prefix: 0x${decoded[0].toString(16)}${decoded[1].toString(16)} (only ed25519-pub 0xed01 is supported in v0.1)`);
  }
  const pubKey = decoded.slice(2);
  if (pubKey.length !== 32) throw new Error(`ed25519 public key must be 32 bytes, got ${pubKey.length}`);
  return pubKey;
}

function ed25519PublicKeyFromRaw(raw) {
  // Wrap raw 32 bytes in SPKI DER for Node's crypto API.
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  return crypto.createPublicKey({
    key: Buffer.concat([spkiPrefix, raw]),
    format: 'der',
    type: 'spki',
  });
}

// ---------- canonical-input construction ----------

function buildCanonicalInput(vector) {
  const lines = [];
  for (const component of vector.covered_components) {
    if (component === '@method') {
      lines.push(`"@method": ${vector.request.method}`);
    } else if (component === '@target-uri') {
      lines.push(`"@target-uri": ${vector.request.target_uri}`);
    } else if (component === 'content-digest') {
      if (vector.content_digest === null) {
        throw new Error(`covered_components has content-digest but vector.content_digest is null`);
      }
      lines.push(`"content-digest": ${vector.content_digest}`);
    } else {
      throw new Error(`unknown covered component: ${component}`);
    }
  }
  const componentList = vector.covered_components.map(c => `"${c}"`).join(' ');
  const p = vector.signature_params;
  const paramStr =
    `created=${p.created};` +
    `expires=${p.expires};` +
    `nonce="${p.nonce}";` +
    `keyid="${p.keyid}";` +
    `alg="${p.alg}"`;
  lines.push(`"@signature-params": (${componentList});${paramStr}`);
  return lines.join('\n');
}

// ---------- verification ----------

function verifySignature(canonicalInput, signatureHex, didKey) {
  const rawPub = decodeDidKey(didKey);
  const pubKey = ed25519PublicKeyFromRaw(rawPub);
  const sig = Buffer.from(signatureHex, 'hex');
  return crypto.verify(null, Buffer.from(canonicalInput, 'utf8'), pubKey, sig);
}

function verifyContentDigest(vector) {
  if (vector.request.body === null || vector.request.body === undefined) {
    return vector.content_digest === null;
  }
  const hash = crypto.createHash('sha256').update(vector.request.body, 'utf8').digest('base64');
  return vector.content_digest === `sha-256=:${hash}:`;
}

// ---------- per-vector check ----------

function checkVector(vector) {
  const errors = [];

  // 1. Content digest matches body
  if (!verifyContentDigest(vector)) {
    errors.push(`content_digest does not match SHA-256 of body`);
  }

  // 2. Canonical input round-trips
  const rebuilt = buildCanonicalInput(vector);
  if (rebuilt !== vector.canonical_signature_input) {
    errors.push(`canonical_signature_input mismatch`);
    errors.push(`  expected: ${JSON.stringify(vector.canonical_signature_input)}`);
    errors.push(`  rebuilt:  ${JSON.stringify(rebuilt)}`);
  }

  // 3. Signature verifies
  try {
    const ok = verifySignature(vector.canonical_signature_input, vector.signature_hex, vector.public_key_did);
    if (!ok) errors.push(`signature_hex did not verify under public_key_did`);
  } catch (e) {
    errors.push(`signature verification threw: ${e.message}`);
  }

  // 4. keyid in signature_params matches public_key_did
  if (vector.signature_params.keyid !== vector.public_key_did) {
    errors.push(`signature_params.keyid (${vector.signature_params.keyid}) != public_key_did (${vector.public_key_did})`);
  }

  return { ok: errors.length === 0, errors };
}

// ---------- main ----------

function loadVectors() {
  const filenames = fs.readdirSync(VECTORS_DIR)
    .filter(f => f.endsWith('.json'))
    .filter(f => !f.startsWith('_'))
    .sort();
  return filenames.map(f => {
    const full = path.join(VECTORS_DIR, f);
    return { file: f, vector: JSON.parse(fs.readFileSync(full, 'utf8')) };
  });
}

function main() {
  const requestedNames = process.argv.slice(2);
  const all = loadVectors();
  const targets = requestedNames.length === 0
    ? all
    : all.filter(v => requestedNames.includes(v.vector.name));

  if (requestedNames.length > 0 && targets.length !== requestedNames.length) {
    const have = new Set(all.map(v => v.vector.name));
    const missing = requestedNames.filter(n => !have.has(n));
    console.error(`unknown vector(s): ${missing.join(', ')}`);
    process.exit(2);
  }

  let pass = 0, fail = 0;
  for (const { file, vector } of targets) {
    const result = checkVector(vector);
    if (result.ok) {
      console.log(`PASS  ${vector.name}`);
      pass++;
    } else {
      console.log(`FAIL  ${vector.name}  (${file})`);
      for (const e of result.errors) console.log(`      ${e}`);
      fail++;
    }
  }
  console.log(``);
  console.log(`${pass} passed, ${fail} failed (of ${targets.length})`);
  process.exit(fail > 0 ? 1 : 0);
}

if (require.main === module) main();

module.exports = {
  buildCanonicalInput,
  verifySignature,
  verifyContentDigest,
  decodeDidKey,
  ed25519PublicKeyFromRaw,
  checkVector,
  loadVectors,
};
