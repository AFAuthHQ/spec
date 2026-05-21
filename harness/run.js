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
const ERRORS_DIR = path.join(__dirname, '..', 'vectors', 'errors');
const REPLAY_DIR = path.join(__dirname, '..', 'vectors', 'replay-window');

// §11.3 reserved codes.
const RESERVED_ERROR_CODES = new Set([
  'invalid_signature', 'expired_signature', 'replayed_nonce',
  'unknown_account', 'revoked_key', 'invalid_attestation',
  'attestation_required', 'invitation_expired', 'invitation_not_found',
  'already_claimed', 'not_claimed', 'owner_authentication_required',
  'owner_binding_blocked', 'account_expired', 'rate_limit_exceeded',
  'malformed_request', 'unsupported_recipient_type',
]);

// §11.2 status codes.
const ALLOWED_STATUSES = new Set([400, 401, 403, 404, 409, 410, 429, 503]);

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

// ---------- C.5 error-envelope checks ----------

function checkErrorVector(vector) {
  const errors = [];
  if (vector.name !== vector.code) {
    errors.push(`name (${vector.name}) must equal code (${vector.code})`);
  }
  if (!RESERVED_ERROR_CODES.has(vector.code)) {
    errors.push(`code "${vector.code}" is not in §11.3 reserved set`);
  }
  if (!ALLOWED_STATUSES.has(vector.http_status)) {
    errors.push(`http_status ${vector.http_status} not in §11.2 set`);
  }
  if (!vector.envelope || typeof vector.envelope !== 'object') {
    errors.push('envelope must be an object');
  } else if (!vector.envelope.error || typeof vector.envelope.error !== 'object') {
    errors.push('envelope.error must be an object');
  } else {
    const e = vector.envelope.error;
    if (e.code !== vector.code) errors.push(`envelope.error.code (${e.code}) must equal code (${vector.code})`);
    if (typeof e.message !== 'string') errors.push('envelope.error.message must be a string');
    const allowed = new Set(['code', 'message', 'details']);
    for (const k of Object.keys(e)) {
      if (!allowed.has(k)) errors.push(`envelope.error has unexpected key "${k}" (allowed: code, message, details)`);
    }
  }
  return { ok: errors.length === 0, errors };
}

// ---------- C.6 replay-window checks ----------

class HarnessNonceStore {
  constructor() { this.seenSet = new Map(); }
  seen(keyid, nonce) {
    const key = `${keyid}\x00${nonce}`;
    if (this.seenSet.has(key)) return false;
    this.seenSet.set(key, true);
    return true;
  }
}

// Self-contained verifier mirroring the §5.5/§5.6 procedure.
// Returns { ok: true } on accept; { ok: false, code, status } on reject.
// `now` is unix seconds; `clockSkewSeconds` defaults to 5.
function verifyForReplayCheck(vector, opts) {
  const { now, nonceStore, clockSkewSeconds = 5, maxSignatureLifetimeSeconds = 300 } = opts;
  const p = vector.signature_params;

  if (!Number.isInteger(p.created) || !Number.isInteger(p.expires)) {
    return { ok: false, code: 'invalid_signature', status: 401, reason: 'created/expires must be integers' };
  }
  if (p.expires <= p.created) {
    return { ok: false, code: 'invalid_signature', status: 401, reason: 'expires must be > created' };
  }
  if (p.expires - p.created > maxSignatureLifetimeSeconds) {
    return { ok: false, code: 'invalid_signature', status: 401, reason: 'lifetime exceeds maximum' };
  }
  if (now < p.created - clockSkewSeconds) {
    return { ok: false, code: 'invalid_signature', status: 401, reason: 'future-dated' };
  }
  if (now > p.expires + clockSkewSeconds) {
    return { ok: false, code: 'expired_signature', status: 401, reason: 'expired' };
  }

  const sigOk = verifySignature(vector.canonical_signature_input, vector.signature_hex, vector.public_key_did);
  if (!sigOk) {
    return { ok: false, code: 'invalid_signature', status: 401, reason: 'signature did not verify' };
  }

  const fresh = nonceStore.seen(p.keyid, p.nonce);
  if (!fresh) {
    return { ok: false, code: 'replayed_nonce', status: 401, reason: 'nonce replayed' };
  }

  return { ok: true };
}

function checkReplayVector(vector) {
  const errors = [];
  const nonceStore = new HarnessNonceStore();
  if (vector.extra_setup?.kind === 'prime_nonce_under_other_keyid') {
    nonceStore.seen(vector.extra_setup.other_keyid, vector.signature_params.nonce);
  }
  const first = verifyForReplayCheck(vector, {
    now: vector.verifier_now_unix_seconds,
    nonceStore,
  });
  const expected = vector.expected_outcome;
  if (expected.type === 'accept') {
    if (!first.ok) {
      errors.push(`expected accept, got reject (${first.code}: ${first.reason})`);
    }
    // Replay invariant: re-verify and expect replayed_nonce.
    if (vector.replay_behaviour && first.ok) {
      const second = verifyForReplayCheck(vector, {
        now: vector.verifier_now_unix_seconds,
        nonceStore,
      });
      if (second.ok) {
        errors.push('second verification accepted; expected replayed_nonce');
      } else if (second.code !== 'replayed_nonce') {
        errors.push(`second verification rejected with ${second.code}; expected replayed_nonce`);
      }
    }
  } else if (expected.type === 'reject') {
    if (first.ok) {
      errors.push(`expected reject ${expected.code}, got accept`);
    } else if (first.code !== expected.code) {
      errors.push(`expected code ${expected.code}, got ${first.code} (${first.reason})`);
    } else if (first.status !== expected.status) {
      errors.push(`expected status ${expected.status}, got ${first.status}`);
    }
  } else {
    errors.push(`unknown expected_outcome.type: ${expected.type}`);
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

function loadDir(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.json') && !f.startsWith('_'))
    .sort()
    .map(f => ({
      file: f,
      vector: JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')),
    }));
}

function runSuite(label, vectors, checker) {
  let pass = 0, fail = 0;
  for (const { file, vector } of vectors) {
    const result = checker(vector);
    if (result.ok) {
      console.log(`PASS  ${label}/${vector.name}`);
      pass++;
    } else {
      console.log(`FAIL  ${label}/${vector.name}  (${file})`);
      for (const e of result.errors) console.log(`      ${e}`);
      fail++;
    }
  }
  return { pass, fail };
}

function main() {
  const requestedNames = process.argv.slice(2);
  const sigs = loadVectors();
  const errs = loadDir(ERRORS_DIR);
  const replays = loadDir(REPLAY_DIR);

  if (requestedNames.length > 0) {
    const all = [...sigs, ...errs, ...replays];
    const have = new Set(all.map(v => v.vector.name));
    const missing = requestedNames.filter(n => !have.has(n));
    if (missing.length > 0) {
      console.error(`unknown vector(s): ${missing.join(', ')}`);
      process.exit(2);
    }
    const filter = (set) => set.filter(v => requestedNames.includes(v.vector.name));
    const totals = [
      runSuite('signatures',     filter(sigs),    checkVector),
      runSuite('errors',         filter(errs),    checkErrorVector),
      runSuite('replay-window',  filter(replays), checkReplayVector),
    ].reduce((a, b) => ({ pass: a.pass + b.pass, fail: a.fail + b.fail }), { pass: 0, fail: 0 });
    console.log(``);
    console.log(`${totals.pass} passed, ${totals.fail} failed`);
    process.exit(totals.fail > 0 ? 1 : 0);
  }

  const r1 = runSuite('signatures',    sigs,    checkVector);
  const r2 = runSuite('errors',        errs,    checkErrorVector);
  const r3 = runSuite('replay-window', replays, checkReplayVector);
  const totals = { pass: r1.pass + r2.pass + r3.pass, fail: r1.fail + r2.fail + r3.fail };
  const grandTotal = totals.pass + totals.fail;
  console.log(``);
  console.log(`${totals.pass} passed, ${totals.fail} failed (of ${grandTotal})`);
  process.exit(totals.fail > 0 ? 1 : 0);
}

if (require.main === module) main();

module.exports = {
  buildCanonicalInput,
  verifySignature,
  verifyContentDigest,
  decodeDidKey,
  ed25519PublicKeyFromRaw,
  checkVector,
  checkErrorVector,
  checkReplayVector,
  verifyForReplayCheck,
  loadVectors,
  loadDir,
  ERRORS_DIR,
  REPLAY_DIR,
  RESERVED_ERROR_CODES,
  ALLOWED_STATUSES,
};
