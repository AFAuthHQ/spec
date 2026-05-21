#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Generator for AFAuth §C.5 error-envelope test vectors. One JSON
// fixture per reserved §11.3 code documenting the canonical envelope
// shape (per §11.1) and the expected HTTP status (per §11.2).
//
// Run from this directory:  node _generate.js

'use strict';

const fs = require('fs');
const path = require('path');

// One entry per reserved code in §11.3.
// status:  the HTTP status the §11.2 table maps this code to.
// section: spec sections that produce / define this code.
// message: a representative human-readable message. Implementations
//          are free to vary this — §11.1 makes `message` informational.
const VECTORS = [
  { code: 'invalid_signature',           status: 401, section: '§5.5, §11.3',
    description: 'Signature verification failed, required Signature/Signature-Input headers are missing or malformed, or required canonical components were not signed.',
    message: 'Signature verification failed' },
  { code: 'expired_signature',           status: 401, section: '§5.6, §11.3',
    description: 'The signature\'s `expires` parameter is before the verifier\'s current time minus the configured clock skew.',
    message: 'Signature has expired' },
  { code: 'replayed_nonce',              status: 401, section: '§5.6, §11.3',
    description: 'A (keyid, nonce) pair has been seen before within the signature\'s validity window.',
    message: 'Nonce has been seen before' },
  { code: 'unknown_account',             status: 404, section: '§6.5, §11.3',
    description: 'The referenced account does not exist. Returned only when implicit signup is disabled.',
    message: 'Account not found' },
  { code: 'revoked_key',                 status: 401, section: '§8.3, §11.3',
    description: 'The signing key has been revoked (via rotation per §8.1 or owner-initiated per §8.4).',
    message: 'Account key has been revoked' },
  { code: 'invalid_attestation',         status: 401, section: '§10, §11.3',
    description: 'An attestation header (§10.2) is present but its signature, audience, or expiry is invalid.',
    message: 'Attestation invalid' },
  { code: 'attestation_required',        status: 401, section: '§10, §11.3',
    description: 'The service requires a valid attestation for this operation but none was supplied.',
    message: 'Attestation required' },
  { code: 'invitation_expired',          status: 410, section: '§7.3, §11.3',
    description: 'The pending invitation\'s TTL has elapsed, or the token was atomically replaced by a subsequent invitation per §7.3.',
    message: 'Invitation has expired' },
  { code: 'invitation_not_found',        status: 410, section: '§7.4, §11.3',
    description: 'The supplied claim token does not correspond to any known pending invitation.',
    message: 'Invitation not found' },
  { code: 'already_claimed',             status: 409, section: '§7.2, §11.3',
    description: 'The account is already in CLAIMED state and the operation is not permitted in that state.',
    message: 'Account is already claimed' },
  { code: 'not_claimed',                 status: 409, section: '§11.3',
    description: 'The operation requires the account to be in CLAIMED state and it is not.',
    message: 'Account is not claimed' },
  { code: 'owner_authentication_required', status: 403, section: '§7.4, §7.5, §8.2, §11.3',
    description: 'The operation requires an owner-authenticated session and the supplied session does not satisfy §7.7 match relation (or is absent).',
    message: 'Owner authentication required' },
  { code: 'owner_binding_blocked',       status: 403, section: '§7.5, §11.3',
    description: 'An agent-signed request attempted an owner-binding operation post-claim. The agent key alone MUST NOT authorize such operations.',
    message: 'Owner-binding operation blocked' },
  { code: 'account_expired',             status: 410, section: '§6.1, §11.3',
    description: 'The account is in EXPIRED state and subsequent requests are no longer accepted.',
    message: 'Account has expired' },
  { code: 'rate_limit_exceeded',         status: 429, section: '§11.2, §11.3',
    description: 'The agent has exceeded the service\'s declared rate limit (§4.4 limits.unclaimed_rate_limit_per_hour or service-defined).',
    message: 'Rate limit exceeded' },
  { code: 'malformed_request',           status: 400, section: '§11.2, §11.3',
    description: 'The request body, headers, or URL are not parseable as a v0.1 AFAuth request (invalid JSON, missing required field, invalid DID syntax, unsupported HTTP method, etc.).',
    message: 'Malformed request' },
  { code: 'unsupported_recipient_type',  status: 400, section: '§4.4, §7.2, §11.3',
    description: 'The owner-invitation request specified a recipient `type` that the service did not declare in its discovery `recipient_types`.',
    message: 'Unsupported recipient type' },
];

const OUT_DIR = __dirname;

for (const v of VECTORS) {
  const out = {
    name: v.code,
    description: v.description,
    section: v.section,
    code: v.code,
    http_status: v.status,
    envelope: {
      error: {
        code: v.code,
        message: v.message,
      },
    },
  };
  const file = path.join(OUT_DIR, `${v.code}.json`);
  fs.writeFileSync(file, JSON.stringify(out, null, 2) + '\n');
  console.log(`wrote ${path.basename(file)}`);
}

console.log(`\n${VECTORS.length} error-envelope vectors written.`);
