#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Generator for AFAuth §C.4 recipient-normalisation test vectors.
// Each fixture carries one wire-format input and the expected
// canonical form (accept) or the expected rejection (reject).
//
// Categories:
//   - email  — NFKC + case-fold per §7.7.1
//   - phone  — E.164, no extensions, only `+` and digits per §7.7.2
//   - oidc   — opaque issuer; MUST reject fragment/query per §7.7.3
//   - did    — canonical form per method; bare DID (no DID URL
//              components) per §7.7.4
//
// Run from this directory:  node _generate.js

'use strict';

const fs = require('fs');
const path = require('path');

const VECTORS = [
  // ---------- email (§7.7.1) ----------
  {
    name: 'email-lowercase-ascii-passthrough',
    type: 'email',
    description: 'Lowercase ASCII email passes through unchanged.',
    input: { type: 'email', value: 'alice@example.com' },
    expected: { type: 'accept', canonical: { type: 'email', value: 'alice@example.com' } },
  },
  {
    name: 'email-uppercase-lowercased',
    type: 'email',
    description: 'Upper-case ASCII email is case-folded per §7.7.1 / RFC 5321 §2.4.',
    input: { type: 'email', value: 'ALICE@EXAMPLE.COM' },
    expected: { type: 'accept', canonical: { type: 'email', value: 'alice@example.com' } },
  },
  {
    name: 'email-mixed-case-lowercased',
    type: 'email',
    description: 'Mixed-case is fully lowercased.',
    input: { type: 'email', value: 'Alice@Example.COM' },
    expected: { type: 'accept', canonical: { type: 'email', value: 'alice@example.com' } },
  },
  {
    name: 'email-nfkc-decomposed-precomposed',
    type: 'email',
    description:
      'NFKC normalisation collapses combining sequences to their precomposed form. Here `e\\u0301` (e + combining acute) becomes `\\u00e9` (é).',
    input: { type: 'email', value: 'élise@example.com' },
    expected: { type: 'accept', canonical: { type: 'email', value: 'élise@example.com' } },
  },
  {
    name: 'email-nfkc-compatibility-ligature',
    type: 'email',
    description:
      'NFKC compatibility decomposition expands the `ﬁ` ligature (U+FB01) into `fi`.',
    input: { type: 'email', value: 'aﬁnd@example.com' },
    expected: { type: 'accept', canonical: { type: 'email', value: 'afind@example.com' } },
  },

  // ---------- phone (§7.7.2) ----------
  {
    name: 'phone-canonical-e164-passthrough',
    type: 'phone',
    description: 'Canonical E.164 (`+` followed by digits) passes through unchanged.',
    input: { type: 'phone', value: '+14155550173' },
    expected: { type: 'accept', canonical: { type: 'phone', value: '+14155550173' } },
  },
  {
    name: 'phone-with-spaces-rejected',
    type: 'phone',
    description:
      'Whitespace is forbidden by §7.7.2 ("MUST reject values containing any character other than `+` and the digits `0`–`9`").',
    input: { type: 'phone', value: '+1 415 555 0173' },
    expected: { type: 'reject', reason: 'phone contains characters other than + and 0-9' },
  },
  {
    name: 'phone-with-dashes-rejected',
    type: 'phone',
    description: 'Dashes are forbidden by §7.7.2.',
    input: { type: 'phone', value: '+1-415-555-0173' },
    expected: { type: 'reject', reason: 'phone contains characters other than + and 0-9' },
  },
  {
    name: 'phone-with-extension-rejected',
    type: 'phone',
    description: 'E.164 extension syntax `;ext=…` is explicitly forbidden by §7.7.2.',
    input: { type: 'phone', value: '+14155550173;ext=42' },
    expected: { type: 'reject', reason: 'phone contains E.164 extension syntax' },
  },
  {
    name: 'phone-missing-plus-rejected',
    type: 'phone',
    description: 'A national-format number without `+` is not E.164.',
    input: { type: 'phone', value: '14155550173' },
    expected: { type: 'reject', reason: 'phone is not E.164 (missing leading +)' },
  },

  // ---------- oidc (§7.7.3) ----------
  {
    name: 'oidc-canonical-passthrough',
    type: 'oidc',
    description: 'Issuer is treated as opaque; canonical value is byte-identical to input.',
    input: { type: 'oidc', value: { issuer: 'https://accounts.google.com', sub: '103948572345' } },
    expected: {
      type: 'accept',
      canonical: { type: 'oidc', value: { issuer: 'https://accounts.google.com', sub: '103948572345' } },
    },
  },
  {
    name: 'oidc-trailing-slash-significant',
    type: 'oidc',
    description:
      'Issuer is opaque — a trailing slash IS significant. The normalised form preserves the wire value byte-for-byte.',
    input: { type: 'oidc', value: { issuer: 'https://accounts.google.com/', sub: '103948572345' } },
    expected: {
      type: 'accept',
      canonical: { type: 'oidc', value: { issuer: 'https://accounts.google.com/', sub: '103948572345' } },
    },
  },
  {
    name: 'oidc-issuer-with-fragment-rejected',
    type: 'oidc',
    description: '§7.7.3: implementations MUST reject issuer values containing a fragment.',
    input: { type: 'oidc', value: { issuer: 'https://accounts.google.com#main', sub: '1' } },
    expected: { type: 'reject', reason: 'oidc issuer contains fragment' },
  },
  {
    name: 'oidc-issuer-with-query-rejected',
    type: 'oidc',
    description: '§7.7.3: implementations MUST reject issuer values containing a query.',
    input: { type: 'oidc', value: { issuer: 'https://accounts.google.com?env=staging', sub: '1' } },
    expected: { type: 'reject', reason: 'oidc issuer contains query' },
  },

  // ---------- did (§7.7.4) ----------
  {
    name: 'did-key-canonical-passthrough',
    type: 'did',
    description: 'did:key in canonical multibase form passes through unchanged.',
    input: { type: 'did', value: 'did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr' },
    expected: {
      type: 'accept',
      canonical: { type: 'did', value: 'did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr' },
    },
  },
  {
    name: 'did-web-uppercase-host-rejected',
    type: 'did',
    description:
      '§7.7.4: did:web canonical form lowercases the host. Non-canonical forms MUST be rejected.',
    input: { type: 'did', value: 'did:web:Example.COM' },
    expected: { type: 'reject', reason: 'did:web host MUST be lowercase' },
  },
  {
    name: 'did-with-path-rejected',
    type: 'did',
    description:
      '§7.7.4: bare DID only — DID URL components (path / query / fragment) MUST be rejected.',
    input: { type: 'did', value: 'did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr/path' },
    expected: { type: 'reject', reason: 'did contains DID URL component (path)' },
  },
  {
    name: 'did-with-fragment-rejected',
    type: 'did',
    description: '§7.7.4: DID URL fragment is forbidden.',
    input: { type: 'did', value: 'did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr#fragment' },
    expected: { type: 'reject', reason: 'did contains DID URL component (fragment)' },
  },
  {
    name: 'did-with-query-rejected',
    type: 'did',
    description: '§7.7.4: DID URL query is forbidden.',
    input: { type: 'did', value: 'did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr?versionId=1' },
    expected: { type: 'reject', reason: 'did contains DID URL component (query)' },
  },
];

const OUT = __dirname;
for (const v of VECTORS) {
  const out = {
    name: v.name,
    description: v.description,
    section: 'C.4',
    recipient_type: v.type,
    input: v.input,
    expected: v.expected,
  };
  fs.writeFileSync(path.join(OUT, `${v.name}.json`), JSON.stringify(out, null, 2) + '\n');
}
console.log(`${VECTORS.length} recipient-normalisation vectors written.`);
