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
//   AFAUTH_TRUST_BASE     URL of the trust service     (default: http://localhost:4001)
//   AFAUTH_REGISTRY_BASE  URL of the registry service  (default: http://localhost:4002)
//   AFAUTH_SERVER_BASE    URL of the reference server  (default: http://localhost:4003)
//
// Exits non-zero on any failure.

'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const DEFAULTS = {
  trustBase: process.env.AFAUTH_TRUST_BASE || 'http://localhost:4001',
  registryBase: process.env.AFAUTH_REGISTRY_BASE || 'http://localhost:4002',
  serverBase: process.env.AFAUTH_SERVER_BASE || 'http://localhost:4003',
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

async function preflight(opts) {
  // Refuse to start scenarios if the stack isn't reachable. Saves
  // confusing "connection refused" errors deep inside a scenario.
  const urls = [
    ['reference-server', opts.serverBase + '/healthz'],
    ['trust', opts.trustBase + '/healthz'],
    // registry healthz isn't load-bearing for the first scenario —
    // probe it but don't fail if it's not up.
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

// Scenario 2 placeholder: `init → trust link → signup`. Requires
// either a test-mode auto-confirm endpoint on trust/ or a Playwright
// browser harness. Tracked as follow-on in ADR-0005 §Status.

const SCENARIOS = {
  'init-signup': scenarioInitSignup,
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

  const opts = makeOpts();
  try {
    await preflight(opts);
  } catch (e) {
    console.error(`PRE   ${e.message}`);
    console.error('hint: run ./scripts/up.sh first');
    process.exit(1);
  }

  let pass = 0;
  let fail = 0;
  for (const name of selected) {
    try {
      await SCENARIOS[name](opts);
      console.log(`PASS  ${name}`);
      pass++;
    } catch (e) {
      console.log(`FAIL  ${name}`);
      console.log(`      ${e.message}`);
      if (e.stack) console.log(e.stack.split('\n').slice(1, 4).map((l) => '      ' + l.trim()).join('\n'));
      fail++;
    }
  }
  cleanupOpts(opts);

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

module.exports = { SCENARIOS, runCli, preflight };
