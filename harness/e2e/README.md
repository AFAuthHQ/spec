# AFAuth end-to-end interop harness

Stack-up tests for the v0.1 protocol. Brings up a real `trust`,
`registry`, and reference `@afauthhq/server` together, then exercises
implementations under test (today: the Go `afauth` CLI) against the
stack over real HTTP.

This is the artefact specified by
[ADR-0005](../../implementation/adr/0005-e2e-interop-harness.md).

For protocol-primitive conformance (vectors only), see the sibling
[`../run.js`](../run.js).

## Status

Six scenarios, all passing locally:

| Scenario | What it exercises |
|---|---|
| `init-signup` | §6.3 implicit signup; CLI ↔ reference-server signed-request round-trip |
| `pre-claim-key-rotate` | §8.1 pre-claim key rotation; CLI signs with old key, server accepts, ledger updates |
| `trust-link` | AFAP-0006 link flow; CLI ↔ trust attestor link round-trip via the gated `TRUST_E2E_AUTOCONFIRM` endpoint |
| `negatives` | §11.1 error envelope conformance on unsigned probes (locks in the `AFAuthError.toResponse()` wiring on the reference server) |
| `registry-roundtrip` | AFAP-0003 service directory; seed a listing via `REGISTRY_E2E_DIRECT_INSERT`, look it up by DID and via list-with-filter |
| `cross-service-portability` | §D.1 portability; same agent key signs up on two reference servers, two independent UNCLAIMED rows, both bound to the same DID |

Not yet covered (tracked as follow-on in ADR-0005 §Status):

- §7 owner invitation + claim — needs an `e2e/last-invitation` shim
  on the reference server and `handleClaimCompletion` test-mode wiring
- §10 attestation presented to a service — needs the reference server
  to be configured as an attestor consumer (JWKS fetch + recognized
  issuer)
- Replay-window + expired-timestamp probes (need a custom signer in
  the harness, parallel to `@afauthhq/agent`)

## Layout

```
e2e/
├── README.md                  this file
├── docker-compose.yml         brings up the dependency-side stack
├── versions.json              pins SHAs of trust, registry, sdk
├── reference-server/          thin wrapper around @afauthhq/server
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   └── src/server.ts
├── scripts/
│   ├── up.sh                  compose up + wait for health
│   └── down.sh                compose down + volume prune
└── run.js                     scenario runner
```

## Contract

Implementations under test plug in via environment variables (see
ADR-0005 §3):

| Variable | Purpose | Default |
|---|---|---|
| `AFAUTH_CLI_BIN` | path to a built `afauth` binary | (required for CLI scenarios) |
| `AFAUTH_AGENT_MODULE` | path to `@afauthhq/agent` | (required for SDK scenarios) |
| `AFAUTH_TRUST_BASE` | URL of the trust service | `http://localhost:4001` |
| `AFAUTH_REGISTRY_BASE` | URL of the registry service | `http://localhost:4002` |
| `AFAUTH_SERVER_BASE` | URL of the reference server | `http://localhost:4003` |

## Local development

The compose file builds `trust`, `registry`, and `reference-server`
from sibling repos by default — assumes the layout in `~/CodeProjects/
afauth/` where `spec/`, `trust/`, `registry/`, `typescript-sdk/`
are siblings. Override the source paths via env vars if your layout
differs:

```bash
export E2E_TRUST_DIR=../../trust          # default: ../../../trust
export E2E_REGISTRY_DIR=../../registry    # default: ../../../registry
```

Run a scenario:

```bash
# 1. build the cli somewhere
cd ../../../cli && make build
export AFAUTH_CLI_BIN=$PWD/bin/afauth

# 2. bring up the stack
cd ../spec/harness/e2e
./scripts/up.sh

# 3. run the scenario
node run.js --scenario init-signup

# 4. tear down
./scripts/down.sh
```

## CI mode (not yet wired)

In CI, `scripts/up.sh` will instead clone each repo at the SHA pinned
in `versions.json` into `.work/`, then build from there. That keeps
producer-side CI (the `spec/` repo) reproducible against pinned
dependencies. Consumer-side CI (the `cli/` repo) overrides the SHA
for the impl under test to its local checkout.

The CI integration itself (workflow YAML in `spec/`, `cli/`,
`typescript-sdk/`) lands in follow-on PRs per ADR-0005 §6.

## Adding a scenario

A scenario is a single async function exported from `run.js` that
returns `void` on pass and throws on fail. It receives the same
options object every scenario does (`{ trustBase, registryBase,
serverBase, cliBin, agentModule, tmpDir }`). Use the existing
`init-signup` scenario as a template.
