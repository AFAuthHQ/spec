# ADR-0005: End-to-end interop harness location and contract

## Status
Accepted 2026-05-28.

## Context

The existing `spec/harness/run.js` exercises Appendix C vectors against any
implementation that imports its building blocks (signature canonicalisation,
discovery validation, replay-window logic). It covers protocol primitives
in isolation. It does not cover **stack-up** — the realistic journeys where
an agent obtains a binding from `trust.afauth.org`, presents the attestation
to a service whose listing came from `registry.afauth.org`, and the service
verifies the request through the SDK's `Verifier`.

A coverage review of the current test surface confirmed:

- Every repo's CI runs only its own tests. The Go CLI never talks to the
  real `trust/` Hono app; the TS `TrustClient` is exercised only against
  hand-rolled mock `fetch`; `attestation.test.ts` mints HMAC tokens
  locally rather than driving an actual `afauth-trust` JWT through
  `trustAttestor()`'s JWKS path.
- Spec vectors are vendored per-impl with a SHA pin in each impl's
  `VERSION` file. Nothing forces those SHAs to agree, so two impls can
  silently sit on different vector corpora.
- The user-facing journey AFAuth promises in marketing — "agent signs
  itself up using its own keypair, optionally binds to a human later" —
  has no test that exercises it end-to-end against real HTTP.

A survey of comparable protocol projects (libp2p/test-plans, QUIC
interop-runner, Matrix Complement, ipfs/interop, OpenID Foundation
conformance-suite) converges on three structural choices:

1. The interop harness lives in a separate artefact from any single
   implementation, owned by the spec org or foundation.
2. The harness ↔ implementation contract is narrow: a Docker image
   reachable by env var, or a binary path reachable by env var.
3. CI runs from both directions — implementation repos consume the
   harness on PRs; the harness repo runs a cross-impl matrix on a
   schedule.

The local layout of `~/CodeProjects/afauth/` is a multi-repo workspace,
not a monorepo: each subdirectory (`cli/`, `trust/`, `registry/`,
`typescript-sdk/`, `spec/`, `docs/`) is a separate GitHub repo with its
own CI. "Add an `e2e/` workspace at the root" has no GitHub home and
would orphan the code.

## Decision

### (1) Home: `AFAuthHQ/spec`, at `spec/harness/e2e/`

The end-to-end harness lives next to the vector harness, in the same
repo. Justification:

- Ownership matches the vector harness pattern already in place — the
  spec org owns conformance tooling, implementations consume it.
- Co-locating the vector and e2e harnesses means a single repo holds
  the full notion of "what an implementation must pass to be
  conformant," which is the contract third parties read.
- Avoids creating a sixth top-level repo whose ownership would drift
  from `spec/` over time.

### (2) Stack-up via `docker-compose.yml`

`spec/harness/e2e/docker-compose.yml` brings up the dependency-side
stack:

- `postgres:16` and `redis:7` (matching what `registry/docker-compose.yml`
  and `trust/docker-compose.yml` already use locally).
- `trust` — built from `AFAuthHQ/trust@<sha>` pinned in the harness.
- `registry` — built from `AFAuthHQ/registry@<sha>` pinned in the
  harness.
- `reference-server` — a thin wrapper around `@afauthhq/server` at the
  pinned `typescript-sdk` SHA, exposing a v0.1-conformant service. The
  wrapper lives at `spec/harness/e2e/reference-server/`.

These three services are *the dependency side* of every test. They are
fixed by the harness; the implementation under test is the *client
side*.

### (3) Client-side contract: env-var-pointed binary or module path

The implementation under test plugs in via environment variables,
mirroring `ipfs/interop`:

| Variable | Purpose |
|---|---|
| `AFAUTH_CLI_BIN` | path to a built `afauth` binary; used by CLI-driven tests |
| `AFAUTH_AGENT_MODULE` | npm path or workspace path to `@afauthhq/agent`; used by SDK-driven tests |
| `AFAUTH_TRUST_BASE` | URL of the trust service (defaults to compose-local) |
| `AFAUTH_REGISTRY_BASE` | URL of the registry service (defaults to compose-local) |
| `AFAUTH_SERVER_BASE` | URL of the reference server (defaults to compose-local) |

An env-var contract is chosen over a Docker-image contract for v0.1
because the two known impls (Go CLI, TS SDK) are convenient to point at
locally, and the contract is forward-compatible: a future Rust SDK can
be wrapped in a Dockerfile that sets `AFAUTH_CLI_BIN=/usr/bin/rust-cli`,
without revising the harness API.

### (4) Runner: Node, importable as a library *and* runnable standalone

`spec/harness/e2e/run.js` mirrors `spec/harness/run.js`: a CLI entry
point plus exported helpers. It exports `runSuite(opts)`,
`startStack()`, and one helper per scenario. This is the lesson from
the survey: `ipfs/interop`'s adoption was driven by being trivially
embeddable in downstream CI; Matrix Complement's slower uptake came
from being test-runner-only. Both modes from day one.

The runner uses `docker compose` (the v2 plugin) and Node 20's
built-in `node:test` runner — no new dependencies beyond what `spec/`
already requires.

### (5) Spec-SHA pinning becomes load-bearing

Each implementation repo's `vendor/spec-vectors/VERSION` (or
`testdata/spec-vectors/VERSION` for the CLI) gains a sibling field
`harness_sha` and the impl's CI checks out `AFAuthHQ/spec` at that
SHA before running the e2e harness. This makes vector-SHA drift
between impls a visible CI failure rather than a silent gap.

### (6) CI on both sides

- **Producer side (`spec/` CI):** the e2e matrix runs on every PR
  and on a nightly schedule, exercising the Go CLI and the TS Agent
  against the pinned dependency-side stack. Failures gate spec
  changes.
- **Consumer side (`cli/`, `typescript-sdk/` CIs):** a new
  `e2e-interop` job checks out `AFAuthHQ/spec` at the pinned SHA,
  builds the local impl, and runs `node spec/harness/e2e/run.js
  --impl <self>`. Failures gate impl PRs.

## Consequences

- **Positive.** One neutral home for stack-up tests, matching the
  pattern that won out at libp2p, QUIC, and Matrix. The existing
  ownership boundary (`spec/` owns conformance tooling) is extended
  rather than duplicated. SHA-pinning becomes load-bearing, fixing
  the silent vector-drift gap surfaced in the test-coverage review.
- **Positive.** The env-var contract keeps the harness small in v0.1
  and is forward-compatible to a Docker-image contract — a future
  Rust or Python impl just provides a Dockerfile that exposes the
  same env vars.
- **Negative.** Impl CIs gain a docker-in-docker dependency. GitHub
  Actions supports this natively, but cold-start time per PR rises
  by ~60–90s for the compose stack-up. The producer-side nightly
  absorbs the bulk of the matrix cost.
- **Negative.** A new top-level subdirectory in `spec/` increases
  the repo's scope from "spec text + vectors + vector harness" to
  "spec text + vectors + vector harness + e2e harness + reference
  server." The repo's README must clarify that the reference
  server in `spec/harness/e2e/reference-server/` is a test fixture,
  not the canonical TS SDK example.
- **Neutral.** The reference server pins a specific
  `typescript-sdk` SHA, which means the harness's "verifier" side
  is *not* protocol-neutral — it bakes in one implementation's
  interpretation of optional behaviour. This is acceptable in v0.1
  because there is only one server-side implementation; v0.2 should
  revisit if a second appears.

## Alternatives considered

- **Top-level `e2e/` workspace at the local repo root.** Rejected:
  the local layout is a multi-repo workspace, not a monorepo, so
  this has no GitHub home. Either a new repo (rejected below) or
  a subdirectory inside an existing repo is required.
- **New `AFAuthHQ/e2e` repo.** Rejected: ownership would drift from
  `spec/`. The vector harness and the e2e harness answer the same
  question ("does this implementation conform?") and benefit from
  sharing a SHA, a license file, and a release cadence.
- **Home in `cli/test/e2e/` or `typescript-sdk/test/e2e/`.** Rejected:
  any single impl's repo is a biased home. Future impls have no
  reason to consume tests from a competitor's repo, and CI
  permissions get awkward.
- **Docker-image-per-impl contract (Matrix/QUIC style).** Rejected for
  v0.1 only. The env-var contract is lighter and works for both
  known impls today. The decision is reversible: a future ADR can
  upgrade the contract when a third impl arrives.
- **Testground-style topology orchestration.** Rejected; libp2p
  retired Testground in 2024 in favour of docker-compose for the
  same reasons that apply here (operational complexity, slow cold
  start, limited debugging).
- **In-process stack-up (no Docker).** Rejected: misses the actual
  HTTP, JWKS resolution, CORS, and TLS surfaces that production
  encounters. The point of the e2e harness is precisely these
  failures.

## Follow-on work

This ADR is the decision; implementation lands in subsequent PRs.
First slice:

1. `spec/harness/e2e/docker-compose.yml` + `reference-server/`
   scaffolding.
2. `spec/harness/e2e/run.js` with one happy-path scenario:
   `afauth init → afauth trust link → afauth signup` against the
   stack.
3. CI job in `cli/` consuming the harness at a pinned spec SHA.
4. Extend `VERSION` schemas in each impl to include `harness_sha`.

The remaining proposed E2E scenarios (cross-language fresh-signature
interop, registry proof verification, key rotation through the
stack) land incrementally against the same harness.
