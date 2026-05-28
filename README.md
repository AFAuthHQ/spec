# AFAuth Protocol

> **Agent-First Auth.** The open protocol that makes AI agents first-class citizens of every service.

Human attention is finite. Agent attention is exploding. AFAuth is how that new attention reaches services — and how agents reach every service that exists. AI agents sign themselves up using their own cryptographic keypair, operate accounts on their own without a human in the loop, and optionally hand ownership to a human at any later point.

This repository is the normative specification.

## Status

**v0.1 — Working Draft.** Not yet final. Comments and proposals welcome.

## Layout

- [`spec/core.md`](spec/core.md) — the protocol specification
- [`spec/conformance.md`](spec/conformance.md) — conformance criteria for agent and service roles
- [`spec/directory.md`](spec/directory.md) — informational: non-normative service-directory convention (AFAP-0003)
- [`schemas/well-known.json`](schemas/well-known.json) — JSON Schema for the `/.well-known/afauth` discovery document
- [`schemas/listing.json`](schemas/listing.json) — JSON Schema for service-directory listings (informational, AFAP-0003)
- [`vectors/`](vectors/) — Appendix C test vectors:
    - [`signatures/`](vectors/signatures/) (§C.1, §C.2 — canonical input + reference signatures)
    - [`discovery/`](vectors/discovery/) (§C.3 — well-formed / forward-compat / malformed discovery docs)
    - [`recipients/`](vectors/recipients/) (§C.4 — per-type recipient normalisation)
    - [`errors/`](vectors/errors/) (§C.5 — envelope shape per §11.3 code)
    - [`replay-window/`](vectors/replay-window/) (§C.6 — expired / future-dated / replay / cross-keyid)
- [`harness/`](harness/) — executable conformance harness that runs every committed vector
- [`implementation/`](implementation/) — implementation scope, ADRs, and SDK API sketch (`sdk-v0.1.d.ts`) for the reference TypeScript SDK
- [`proposals/`](proposals/README.md) — AFAuth Protocol Proposals (AFAPs)

## Reference implementations

- **CLI + agent**: [`github.com/AFAuthHQ/cli`](https://github.com/AFAuthHQ/cli) — Go.
  Pre-built binaries on the [releases page](https://github.com/AFAuthHQ/cli/releases) (linux/darwin/windows × amd64/arm64), or `go install github.com/AFAuthHQ/cli/cmd/afauth@latest`.
- **TypeScript SDKs**: [`github.com/AFAuthHQ/typescript-sdk`](https://github.com/AFAuthHQ/typescript-sdk).
  Published to npm under [`@afauthhq`](https://www.npmjs.com/org/afauthhq):
  ```
  npm i @afauthhq/agent     # client / agent
  npm i @afauthhq/server    # service handlers + Verifier
  npm i @afauthhq/worker    # Cloudflare Workers bindings
  npm i @afauthhq/core      # primitives shared by the above
  ```

Both reference implementations track the v0.1 spec. Current releases:

- TypeScript SDK: `@afauthhq/{agent,server,worker}@0.2.0` + `@afauthhq/core@0.1.0` on npm — `0.2.0` adds the AFAP-0006 trust-attestor surface (`TrustClient`, `trustAttestor()`).
- CLI: [`v0.3.0`](https://github.com/AFAuthHQ/cli/releases/tag/v0.3.0) — binaries + Homebrew tap, includes the `afauth trust` subcommand.

Alternative implementations are welcome. The protocol is intentionally small and language-agnostic.

## License

- **Specification text** (`spec/`, `proposals/`, `README.md`) — [CC-BY-4.0](LICENSE).
- **Code-shaped artefacts** (`vectors/`, `schemas/`, `harness/`) — [Apache-2.0](LICENSE-CODE).

This dual-licensing follows standard practice for protocol repositories that ship a normative text alongside reference test data and tooling.
