# AFAuth Protocol

> An open protocol for agent-first account creation and human handoff.

This repository contains the specification for **AFAuth** — an open protocol that lets AI agents sign up to internet services using a self-generated cryptographic keypair, operate those accounts autonomously, and optionally hand ownership to a human at any later point.

## Status

**v0.1 — Working Draft.** Not yet final. Comments and proposals welcome.

## Layout

- [`spec/core.md`](spec/core.md) — the protocol specification
- [`spec/conformance.md`](spec/conformance.md) — conformance criteria (stub; full test suite planned)
- [`schemas/well-known.json`](schemas/well-known.json) — JSON Schema for the `/.well-known/afauth` discovery document
- [`proposals/`](proposals/README.md) — AFAuth Protocol Proposals (AFAPs)

## Reference implementations

- CLI + agent: [`github.com/AFAuthHQ/cli`](https://github.com/AFAuthHQ/cli)
- TypeScript SDKs: [`github.com/AFAuthHQ/typescript-sdk`](https://github.com/AFAuthHQ/typescript-sdk)

Alternative implementations are welcome. The protocol is intentionally small and language-agnostic.

## License

The specification is licensed under [CC-BY 4.0](LICENSE).
