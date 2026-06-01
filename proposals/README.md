# AFAuth Protocol Proposals (AFAPs)

**Status:** Active.

This directory holds AFAuth Protocol Proposals — design changes to the protocol that go beyond editorial fixes. The process is intentionally light-touch.

## When to file an AFAP

- Adding or modifying normative requirements in `spec/core.md`.
- Adding or changing fields in the discovery document schema.
- Reserving new error codes, attestor identifiers, DID methods, or signature algorithms.
- Adding new endpoints to the protocol surface.

Editorial fixes (typos, clarifications, examples) do not require an AFAP and may be submitted as ordinary pull requests.

## Format

Each AFAP is a single Markdown file named `NNNN-short-title.md`, where `NNNN` is a zero-padded number assigned at filing time. Suggested sections:

1. **Summary** — one paragraph describing the change.
2. **Motivation** — what problem this solves and why the current spec is inadequate.
3. **Specification** — the proposed normative text, suitable for direct inclusion in `core.md`.
4. **Compatibility** — whether the change is wire-compatible with the current spec; if not, the migration path.
5. **Security and privacy considerations** — threats the change addresses or introduces.
6. **Alternatives considered** — other shapes you considered and why you didn't pick them.
7. **References** — prior art, related IETF/W3C work.

## Lifecycle

`Draft → Discussion → Last Call → Accepted | Withdrawn | Rejected`

The first AFAP filed will document the AFAP process itself.

## Status

The `spec/core.md` baseline is editor-driven; all normative changes route through this directory.
