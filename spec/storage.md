# AFAuth Agent Home — Local Credential Storage

**Status:** Informational
**Version:** 0.1
**Date:** 2026-06-06
**License:** [CC-BY 4.0](../LICENSE)

> This document is **non-normative with respect to the wire protocol**.
> A conforming AFAuth agent signs requests with an Ed25519 keypair
> (`core.md` §5); *where and how* it stores that keypair is its own
> business, and the normative protocol in [`core.md`](core.md) is
> indifferent to it.
>
> It is, however, the **interop contract** for clients that choose to
> share an agent home directory. The payoff of sharing is concrete: a
> human links an agent to themselves **once** (§10 attestation), and
> *every* AFAuth client on the machine — the reference [`afauth`
> CLI](https://github.com/AFAuthHQ/cli), an SDK-built tool, a
> service-distributed CLI — reuses that one identity and that one human
> link instead of each re-prompting. That property only holds if those
> clients agree on the file formats below.

## Abstract

This document defines the **agent home directory** and the two files an
AFAuth client persists there:

- `key.json` — the agent's Ed25519 keypair and derived `did:key`.
- `trust.json` — the agent's binding(s) to one or more trust attestors.

Both are described by JSON Schemas under
[`schemas/`](../schemas/): [`key-store.json`](../schemas/key-store.json)
and [`trust-store.json`](../schemas/trust-store.json). The formats here
are exactly what the reference `afauth` CLI reads and writes as of v0.1;
documenting them lets any implementation (e.g. the TypeScript SDK's
`@afauthhq/agent`) be a faithful citizen of the same home.

## The agent home directory

The home directory is resolved as:

1. `$AFAUTH_HOME` when that environment variable is set (used for
   sandboxing and tests), else
2. `~/.afauth` (`$HOME/.afauth`).

A client creates the directory at mode `0700` (owner-only) if missing.
The two files live directly inside it: `$AFAUTH_HOME/key.json` and
`$AFAUTH_HOME/trust.json`.

## `key.json`

The agent keypair. v0.1 stores a **single key per agent**; multi-key
support is deferred. Written with file mode `0600`. Schema:
[`schemas/key-store.json`](../schemas/key-store.json).

```json
{
  "version": 1,
  "algorithm": "ed25519",
  "did_key": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
  "public_key_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "private_key_seed_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
}
```

- `version` — `1` in v0.1. A reader that does not understand the version
  MUST refuse the file rather than guess.
- `algorithm` — `"ed25519"` (the only v0.1 algorithm).
- `did_key` — the `did:key` of `public_key_hex`.
- `public_key_hex` — raw 32-byte Ed25519 public key, lowercase hex.
- `private_key_seed_hex` — raw 32-byte Ed25519 **seed**, lowercase hex.
  The 64-byte expanded signing key is derived at sign time and never
  persisted.

**Loader invariants.** A loader MUST recompute the public key from the
seed and reject the file if it does not match `public_key_hex`, and
likewise reject it if `did_key` does not match the `did:key` derived
from the public key. These catch on-disk tampering or truncation.

## `trust.json`

The agent's trust-attestor binding(s). An agent MAY hold several at once
(e.g. the public `afauth-trust` plus a private enterprise attestor); a
consuming command picks the one a given service accepts via
`billing.accepted_attestors` (§4.4). Written with file mode `0600`,
ideally via a temp-file-and-rename for atomicity. Schema:
[`schemas/trust-store.json`](../schemas/trust-store.json).

```json
{
  "version": 2,
  "bindings": [
    {
      "base_url": "https://trust.afauth.org",
      "iss": "afauth-trust",
      "agent_did": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
      "binding_id": "bnd_3f9a…",
      "binding_token_expires_at": 1781049600,
      "verification": "email",
      "verification_seen_at": 1778457600
    }
  ]
}
```

- `version` — `2` is canonical (the `bindings` array). **Version 1** held
  a single binding inline at the top level (the same per-binding fields,
  no `bindings` array); a conformant reader SHOULD migrate a v1 file to
  v2 on load.
- `bindings[]` — keyed logically by `base_url` (trailing slash ignored).
  Re-linking the same `base_url` replaces the binding in place rather
  than appending a duplicate, and preserves a previously-learned `iss`
  if the incoming binding lacks one.

Per-binding fields (`base_url`, `agent_did`, `binding_id`,
`binding_token_expires_at` are always present; `iss`, `verification`,
`verification_seen_at` are filled in lazily from minted tokens) are
documented in the schema. Two behaviours matter for interop:

- **Orphaned bindings.** A binding whose `agent_did` differs from the
  active key (e.g. left behind by a rotation) MUST NOT be used to mint —
  the attestation would assert the old DID while requests are signed by
  the new key. A binding with no `agent_did` is treated as not-orphaned.
- **Expiry.** `binding_token_expires_at` is the inactivity window; the
  attestor slides it forward on each mint. A client SHOULD refresh the
  cached value from the mint response, and treat `0` as "no expiry
  reported" (not expired).

## Security considerations

- `key.json` holds private key material; it MUST be mode `0600` and the
  seed MUST NEVER be transmitted — the agent proves possession by
  *signing*, never by sending the key.
- The home directory SHOULD be `0700`.
- `trust.json` carries no bearer secret (mints are keyless, §3.1), but it
  reveals which attestors a human has linked, so it is also written
  `0600`.

## Relationship to the protocol

Nothing in [`core.md`](core.md) requires a client to use this layout — an
agent that keeps its key in an HSM, a password manager, or a service's
own config directory is fully conformant. This document exists so that
clients which *do* want the "link once, reuse everywhere" property have a
single format to agree on. It introduces no new wire fields and changes
no normative behaviour.
