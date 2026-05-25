# AFAuth Service Directory

**Status:** Informational
**Version:** 0.1 (working draft)
**Date:** 2026-05-25
**License:** [CC-BY 4.0](../LICENSE)

> This document is **non-normative**. A conforming AFAuth agent or
> service has no obligation to interact with any directory. The
> directory described here is a community convention; the normative
> protocol lives in [`core.md`](core.md). See
> [AFAP-0003](../proposals/0003-service-directory.md) for the
> motivation, alternatives considered, and security/privacy
> analysis behind this design.

## Abstract

A non-normative public **service directory** — a list of services
that have voluntarily announced AFAuth support — operated at
`https://registry.afauth.org` and mirrorable by anyone. The
directory's sole purpose is announcement and cold-start discovery
for early adopters; it imposes no requirements on either agents or
services and introduces no new fields on the `/.well-known/afauth`
document.

Membership is **opt-in**, **self-serve via proof of control of the
discovery host**, and **independent of conformance**: a listing
means a service has claimed AFAuth support, not that it has been
audited.

If `afauth.org` were to disappear, every conforming agent and
service would continue working unchanged.

## 1. Status and scope

This document is informational. It does not amend
[`core.md`](core.md). A conforming agent or service has no
obligation to interact with any directory. This document describes
a convention for the `registry.afauth.org`-hosted registry and any
mirror or fork that wishes to interoperate with it.

## 2. Listing record

Each listing is a JSON object with the following shape:

```json
{
  "service_did":     "did:web:api.example.com",
  "discovery_url":   "https://api.example.com/.well-known/afauth",
  "discovery_doc":   { /* cached copy of /.well-known/afauth */ },
  "fetched_at":      "2026-05-23T14:00:00Z",
  "first_listed_at": "2026-04-01T09:12:33Z",
  "status":          "active",
  "tags":            ["productivity", "storage"],
  "title":           "Example Photo Storage",
  "description":     "AFAuth-supported photo storage for agents.",
  "_meta":           { }
}
```

The full JSON Schema is provided at
[`../schemas/listing.json`](../schemas/listing.json).

**Required fields:** `service_did`, `discovery_url`, `discovery_doc`,
`fetched_at`, `first_listed_at`, `status`.

**`discovery_doc`** is a cached snapshot taken at `fetched_at`.
Consumers that need to act on `endpoints`, `billing`, or
`accepted_attestors` (rather than merely display the listing) SHOULD
re-fetch the live `/.well-known/afauth` document from `discovery_url`
before doing so; the cached copy may lag the live document by up to
the directory's revalidation interval.

**`status`** is one of:
- `active` — discovery doc fetched successfully on the last probe and
  validates against [`../schemas/well-known.json`](../schemas/well-known.json).
- `stale` — recent probes failed or the discovery doc no longer
  validates; retained for downstream mirror convergence.
- `deleted` — the controller of `service_did` requested removal.
  Retained (soft-delete) so mirrors converge.

**`_meta`** is a free-form object reserved for future extensions.
Federation conventions for `_meta` (namespacing, third-party
annotations, scan results) are deliberately not specified in this
version and will be defined in a follow-up revision if and when
there are aggregators that need them.

## 3. Identity model

A listing is **bound to the `service_did` already declared in the
discovery document.** AFAuth's existing DID model is the only
namespace the directory needs; reverse-DNS namespacing is not
adopted because it would parallel the DID layer without adding
security. Authentication of a listing is host-based (§4) and
therefore independent of DID method: `did:web` and `did:key`
`service_did` values are accepted on equal terms.

Consequences:

- A `did:web:host` listing's authority is anchored in DNS + TLS for
  `host` — the same anchor used elsewhere in the protocol. Claiming
  `did:web:acme.example.com` requires control of `acme.example.com`,
  full stop.
- A `did:key:` listing's authority is anchored, like every listing,
  in control of the discovery host (§4). The `did:key` identifier
  itself carries no domain anchor ([`core.md`](core.md) §4.3): a
  consumer browsing the listing cannot infer the operating
  organisation from the DID alone. Browse interfaces presenting
  listings MUST render `did:key:` entries with a visible "no domain
  anchor" indicator and prominently display the host derived from
  `discovery_url`.
- Conflicts cannot arise: two services cannot legitimately claim the
  same `service_did`, because the DID resolves to at most one key
  set.

## 4. Listing protocol

The directory authenticates a controller through **proof of control
of the discovery host**. The scheme is a two-step well-known
challenge: the directory issues a one-time token, the controller
publishes it at a known path on the host serving `discovery_url`,
and the directory verifies by independent HTTPS fetch. After
verification the directory issues a short-lived **session token**
that authenticates subsequent operations on the same listing.

This is the same trust anchor — DNS + TLS for the discovery host —
that ACME (HTTP-01), GitHub Pages, the MCP registry's HTTP
authentication mode, and the AFAuth discovery mechanism itself rely
on. No new identity primitive is introduced; the controller's
authority derives entirely from operating the host whose
`/.well-known/afauth` document declares the service.

The proof path `/.well-known/afauth-registry-proof` (§4.1 step 2)
is an unregistered well-known URI scoped to directory participants.
It is not proposed for IANA registration in this version; the path
is part of the directory convention, not the AFAuth core
specification.

### 4.1 Initial registration

To register a new listing, the controller performs three steps:

**1. Request a challenge.**

```http
POST /v1/listings/challenge HTTP/1.1
Host: registry.afauth.org
Content-Type: application/json

{ "discovery_url": "https://api.example.com/.well-known/afauth" }
```

The directory returns a challenge token bound to the discovery host
derived from `discovery_url`:

```http
200 OK
Content-Type: application/json

{
  "challenge_token": "ch_01HXYZ...",
  "proof_url":       "https://api.example.com/.well-known/afauth-registry-proof",
  "expires_at":      "2026-05-25T15:30:00Z"
}
```

Challenge tokens MUST contain at least 128 bits of entropy from a
cryptographically secure source. They MUST expire within 30 minutes
of issuance and MUST be single-use. The challenge request is
unauthenticated; rate limiting is the only abuse control at this
step (anyone may *request* a challenge for any host, but only the
host's controller can *satisfy* one).

**2. Publish the proof.**

The controller publishes the challenge token at `proof_url`. The
response MUST be HTTP 200, `Content-Type: text/plain`, with the
response body containing the bare token (no surrounding JSON, no
trailing newline, no whitespace).

**3. Submit the listing.**

```http
POST /v1/listings HTTP/1.1
Host: registry.afauth.org
Content-Type: application/json

{
  "discovery_url":   "https://api.example.com/.well-known/afauth",
  "challenge_token": "ch_01HXYZ...",
  "title":           "Example Photo Storage",
  "description":     "AFAuth-supported photo storage for agents.",
  "tags":            ["productivity", "storage"]
}
```

The directory then:

1. Verifies the challenge token is valid, unexpired, unused, and
   bound to the host derived from the submitted `discovery_url`.
2. Fetches `proof_url` over HTTPS (validating the TLS certificate
   against the public CA bundle) and confirms the response body
   equals the challenge token byte-for-byte.
3. Fetches `discovery_url` over HTTPS and validates the response
   against [`../schemas/well-known.json`](../schemas/well-known.json).
4. Marks the challenge token as consumed.
5. On success, creates the listing and returns a **session token**:

```http
201 Created
Content-Type: application/json

{
  "service_did":   "did:web:api.example.com",
  "session_token": "sess_01HABC...",
  "expires_at":    "2026-06-01T15:30:00Z"
}
```

Session tokens are bearer credentials scoped to a single
`service_did`. They MUST contain at least 128 bits of entropy and
MUST expire within 7 days of issuance. The controller MAY remove
the proof file from `proof_url` once the session token has been
issued; the directory does not re-validate the proof except at
initial registration and on re-challenge (§4.3).

### 4.2 Update and removal

`PATCH /v1/listings/{service_did}` and
`DELETE /v1/listings/{service_did}` are authenticated with the
session token in an HTTP `Authorization: Bearer` header:

```http
PATCH /v1/listings/did:web:api.example.com HTTP/1.1
Host: registry.afauth.org
Authorization: Bearer sess_01HABC...
Content-Type: application/json

{ "tags": ["productivity", "storage", "photos"] }
```

The directory MUST reject a session token whose bound `service_did`
does not match the path parameter, and MUST reject expired or
revoked tokens with HTTP 401.

The `PATCH` body MAY include any subset of the writeable listing
fields (`title`, `description`, `tags`). The `service_did` and
`discovery_url` fields are not writeable through `PATCH`; a service
whose discovery host changes must `DELETE` the existing listing and
re-register.

`DELETE` is a soft-delete: the directory transitions the listing's
`status` to `deleted` and retains the record so mirrors converge
(see §7 and §10). The directory MUST NOT hard-erase listings
through this endpoint; hard-erase is reserved for unlawful content
and is governed by the operator's take-down policy (§10).

### 4.3 Re-challenge on session expiry or recovery

When a session token expires, or when the controller has lost it, a
new session is obtained by repeating §4.1 against the same
`discovery_url`. On a successful re-challenge for an existing
listing:

- The directory issues a fresh session token bound to the same
  `service_did`.
- The directory MUST revoke any prior session tokens for that
  listing. This is the recovery path for a compromised session
  token: regaining host control regains the listing.

The discovery-document revalidation flow (§7) is independent of
session tokens: the directory periodically re-fetches each
listing's `discovery_url` regardless of whether any session is
active. A controller whose session token has expired need not
refresh it unless they intend to mutate the listing.

### 4.4 Why no signed requests

The directory deliberately does not require the controller to sign
requests with the service's DID key. In v0.1, an AFAuth service
publishes `/.well-known/afauth` but is **not** required to publish
a DID document at `/.well-known/did.json` — [`core.md`](core.md)
§3.1.2 governs DID resolution for *account* DIDs that services
accept, not for the service's own `service_did`, which is
declarative in v0.1. Observation: representative v0.1 deployments
(e.g., `https://artidrop.ai/.well-known/afauth` declares
`service_did: "did:web:artidrop.ai"`, while
`https://artidrop.ai/.well-known/did.json` returns 404) confirm
that the controller key the DID nominally resolves to is, in
practice, not published.

A signed-submission scheme would therefore have introduced a new
prerequisite on services that wish to list — standing up DID-document
publication, generating and storing a controller key, and
integrating outbound HTTP Message Signature generation — none of
which the protocol otherwise demands. The challenge scheme requires
only what the controller already operates: the discovery host.

## 5. Read API

All read endpoints are unauthenticated, served over HTTPS with HSTS,
and rate-limited only against abuse.

| Endpoint | Purpose |
|---|---|
| `GET /v1/listings` | Cursor-paginated list. Query params: `cursor`, `limit` (≤100), `search`, `tag`, `updated_since` (RFC 3339), `status`, `include_deleted`. |
| `GET /v1/listings/{service_did}` | Single listing. |

The `cursor` value is opaque to clients: it MUST be treated as a
server-issued continuation token and submitted unmodified in the
next request. Its internal encoding is unspecified and MAY change
between directory versions without notice.

Two endpoints is deliberately the entire v0 surface. Bulk-dump,
snapshot, history, and OpenAPI endpoints are non-breaking additions
that may be introduced in a follow-up revision once a consumer
pattern exists that the paginated list cannot serve; at the
expected v0 scale (tens of listings), the paginated list is
sufficient for mirrors and aggregators that poll with
`updated_since`.

## 6. Conformance probes

Active conformance probing against listed services — running test
vectors, publishing per-listing pass/fail results, the directory
acting as a signing AFAuth agent (`did:web:afauth.org`), and the
attendant rate budget — is **out of scope for this version** and is
tracked separately. The directory's only liveness signal in this
version is the discovery-document revalidation defined in §7.

When conformance probing is added in a future revision, the listing
record (§2) gains a `conformance` block; existing fields are
unchanged.

## 7. Revalidation and soft-delete

The directory periodically (RECOMMENDED daily) re-fetches each
listing's `discovery_url`. A listing transitions to `stale` only
after **at least three consecutive revalidation failures** — a
single network blip or transient 5xx MUST NOT flip a healthy
listing. After a controller-configurable grace period (RECOMMENDED
30 days from the first failure in the run that drove the listing
to `stale`), the directory MAY transition `stale` listings to
`deleted`.

`deleted` records persist in the list response with
`status: "deleted"` (returned only when `include_deleted=true`) so
mirrors converge. Hard-erase is reserved for unlawful content.

The directory retains only the **current** `discovery_doc` snapshot
per listing in this version. Per-listing history, history-purge,
registry-wide daily snapshots, and snapshot-retention policy are
out of scope and may be added by a follow-up revision.

## 8. Federation

The directory **is not the protocol's single source of truth.**
Anyone may host a directory implementing the same surface; agents
and aggregators may consume any directory or several. The schema
lives in [`../schemas/listing.json`](../schemas/listing.json) and
is versioned alongside the spec.

Recommended federation patterns:

- **Mirrors**: clone the canonical dataset by polling
  `GET /v1/listings` with `updated_since`, and serve identical
  content under their own domain.
- **Aggregators**: combine the canonical directory with their own
  curation, scan results, or editorial annotations. Conventions
  for representing third-party annotations on a listing are not
  specified in this version (see §2, `_meta`).
- **Private directories**: enterprises with internal-only AFAuth
  services run their own directory, never publishing to
  `afauth.org`. The same schema and challenge-based registration
  protocol apply.

## 9. Operator and governance

AFAuthHQ operates `registry.afauth.org` in this version. A public
operator commitment at `https://registry.afauth.org/operator`
documents:

- Who has operational authority.
- The actions the operator MAY take unilaterally (routine
  moderation per §10, infrastructure changes, schema-conformant
  data migrations).
- The actions the operator MUST NOT take unilaterally (delisting a
  service outside the published moderation policy, breaking-change
  schema amendments, censoring listings on ideological grounds).

The schema and challenge-based registration protocol are public;
anyone may mirror, fork, or run a private directory (see §8).
Governance evolution — a steering committee, donation to a neutral
standards home, multi-operator co-stewardship — will be addressed
in a follow-up revision once adoption warrants it. This document
does not commit the project to a specific governance trajectory in
advance of that evidence.

## 10. Take-down policy

The canonical directory's take-down policy (illegal content,
malware, spam, fraudulent claims) is published at
`https://registry.afauth.org/policy`. Operational decisions made by
the canonical directory do not bind mirrors or aggregators, which
set their own policies.

A service controller may withdraw a listing at any time by issuing
an authenticated `DELETE` request (§4.2). Withdrawn listings
appear in
`GET /v1/listings?include_deleted=true&updated_since=…`
with `status: "deleted"` so mirrors converge.

## Security and privacy considerations

A summary; see [AFAP-0003](../proposals/0003-service-directory.md)
for the full analysis.

- **Squatting and impersonation.** Authority for a listing derives
  from proof of control of the discovery host (§4.1) and ongoing
  matching between `discovery_doc.service_did` and the listing's
  `service_did` on every probe. A third party cannot list a service
  whose discovery host they do not control.
- **Stale or hostile listings.** A compromised discovery host can
  submit hostile listings; the legitimate controller re-claims the
  listing by re-challenging (§4.3), which revokes all prior
  session tokens.
- **First-registration hijack.** Trust rests on two TLS+DNS fetches
  at registration time. The canonical directory MAY adopt
  multi-perspective issuance corroboration (MPIC) for first-
  registration proof verification; tracked as future hardening.
- **Session-token leakage.** Session tokens are bearer credentials;
  leakage gives an attacker control of one listing for up to 7
  days. Per-listing scope contains the blast radius;
  instantaneous recovery via re-challenge (§4.3) revokes the
  stolen token.
- **No agent-side data.** The directory holds records about
  *services*, not agents or accounts.
- **Privacy of `discovery_doc` snapshots.** Only the current
  snapshot is retained per listing in this version. If per-
  listing history is added in a future revision, services should
  reassess what they publish into the discovery document.

## Background and rationale

See [AFAP-0003](../proposals/0003-service-directory.md) for the
proposal's motivation, alternatives considered (including
HMS-signed submission, OAuth-on-code-host, static repo, fully
peer-to-peer announcement, and a `directory` field in the
discovery document), and references to MCP-registry prior art.
